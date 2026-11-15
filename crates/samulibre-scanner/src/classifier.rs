use chrono::Utc;
use samulibre_types::{
    AuthenticodeSummary, ConfidenceLevel, DetectionEvidence, EvidenceCategory, FileScanStatus,
    ValidationStatus,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Umbrales configurables y calibrados del clasificador multicapa
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierConfig {
    /// Umbral mínimo de puntuación calibrada para CRÍTICO (con >=2 categorías independientes o evidencia definitiva)
    pub critico_threshold: i32,
    /// Umbral mínimo de puntuación calibrada para ALTO (con >=2 categorías independientes)
    pub alto_threshold: i32,
    /// Umbral mínimo de puntuación calibrada para MEDIO / SOSPECHOSO (nunca cuarentena automática)
    pub medio_threshold: i32,
    /// Peso atenuante cuando existe firma Authenticode válida de Microsoft/OS
    pub valid_microsoft_sig_mitigation: i32,
    /// Peso atenuante cuando existe firma Authenticode válida de tercero
    pub valid_third_party_sig_mitigation: i32,
    /// Puntuación máxima adicional por rasgos secundarios dentro de una misma categoría (evita doble conteo)
    pub intra_category_secondary_cap: i32,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            critico_threshold: 85,
            alto_threshold: 60,
            medio_threshold: 35,
            valid_microsoft_sig_mitigation: -35,
            valid_third_party_sig_mitigation: -22,
            intra_category_secondary_cap: 15,
        }
    }
}

/// Decisión estructurada emitida por el motor de clasificación
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationDecision {
    pub status: FileScanStatus,
    pub confidence_level: ConfidenceLevel,
    pub calibrated_score: i32,
    pub primary_detection_name: Option<String>,
    pub primary_engine: String,
    pub classification_label: String,
    pub auto_quarantine_allowed: bool,
    pub independent_risk_categories: usize,
    pub evidences: Vec<DetectionEvidence>,
    pub authenticode: Option<AuthenticodeSummary>,
}

/// Clasificador multi-evidencia con correlación entre categorías independientes
#[derive(Debug, Clone)]
pub struct MultiEvidenceClassifier {
    config: ClassifierConfig,
}

impl Default for MultiEvidenceClassifier {
    fn default() -> Self {
        Self::new(ClassifierConfig::default())
    }
}

impl MultiEvidenceClassifier {
    pub fn new(config: ClassifierConfig) -> Self {
        Self { config }
    }

    /// Evalúa todas las evidencias recopiladas sin doble conteo de rasgos derivados
    pub fn classify(
        &self,
        evidences: Vec<DetectionEvidence>,
        authenticode: Option<AuthenticodeSummary>,
    ) -> ClassificationDecision {
        if evidences.is_empty() {
            return ClassificationDecision {
                status: FileScanStatus::Clean,
                confidence_level: ConfidenceLevel::Bajo,
                calibrated_score: 0,
                primary_detection_name: None,
                primary_engine: "Multi-Engine Clean".to_string(),
                classification_label: "Limpio / Sin evidencias de riesgo".to_string(),
                auto_quarantine_allowed: false,
                independent_risk_categories: 0,
                evidences,
                authenticode,
            };
        }

        let has_definitive = evidences.iter().any(|e| e.is_definitive);

        // Agrupar evidencias positivas por categoría para evitar contar rasgos derivados como pruebas independientes
        let mut positive_by_cat: HashMap<EvidenceCategory, Vec<&DetectionEvidence>> = HashMap::new();
        let mut mitigation_sum: i32 = 0;

        for ev in &evidences {
            if ev.weight > 0 {
                positive_by_cat.entry(ev.category).or_default().push(ev);
            } else if ev.weight < 0 {
                mitigation_sum += ev.weight;
            }
        }

        // Aplicar mitigación por Authenticode si corresponde, pero NUNCA confiar ciegamente si hay
        // evidencia definitiva (hash malicioso confirmado / EICAR) o múltiples categorías fuertes (>= 85 bruto)
        if let Some(ref auth) = authenticode {
            if auth.is_signed && auth.is_valid_chain {
                let is_ms = auth
                    .publisher
                    .as_deref()
                    .map(|p| p.to_ascii_lowercase().contains("microsoft"))
                    .unwrap_or(false);
                mitigation_sum += if is_ms {
                    self.config.valid_microsoft_sig_mitigation
                } else {
                    self.config.valid_third_party_sig_mitigation
                };
            }
        }

        let mut raw_risk_score: i32 = 0;
        let mut independent_risk_categories: usize = 0;
        let mut distinct_high_rules: usize = 0;
        let mut has_multi_token_exploit = false;

        for (cat, mut cat_evidences) in positive_by_cat {
            cat_evidences.sort_by(|a, b| b.weight.cmp(&a.weight));
            for ev in &cat_evidences {
                if ev.weight >= 35 {
                    distinct_high_rules += 1;
                }
                if ev.weight >= 65
                    && matches!(
                        cat,
                        EvidenceCategory::YaraRule | EvidenceCategory::DocumentExploit
                    )
                {
                    has_multi_token_exploit = true;
                }
            }
            if let Some(strongest) = cat_evidences.first() {
                // Solo cuentan como categoría independiente las señales con peso significativo (>= 15),
                // o contexto de origen (>= 10) cuando ya existe otra señal fuerte
                if strongest.weight >= 15 || (cat == EvidenceCategory::OriginContext && strongest.weight >= 10) {
                    independent_risk_categories += 1;
                }
                let secondary_sum: i32 = cat_evidences
                    .iter()
                    .skip(1)
                    .map(|e| e.weight / 3)
                    .sum::<i32>()
                    .min(self.config.intra_category_secondary_cap);
                raw_risk_score += strongest.weight + secondary_sum;
            }
        }

        // Si es definitivo (EICAR o hash de malware confirmado), la firma digital no puede rebajarlo (posible cert robado/abuso)
        let calibrated_score = if has_definitive {
            raw_risk_score.max(100)
        } else if raw_risk_score >= 95 && independent_risk_categories >= 3 {
            // Múltiples indicadores independientes graves (posible certificado comprometido): atenuación reducida a la mitad
            (raw_risk_score + (mitigation_sum / 2)).max(0)
        } else {
            (raw_risk_score + mitigation_sum).max(0)
        };

        // Determinar nivel de confianza calibrado
        let confidence_level = if has_definitive
            || (calibrated_score >= self.config.critico_threshold
                && independent_risk_categories >= 2)
        {
            ConfidenceLevel::Critico
        } else if calibrated_score >= self.config.alto_threshold
            && (independent_risk_categories >= 2
                || distinct_high_rules >= 2
                || has_multi_token_exploit)
        {
            ConfidenceLevel::Alto
        } else if calibrated_score >= self.config.medio_threshold {
            ConfidenceLevel::Medio
        } else {
            ConfidenceLevel::Bajo
        };

        // Regla estricta: BAJO / NO CONCLUYENTE no se clasifica como amenaza; MEDIO nunca cuarentena automática
        let (status, auto_quarantine_allowed, classification_label) = match confidence_level {
            ConfidenceLevel::Critico => (
                FileScanStatus::Infected,
                true,
                "CRÍTICO / MALICIOSO CONFIRMADO".to_string(),
            ),
            ConfidenceLevel::Alto => (
                FileScanStatus::Infected,
                true,
                "ALTO / PROBABLEMENTE MALICIOSO".to_string(),
            ),
            ConfidenceLevel::Medio => (
                FileScanStatus::Suspicious,
                false,
                "MEDIO / SOSPECHOSO (Requiere verificación)".to_string(),
            ),
            ConfidenceLevel::Bajo => (
                FileScanStatus::Clean,
                false,
                "BAJO / NO CONCLUYENTE".to_string(),
            ),
        };

        let mut sorted_evidences = evidences.clone();
        sorted_evidences.sort_by(|a, b| {
            b.is_definitive
                .cmp(&a.is_definitive)
                .then_with(|| b.weight.cmp(&a.weight))
        });

        let primary_detection_name = if status == FileScanStatus::Clean {
            None
        } else {
            sorted_evidences.first().map(|e| e.rule_id.clone())
        };

        let primary_engine = if let Some(top) = sorted_evidences.first() {
            match top.category {
                EvidenceCategory::SignatureHash => "SignatureHash + MultiEvidence".to_string(),
                EvidenceCategory::YaraRule => "YARA + MultiEvidence".to_string(),
                EvidenceCategory::StructuralPe => "PE Analyzer + MultiEvidence".to_string(),
                EvidenceCategory::EntropyObfuscation => {
                    "Entropy/Polymorphic + MultiEvidence".to_string()
                }
                EvidenceCategory::DocumentExploit => "DocumentExploit + MultiEvidence".to_string(),
                EvidenceCategory::BehavioralPattern => "BehaviorMonitor + MultiEvidence".to_string(),
                EvidenceCategory::Authenticity => "Authenticode + MultiEvidence".to_string(),
                EvidenceCategory::OriginContext => "OriginContext + MultiEvidence".to_string(),
            }
        } else {
            "MultiEvidenceClassifier".to_string()
        };

        ClassificationDecision {
            status,
            confidence_level,
            calibrated_score,
            primary_detection_name,
            primary_engine,
            classification_label,
            auto_quarantine_allowed,
            independent_risk_categories,
            evidences: sorted_evidences,
            authenticode,
        }
    }
}

/// Entrada inmutable encadenada criptográficamente para trazabilidad de decisiones
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLedgerEntry {
    pub timestamp_utc: String,
    pub event_type: String, // "DETECTION", "CONFIRM_THREAT", "MARK_FALSE_POSITIVE", "QUARANTINE", "RESTORE", "EXCLUSION"
    pub sha256: String,
    pub file_path: String,
    pub rule_or_detection: String,
    pub confidence_level: String,
    pub calibrated_score: i32,
    pub actor: String, // "Engine" | "Analyst"
    pub details: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Registro de auditoría con cadena de hashes SHA-256 (tamper-evident)
pub struct DetectionAuditLedger;

impl DetectionAuditLedger {
    pub fn append_entry(
        ledger_path: &Path,
        event_type: &str,
        sha256: &str,
        file_path: &str,
        rule_or_detection: &str,
        confidence_level: &str,
        calibrated_score: i32,
        actor: &str,
        details: &str,
    ) -> anyhow::Result<AuditLedgerEntry> {
        if let Some(parent) = ledger_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let prev_hash = Self::read_last_hash(ledger_path).unwrap_or_else(|| "GENESIS".to_string());
        let timestamp_utc = Utc::now().to_rfc3339();

        let payload = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            timestamp_utc,
            event_type,
            sha256,
            file_path,
            rule_or_detection,
            confidence_level,
            calibrated_score,
            actor,
            details,
            prev_hash
        );
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let entry_hash = hex::encode(hasher.finalize());

        let entry = AuditLedgerEntry {
            timestamp_utc,
            event_type: event_type.to_string(),
            sha256: sha256.to_string(),
            file_path: file_path.to_string(),
            rule_or_detection: rule_or_detection.to_string(),
            confidence_level: confidence_level.to_string(),
            calibrated_score,
            actor: actor.to_string(),
            details: details.to_string(),
            prev_hash,
            entry_hash,
        };

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(ledger_path)?;
        writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        Ok(entry)
    }

    fn read_last_hash(ledger_path: &Path) -> Option<String> {
        let content = fs::read_to_string(ledger_path).ok()?;
        let last_line = content.lines().rev().find(|l| !l.trim().is_empty())?;
        let parsed: AuditLedgerEntry = serde_json::from_str(last_line).ok()?;
        Some(parsed.entry_hash)
    }

    /// Verifica que toda la cadena de auditoría no haya sido alterada manualmente
    pub fn verify_integrity(ledger_path: &Path) -> anyhow::Result<(bool, usize)> {
        if !ledger_path.exists() {
            return Ok((true, 0));
        }
        let content = fs::read_to_string(ledger_path)?;
        let mut expected_prev = "GENESIS".to_string();
        let mut count = 0usize;

        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let entry: AuditLedgerEntry = serde_json::from_str(line)?;
            if entry.prev_hash != expected_prev {
                return Ok((false, count));
            }
            let payload = format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                entry.timestamp_utc,
                entry.event_type,
                entry.sha256,
                entry.file_path,
                entry.rule_or_detection,
                entry.confidence_level,
                entry.calibrated_score,
                entry.actor,
                entry.details,
                entry.prev_hash
            );
            let mut hasher = Sha256::new();
            hasher.update(payload.as_bytes());
            let computed = hex::encode(hasher.finalize());
            if computed != entry.entry_hash {
                return Ok((false, count));
            }
            expected_prev = entry.entry_hash;
            count += 1;
        }
        Ok((true, count))
    }
}

/// Registro controlado de falsos positivos confirmados (no muta reglas globales sin revisión)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveFeedback {
    pub id: String,
    pub timestamp_utc: String,
    pub sha256: String,
    pub file_path: String,
    pub rule_id: String,
    pub reason: String,
    pub rule_review_status: String, // "PendienteRevisiónRegla", "ReglaRefinada", "Descartado"
}

pub struct FalsePositiveRegistry;

impl FalsePositiveRegistry {
    pub fn record_fp(
        registry_path: &Path,
        sha256: &str,
        file_path: &str,
        rule_id: &str,
        reason: &str,
    ) -> anyhow::Result<FalsePositiveFeedback> {
        if let Some(parent) = registry_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut items: Vec<FalsePositiveFeedback> = if registry_path.exists() {
            let s = fs::read_to_string(registry_path).unwrap_or_default();
            serde_json::from_str(&s).unwrap_or_default()
        } else {
            Vec::new()
        };

        let entry = FalsePositiveFeedback {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp_utc: Utc::now().to_rfc3339(),
            sha256: sha256.to_string(),
            file_path: file_path.to_string(),
            rule_id: rule_id.to_string(),
            reason: reason.to_string(),
            rule_review_status: ValidationStatus::EnAnalisis.to_string_label(),
        };

        // Evitar duplicados exactos por (sha256, rule_id)
        let existing_keys: HashSet<(String, String)> = items
            .iter()
            .map(|i| (i.sha256.clone(), i.rule_id.clone()))
            .collect();
        if !existing_keys.contains(&(entry.sha256.clone(), entry.rule_id.clone())) {
            items.push(entry.clone());
            fs::write(registry_path, serde_json::to_string_pretty(&items)?)?;
        }
        Ok(entry)
    }
}

trait ValidationLabelExt {
    fn to_string_label(&self) -> String;
}

impl ValidationLabelExt for ValidationStatus {
    fn to_string_label(&self) -> String {
        match self {
            ValidationStatus::Pendiente => "Pendiente".to_string(),
            ValidationStatus::Confirmada => "Confirmada".to_string(),
            ValidationStatus::FalsoPositivo => "FalsoPositivo".to_string(),
            ValidationStatus::EnAnalisis => "PendienteRevisiónRegla".to_string(),
        }
    }
}
