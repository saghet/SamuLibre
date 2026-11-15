use serde::{Deserialize, Serialize};

/// Niveles de decisión calibrados del Motor Antifalsos Positivos de SamuLibre
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThreatDecisionLevel {
    Confirmado,
    AltoRiesgo,
    Sospechoso,
    Informativo,
}

/// Contexto de archivo/proceso evaluado para prevenir falsos positivos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpEvaluationInput {
    pub file_path: String,
    pub has_definitive_hash_match: bool,
    pub yara_match_count: usize,
    pub heuristic_match_count: usize,
    pub independent_sources_count: usize,
    pub max_source_reputation: u8,
    pub has_valid_authenticode: bool,
    pub publisher: Option<String>,
    pub is_admin_or_dev_tool: bool,
    pub has_active_behavior_alert: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpEvaluationDecision {
    pub level: ThreatDecisionLevel,
    pub allow_auto_quarantine: bool,
    pub final_confidence: u8,
    pub rationale: String,
}

pub struct AntiFalsePositiveEngine;

impl AntiFalsePositiveEngine {
    /// Evalúa múltiples señales independientes evitando falsos positivos en software legítimo/firmado/dev
    pub fn evaluate(input: &FpEvaluationInput) -> FpEvaluationDecision {
        let mut score: i32 = 0;
        let mut reasons: Vec<String> = Vec::new();

        if input.has_definitive_hash_match {
            score += 95;
            reasons.push("Coincidencia exacta de hash SHA-256 verificado".to_string());
        }
        if input.yara_match_count > 0 {
            score += (input.yara_match_count as i32 * 35).min(70);
            reasons.push(format!("{} regla(s) YARA-X coincidente(s)", input.yara_match_count));
        }
        if input.heuristic_match_count > 0 {
            score += (input.heuristic_match_count as i32 * 18).min(36);
            reasons.push(format!("{} indicador(es) heurístico(s)", input.heuristic_match_count));
        }
        if input.has_active_behavior_alert {
            score += 35;
            reasons.push("Correlación de comportamiento activo".to_string());
        }
        if input.independent_sources_count >= 2 {
            score += 15;
            reasons.push(format!("Corroborado por {} fuentes independientes", input.independent_sources_count));
        }
        if input.max_source_reputation >= 90 {
            score += 5;
        }

        // Factores mitigantes (NO absolutos: la firma digital no exonera un hash malicioso confirmado)
        if input.has_valid_authenticode && !input.has_definitive_hash_match {
            score -= 35;
            reasons.push(format!(
                "Firma Authenticode válida ({})",
                input.publisher.as_deref().unwrap_or("Fabricante verificado")
            ));
        }
        if input.is_admin_or_dev_tool && !input.has_definitive_hash_match && !input.has_active_behavior_alert {
            score -= 25;
            reasons.push("Contexto de herramienta administrativa/diagnóstico/desarrollo".to_string());
        }

        let final_confidence = score.clamp(0, 100) as u8;
        let (level, allow_auto_quarantine) = if input.has_definitive_hash_match
            || (final_confidence >= 85 && input.independent_sources_count >= 2)
        {
            (ThreatDecisionLevel::Confirmado, true)
        } else if final_confidence >= 70 && (!input.has_valid_authenticode || input.has_active_behavior_alert) {
            (ThreatDecisionLevel::AltoRiesgo, !input.is_admin_or_dev_tool)
        } else if final_confidence >= 40 {
            (ThreatDecisionLevel::Sospechoso, false)
        } else {
            (ThreatDecisionLevel::Informativo, false)
        };

        FpEvaluationDecision {
            level,
            allow_auto_quarantine,
            final_confidence,
            rationale: reasons.join("; "),
        }
    }

    /// Detecta si una ruta corresponde a contextos legítimos que no deben cuarentenarse por heurística débil
    pub fn is_protected_context_path(path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        lower.starts_with("c:\\windows\\system32\\")
            || lower.starts_with("c:\\windows\\syswow64\\")
            || lower.contains("\\program files\\")
            || lower.contains("\\totalvfp9\\")
            || lower.contains("\\target\\debug\\")
            || lower.contains("\\target\\release\\")
    }
}
