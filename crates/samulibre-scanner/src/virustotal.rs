use crate::classifier::DetectionAuditLedger;
use chrono::{DateTime, Utc};
use samulibre_types::{ConfidenceLevel, ThreatRecord};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

const VT_API_BASE: &str = "https://www.virustotal.com/api/v3";
const VT_FREE_PER_MINUTE: usize = 4;
const VT_FREE_PER_DAY: usize = 500;
const VT_MAX_DIRECT_UPLOAD_BYTES: u64 = 32 * 1024 * 1024;
const VT_CACHE_TTL_SECS: i64 = 24 * 3600;

/// Categoría normalizada de veredicto por motor en VirusTotal API v3
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VtEngineCategory {
    Malicious,
    Suspicious,
    Undetected,
    Harmless,
    TimeoutOrError,
}

impl VtEngineCategory {
    pub fn from_vt_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "malicious" => Self::Malicious,
            "suspicious" => Self::Suspicious,
            "undetected" => Self::Undetected,
            "harmless" => Self::Harmless,
            _ => Self::TimeoutOrError, // timeout, confirmed-timeout, failure, type-unsupported
        }
    }

    pub fn label_es(&self) -> &'static str {
        match self {
            Self::Malicious => "malicious",
            Self::Suspicious => "suspicious",
            Self::Undetected => "undetected",
            Self::Harmless => "harmless",
            Self::TimeoutOrError => "timeout/error",
        }
    }
}

/// Resultado individual de un motor antivirus en VirusTotal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtEngineResult {
    pub engine_name: String,
    pub category: VtEngineCategory,
    pub raw_category: String,
    pub result: Option<String>,
    pub method: Option<String>,
    pub engine_version: Option<String>,
    pub agrees_with_local: bool,
    pub disagrees_with_local: bool,
}

/// Resumen estadístico de motores VirusTotal
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VtAnalysisStats {
    pub malicious: u32,
    pub suspicious: u32,
    pub undetected: u32,
    pub harmless: u32,
    pub timeout_or_error: u32,
    pub total_engines: u32,
}

/// Informe completo de VirusTotal API v3 cacheable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtFileReport {
    pub sha256: String,
    pub stats: VtAnalysisStats,
    pub engines: Vec<VtEngineResult>,
    pub last_analysis_date_epoch: Option<i64>,
    pub last_analysis_date_utc: Option<String>,
    pub report_age_human: String,
    pub reputation: Option<i64>,
    pub meaning_name: Option<String>,
    pub permalink: String,
    pub cached_at_utc: String,
}

/// Política de subida y privacidad para VIRUSTOTAL THREAT VERIFICATION
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtVerificationPolicy {
    /// Modalidad de consulta por hash sin subida del archivo (comercial/privacidad)
    pub hash_only_mode: bool,
    /// Subir automáticamente únicamente cuando existe sospecha local y NO es Office/PDF
    pub auto_upload_suspicious_non_docs: bool,
}

impl Default for VtVerificationPolicy {
    fn default() -> Self {
        Self {
            hash_only_mode: true,
            auto_upload_suspicious_non_docs: false,
        }
    }
}

/// Resultado correlacionado entre el motor local SamuLibre y VirusTotal API v3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtCorrelationReport {
    pub sha256: String,
    pub file_path: String,
    pub local_detections: Vec<String>,
    pub local_confidence: ConfidenceLevel,
    pub local_score: i32,
    pub found_in_vt: bool,
    pub from_cache: bool,
    pub vt_stats: Option<VtAnalysisStats>,
    pub vt_engines: Vec<VtEngineResult>,
    pub agreeing_engines: Vec<String>,
    pub disagreeing_engines: Vec<String>,
    pub analysis_date_utc: Option<String>,
    pub report_age_human: Option<String>,
    pub samulibre_recommendation: String,
    pub privacy_status: String,
    pub is_sensitive_document: bool,
    pub requires_explicit_consent: bool,
    pub can_offer_upload: bool,
    pub privacy_warning: Option<String>,
    pub uploaded_analysis_id: Option<String>,
    pub error_detail: Option<String>,
    pub quota_minute_used: usize,
    pub quota_minute_limit: usize,
    pub quota_day_used: usize,
    pub quota_day_limit: usize,
}

/// Errores tipados del cliente VirusTotal API v3
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VtErrorKind {
    MissingApiKey,
    NotFound,
    RateLimit429,
    AuthError,
    Timeout,
    Connectivity,
    PrivacyConsentRequired,
    HashOnlyModeBlocked,
    FileTooLarge,
    ParseError,
}

#[derive(Debug, Clone)]
pub struct VtError {
    pub kind: VtErrorKind,
    pub message: String,
}

impl std::fmt::Display for VtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for VtError {}

/// Control persistente de cuotas gratuitas (4 req/min, 500 req/día)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VtQuotaState {
    pub minute_timestamps: VecDeque<i64>,
    pub day_date_utc: String,
    pub day_count: usize,
}

impl VtQuotaState {
    pub fn load(path: &Path) -> Self {
        if let Ok(s) = fs::read_to_string(path) {
            if let Ok(mut q) = serde_json::from_str::<Self>(&s) {
                q.prune();
                return q;
            }
        }
        Self {
            minute_timestamps: VecDeque::new(),
            day_date_utc: Utc::now().format("%Y-%m-%d").to_string(),
            day_count: 0,
        }
    }

    pub fn prune(&mut self) {
        let now = Utc::now().timestamp();
        while let Some(&front) = self.minute_timestamps.front() {
            if now - front >= 60 {
                self.minute_timestamps.pop_front();
            } else {
                break;
            }
        }
        let today = Utc::now().format("%Y-%m-%d").to_string();
        if self.day_date_utc != today {
            self.day_date_utc = today;
            self.day_count = 0;
        }
    }

    pub fn check_and_consume(&mut self, path: &Path) -> Result<(), VtError> {
        self.prune();
        if self.minute_timestamps.len() >= VT_FREE_PER_MINUTE {
            return Err(VtError {
                kind: VtErrorKind::RateLimit429,
                message: format!(
                    "Límite local de cuota gratuita VirusTotal alcanzado ({}/{} peticiones por minuto). Espere unos segundos.",
                    self.minute_timestamps.len(),
                    VT_FREE_PER_MINUTE
                ),
            });
        }
        if self.day_count >= VT_FREE_PER_DAY {
            return Err(VtError {
                kind: VtErrorKind::RateLimit429,
                message: format!(
                    "Límite diario de cuota gratuita VirusTotal alcanzado ({}/{} peticiones hoy).",
                    self.day_count, VT_FREE_PER_DAY
                ),
            });
        }
        let now = Utc::now().timestamp();
        self.minute_timestamps.push_back(now);
        self.day_count += 1;
        self.save(path);
        Ok(())
    }

    pub fn save(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
        }
    }
}

/// Caché persistente de informes VirusTotal por SHA-256
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VtCacheStore {
    pub entries: HashMap<String, VtFileReport>,
}

impl VtCacheStore {
    pub fn load(path: &Path) -> Self {
        if let Ok(s) = fs::read_to_string(path) {
            if let Ok(c) = serde_json::from_str::<Self>(&s) {
                return c;
            }
        }
        Self::default()
    }

    pub fn get_fresh(&self, sha256: &str) -> Option<VtFileReport> {
        let key = sha256.to_ascii_lowercase();
        let entry = self.entries.get(&key)?;
        let cached_dt = DateTime::parse_from_rfc3339(&entry.cached_at_utc).ok()?;
        let age_secs = Utc::now().signed_duration_since(cached_dt.with_timezone(&Utc)).num_seconds();
        if age_secs <= VT_CACHE_TTL_SECS {
            let mut cloned = entry.clone();
            if let Some(epoch) = cloned.last_analysis_date_epoch {
                cloned.report_age_human = format_report_age(epoch);
            }
            Some(cloned)
        } else {
            None
        }
    }

    pub fn insert_and_save(&mut self, report: VtFileReport, path: &Path) {
        self.entries
            .insert(report.sha256.to_ascii_lowercase(), report);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
        }
    }
}

/// Gestor seguro de clave API exclusivamente en backend (env var o archivo DPAPI/restringido)
pub struct VtSecureKeyBackend;

impl VtSecureKeyBackend {
    pub fn resolve_api_key(data_dir: &Path) -> Option<String> {
        for var in ["VT_API_KEY", "SAMULIBRE_VT_API_KEY"] {
            if let Ok(val) = std::env::var(var) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        let secure_path = data_dir.join("secure").join("vt_backend.key");
        if secure_path.exists() {
            if let Ok(raw) = fs::read_to_string(&secure_path) {
                let trimmed = raw.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        None
    }

    pub fn has_api_key(data_dir: &Path) -> bool {
        Self::resolve_api_key(data_dir).is_some()
    }

    pub fn save_backend_key(data_dir: &Path, key: &str) -> anyhow::Result<()> {
        let secure_dir = data_dir.join("secure");
        fs::create_dir_all(&secure_dir)?;
        let secure_path = secure_dir.join("vt_backend.key");
        let trimmed = key.trim();
        if trimmed.is_empty() {
            if secure_path.exists() {
                fs::remove_file(&secure_path)?;
            }
            return Ok(());
        }
        fs::write(&secure_path, trimmed)?;
        Ok(())
    }
}

/// Servicio principal VIRUSTOTAL THREAT VERIFICATION
pub struct VirusTotalVerifier {
    data_dir: PathBuf,
    policy: VtVerificationPolicy,
}

impl VirusTotalVerifier {
    pub fn new(data_dir: impl AsRef<Path>, policy: VtVerificationPolicy) -> Self {
        Self {
            data_dir: data_dir.as_ref().to_path_buf(),
            policy,
        }
    }

    pub fn load_policy(data_dir: &Path) -> VtVerificationPolicy {
        let p = data_dir.join("vt_policy.json");
        if let Ok(s) = fs::read_to_string(&p) {
            if let Ok(pol) = serde_json::from_str::<VtVerificationPolicy>(&s) {
                return pol;
            }
        }
        VtVerificationPolicy::default()
    }

    pub fn save_policy(data_dir: &Path, policy: &VtVerificationPolicy) {
        let _ = fs::create_dir_all(data_dir);
        let p = data_dir.join("vt_policy.json");
        if let Ok(json) = serde_json::to_string_pretty(policy) {
            let _ = fs::write(p, json);
        }
    }

    pub fn compute_sha256_file(path: &Path) -> anyhow::Result<String> {
        let mut file = fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn is_sensitive_document(path: &Path) -> bool {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if matches!(
            ext.as_str(),
            "pdf" | "doc" | "docx" | "docm" | "xls" | "xlsx" | "xlsm" | "ppt" | "pptx" | "pptm"
                | "odt" | "ods" | "odp" | "rtf"
        ) {
            return true;
        }
        if let Ok(mut f) = fs::File::open(path) {
            let mut magic = [0u8; 5];
            if f.read(&mut magic).unwrap_or(0) >= 4 && magic.starts_with(b"%PDF") {
                return true;
            }
        }
        false
    }

    fn ledger_path(&self) -> PathBuf {
        self.data_dir.join("audit").join("detection_ledger.jsonl")
    }

    fn cache_path(&self) -> PathBuf {
        self.data_dir.join("vt_cache.json")
    }

    fn quota_path(&self) -> PathBuf {
        self.data_dir.join("vt_quota.json")
    }

    /// 1) Calcula SHA-256 si hace falta, 2) Consulta caché/API por SHA-256,
    /// 3) Correlaciona con el motor local sin alterar reglas locales ni asumir 0 detecciones = seguro.
    pub fn verify_threat_record(
        &self,
        record: &ThreatRecord,
        allow_upload_with_explicit_consent: bool,
    ) -> VtCorrelationReport {
        let file_path = Path::new(&record.file_path);
        let sha256 = if !record.sha256.is_empty() && record.sha256 != "BLOCKED_BY_KERNEL" {
            record.sha256.to_ascii_lowercase()
        } else if file_path.exists() {
            Self::compute_sha256_file(file_path).unwrap_or_default()
        } else {
            String::new()
        };

        let is_sensitive_doc = Self::is_sensitive_document(file_path);
        let privacy_warning = if is_sensitive_doc {
            Some("ADVERTENCIA DE PRIVACIDAD: El archivo es un documento PDF u Office que puede contener información personal o corporativa confidencial. No se subirá a VirusTotal sin su consentimiento explícito.".to_string())
        } else {
            None
        };

        let mut local_detections = vec![record.threat_name.clone()];
        for ev in &record.evidences {
            if !local_detections.contains(&ev.rule_id) {
                local_detections.push(ev.rule_id.clone());
            }
        }

        let mut quota = VtQuotaState::load(&self.quota_path());
        quota.prune();

        if sha256.len() != 64 {
            return self.build_error_report(
                record,
                &sha256,
                local_detections,
                is_sensitive_doc,
                privacy_warning,
                &quota,
                "SHA-256 inválido o archivo bloqueado/no accesible para hashing.",
            );
        }

        // Consultar caché primero (sin consumir cuota)
        let mut cache = VtCacheStore::load(&self.cache_path());
        if let Some(cached_report) = cache.get_fresh(&sha256) {
            let _ = DetectionAuditLedger::append_entry(
                &self.ledger_path(),
                "VT_CACHE_HIT",
                &sha256,
                &record.file_path,
                &record.threat_name,
                record.confidence_level.as_str(),
                record.calibrated_score,
                "VirusTotalVerifier",
                "Informe recuperado de caché local (<=24h)",
            );
            return self.correlate_with_vt(
                record,
                local_detections,
                cached_report,
                true,
                is_sensitive_doc,
                privacy_warning,
                &quota,
                None,
            );
        }

        // Verificar API Key en backend seguro
        let api_key = match VtSecureKeyBackend::resolve_api_key(&self.data_dir) {
            Some(k) => k,
            None => {
                let _ = DetectionAuditLedger::append_entry(
                    &self.ledger_path(),
                    "VT_ERROR",
                    &sha256,
                    &record.file_path,
                    &record.threat_name,
                    record.confidence_level.as_str(),
                    record.calibrated_score,
                    "VirusTotalVerifier",
                    "API Key no configurada en backend seguro (VT_API_KEY / vt_backend.key)",
                );
                return self.build_error_report(
                    record,
                    &sha256,
                    local_detections,
                    is_sensitive_doc,
                    privacy_warning,
                    &quota,
                    "API Key de VirusTotal no configurada en el backend seguro. Configure la clave en el panel Backend Seguro o en la variable de entorno VT_API_KEY.",
                );
            }
        };

        // Consultar informe existente por SHA-256
        match self.fetch_file_report_by_hash(&api_key, &sha256, &mut quota) {
            Ok(report) => {
                cache.insert_and_save(report.clone(), &self.cache_path());
                let _ = DetectionAuditLedger::append_entry(
                    &self.ledger_path(),
                    "VT_HASH_LOOKUP",
                    &sha256,
                    &record.file_path,
                    &record.threat_name,
                    record.confidence_level.as_str(),
                    record.calibrated_score,
                    "VirusTotalVerifier",
                    &format!(
                        "Consulta SHA-256 exitosa: malicious={}, suspicious={}, undetected={}",
                        report.stats.malicious, report.stats.suspicious, report.stats.undetected
                    ),
                );
                self.correlate_with_vt(
                    record,
                    local_detections,
                    report,
                    false,
                    is_sensitive_doc,
                    privacy_warning,
                    &quota,
                    None,
                )
            }
            Err(err) if err.kind == VtErrorKind::NotFound => {
                let _ = DetectionAuditLedger::append_entry(
                    &self.ledger_path(),
                    "VT_HASH_NOT_FOUND",
                    &sha256,
                    &record.file_path,
                    &record.threat_name,
                    record.confidence_level.as_str(),
                    record.calibrated_score,
                    "VirusTotalVerifier",
                    "Sin informe previo en VirusTotal para este SHA-256 (HTTP 404)",
                );

                // Evaluar si procede subida automática (solo sospecha, NO Office/PDF, y NO modo solo-hash)
                // o si requiere consentimiento explícito.
                let is_local_suspicion = matches!(
                    record.confidence_level,
                    ConfidenceLevel::Medio | ConfidenceLevel::Alto | ConfidenceLevel::Critico
                );
                let auto_upload_allowed = !self.policy.hash_only_mode
                    && self.policy.auto_upload_suspicious_non_docs
                    && is_local_suspicion
                    && !is_sensitive_doc;

                if !self.policy.hash_only_mode
                    && (allow_upload_with_explicit_consent || auto_upload_allowed)
                    && file_path.exists()
                {
                    if allow_upload_with_explicit_consent {
                        let _ = DetectionAuditLedger::append_entry(
                            &self.ledger_path(),
                            "VT_PRIVACY_CONSENT",
                            &sha256,
                            &record.file_path,
                            &record.threat_name,
                            record.confidence_level.as_str(),
                            record.calibrated_score,
                            "Analyst",
                            "Consentimiento explícito otorgado para subida de archivo a VirusTotal",
                        );
                    }
                    match self.upload_file_to_vt(&api_key, file_path, &mut quota) {
                        Ok(analysis_id) => {
                            let _ = DetectionAuditLedger::append_entry(
                                &self.ledger_path(),
                                "VT_FILE_UPLOAD",
                                &sha256,
                                &record.file_path,
                               &record.threat_name,
                                record.confidence_level.as_str(),
                                record.calibrated_score,
                                "VirusTotalVerifier",
                                &format!("Archivo enviado a VirusTotal (analysis_id={})", analysis_id),
                            );
                            VtCorrelationReport {
                                sha256,
                                file_path: record.file_path.clone(),
                                local_detections,
                                local_confidence: record.confidence_level,
                                local_score: record.calibrated_score,
                                found_in_vt: false,
                                from_cache: false,
                                vt_stats: None,
                                vt_engines: Vec::new(),
                                agreeing_engines: Vec::new(),
                                disagreeing_engines: Vec::new(),
                                analysis_date_utc: None,
                                report_age_human: None,
                                samulibre_recommendation: "Archivo enviado a VirusTotal para análisis. Re-consulte en 30-60s para obtener el veredicto de motores.".to_string(),
                                privacy_status: if is_sensitive_doc {
                                    "Documento sensible subido con consentimiento explícito del usuario.".to_string()
                                } else if auto_upload_allowed {
                                    "Subida automática autorizada por política (sospecha local en binario no documental).".to_string()
                                } else {
                                    "Subido con autorización explícita del usuario.".to_string()
                                },
                                is_sensitive_document: is_sensitive_doc,
                                requires_explicit_consent: false,
                                can_offer_upload: false,
                                privacy_warning,
                                uploaded_analysis_id: Some(analysis_id),
                                error_detail: None,
                                quota_minute_used: quota.minute_timestamps.len(),
                                quota_minute_limit: VT_FREE_PER_MINUTE,
                                quota_day_used: quota.day_count,
                                quota_day_limit: VT_FREE_PER_DAY,
                            }
                        }
                        Err(up_err) => self.build_error_report(
                            record,
                            &sha256,
                            local_detections,
                            is_sensitive_doc,
                            privacy_warning,
                            &quota,
                            &up_err.message,
                        ),
                    }
                } else {
                    let privacy_status = if self.policy.hash_only_mode {
                        "Modo Solo Hash activo: archivo NO subido (sin informe previo en VT).".to_string()
                    } else if is_sensitive_doc {
                        "Bloqueado por privacidad (PDF/Office): requiere consentimiento explícito para subir.".to_string()
                    } else {
                        "Sin informe previo en VT: requiere autorización del analista para subir el archivo.".to_string()
                    };
                    VtCorrelationReport {
                        sha256,
                        file_path: record.file_path.clone(),
                        local_detections,
                        local_confidence: record.confidence_level,
                        local_score: record.calibrated_score,
                        found_in_vt: false,
                        from_cache: false,
                        vt_stats: None,
                        vt_engines: Vec::new(),
                        agreeing_engines: Vec::new(),
                        disagreeing_engines: Vec::new(),
                        analysis_date_utc: None,
                        report_age_human: None,
                        samulibre_recommendation: "Sin informe previo en VirusTotal. Mantenga la evaluación del motor local SamuLibre; puede autorizar la subida si desea análisis remoto.".to_string(),
                        privacy_status,
                        is_sensitive_document: is_sensitive_doc,
                        requires_explicit_consent: true,
                        can_offer_upload: file_path.exists(),
                        privacy_warning,
                        uploaded_analysis_id: None,
                        error_detail: None,
                        quota_minute_used: quota.minute_timestamps.len(),
                        quota_minute_limit: VT_FREE_PER_MINUTE,
                        quota_day_used: quota.day_count,
                        quota_day_limit: VT_FREE_PER_DAY,
                    }
                }
            }
            Err(err) => {
                let _ = DetectionAuditLedger::append_entry(
                    &self.ledger_path(),
                    "VT_ERROR",
                    &sha256,
                    &record.file_path,
                    &record.threat_name,
                    record.confidence_level.as_str(),
                    record.calibrated_score,
                    "VirusTotalVerifier",
                    &err.message,
                );
                self.build_error_report(
                    record,
                    &sha256,
                    local_detections,
                    is_sensitive_doc,
                    privacy_warning,
                    &quota,
                    &err.message,
                )
            }
        }
    }

    /// Consulta HTTP GET /api/v3/files/{sha256} manejando 404, 429, 401/403, timeout y red
    pub fn fetch_file_report_by_hash(
        &self,
        api_key: &str,
        sha256: &str,
        quota: &mut VtQuotaState,
    ) -> Result<VtFileReport, VtError> {
        quota.check_and_consume(&self.quota_path())?;
        let url = format!("{}/files/{}", VT_API_BASE, sha256);
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(8))
            .timeout_read(Duration::from_secs(15))
            .build();

        match agent.get(&url).set("x-apikey", api_key).call() {
            Ok(resp) => {
                let val: serde_json::Value = resp.into_json().map_err(|e| VtError {
                    kind: VtErrorKind::ParseError,
                    message: format!("Respuesta JSON inválida de VirusTotal: {}", e),
                })?;
                Self::parse_vt_file_report(sha256, &val)
            }
            Err(ureq::Error::Status(code, _resp)) => Err(Self::map_http_status_error(code)),
            Err(ureq::Error::Transport(t)) => {
                let msg = t.to_string();
                let kind = if msg.to_ascii_lowercase().contains("timed out") {
                    VtErrorKind::Timeout
                } else {
                    VtErrorKind::Connectivity
                };
                Err(VtError {
                    kind,
                    message: format!("Fallo de conectividad/timeout con VirusTotal: {}", msg),
                })
            }
        }
    }

    /// Subida real multipart/form-data a POST /api/v3/files (<=32MB)
    pub fn upload_file_to_vt(
        &self,
        api_key: &str,
        file_path: &Path,
        quota: &mut VtQuotaState,
    ) -> Result<String, VtError> {
        let meta = fs::metadata(file_path).map_err(|e| VtError {
            kind: VtErrorKind::Connectivity,
            message: format!("No se pudo leer metadatos del archivo: {}", e),
        })?;
        if meta.len() > VT_MAX_DIRECT_UPLOAD_BYTES {
            return Err(VtError {
                kind: VtErrorKind::FileTooLarge,
                message: "El archivo supera el límite de 32 MB de subida directa de la API pública gratuita.".to_string(),
            });
        }

        quota.check_and_consume(&self.quota_path())?;
        let bytes = fs::read(file_path).map_err(|e| VtError {
            kind: VtErrorKind::Connectivity,
            message: format!("No se pudo leer archivo para subida: {}", e),
        })?;
        let filename = file_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("sample.bin");

        let boundary = format!("----SamuLibreVT{}", uuid::Uuid::new_v4().simple());
        let mut body = Vec::with_capacity(bytes.len() + 512);
        body.extend_from_slice(
            format!(
                "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
                boundary, filename
            )
            .as_bytes(),
        );
        body.extend_from_slice(&bytes);
        body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());

        let url = format!("{}/files", VT_API_BASE);
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_write(Duration::from_secs(30))
            .timeout_read(Duration::from_secs(20))
            .build();

        match agent
            .post(&url)
            .set("x-apikey", api_key)
            .set(
                "Content-Type",
                &format!("multipart/form-data; boundary={}", boundary),
            )
            .send_bytes(&body)
        {
            Ok(resp) => {
                let val: serde_json::Value = resp.into_json().map_err(|e| VtError {
                    kind: VtErrorKind::ParseError,
                    message: format!("Respuesta JSON inválida tras subida: {}", e),
                })?;
                let id = val["data"]["id"]
                    .as_str()
                    .unwrap_or("pending-analysis")
                    .to_string();
                Ok(id)
            }
            Err(ureq::Error::Status(code, _)) => Err(Self::map_http_status_error(code)),
            Err(ureq::Error::Transport(t)) => Err(VtError {
                kind: VtErrorKind::Connectivity,
                message: format!("Error de red durante subida a VirusTotal: {}", t),
            }),
        }
    }

    pub fn map_http_status_error(code: u16) -> VtError {
        match code {
            404 => VtError {
                kind: VtErrorKind::NotFound,
                message: "HTTP 404: El hash SHA-256 no existe aún en VirusTotal.".to_string(),
            },
            429 => VtError {
                kind: VtErrorKind::RateLimit429,
                message: "HTTP 429: Cuota de peticiones de VirusTotal excedida. Reintente más tarde.".to_string(),
            },
            401 | 403 => VtError {
                kind: VtErrorKind::AuthError,
                message: format!("HTTP {}: Error de autenticación o permisos con la API Key de VirusTotal.", code),
            },
            408 | 504 => VtError {
                kind: VtErrorKind::Timeout,
                message: format!("HTTP {}: Tiempo de espera agotado en VirusTotal.", code),
            },
            _ => VtError {
                kind: VtErrorKind::Connectivity,
                message: format!("HTTP {}: Error devuelto por la API de VirusTotal.", code),
            },
        }
    }

    /// Parsea la respuesta oficial de VirusTotal API v3 `/api/v3/files/{hash}`
    pub fn parse_vt_file_report(
        sha256: &str,
        root: &serde_json::Value,
    ) -> Result<VtFileReport, VtError> {
        let attrs = &root["data"]["attributes"];
        if attrs.is_null() {
            return Err(VtError {
                kind: VtErrorKind::ParseError,
                message: "Falta objeto data.attributes en la respuesta de VirusTotal.".to_string(),
            });
        }

        let mut stats = VtAnalysisStats::default();
        let mut engines = Vec::new();

        if let Some(results_map) = attrs["last_analysis_results"].as_object() {
            for (name, item) in results_map {
                let raw_cat = item["category"].as_str().unwrap_or("timeout").to_string();
                let cat = VtEngineCategory::from_vt_str(&raw_cat);
                match cat {
                    VtEngineCategory::Malicious => stats.malicious += 1,
                    VtEngineCategory::Suspicious => stats.suspicious += 1,
                    VtEngineCategory::Undetected => stats.undetected += 1,
                    VtEngineCategory::Harmless => stats.harmless += 1,
                    VtEngineCategory::TimeoutOrError => stats.timeout_or_error += 1,
                }
                stats.total_engines += 1;
                engines.push(VtEngineResult {
                    engine_name: item["engine_name"]
                        .as_str()
                        .unwrap_or(name.as_str())
                        .to_string(),
                    category: cat,
                    raw_category: raw_cat,
                    result: item["result"].as_str().map(|s| s.to_string()),
                    method: item["method"].as_str().map(|s| s.to_string()),
                    engine_version: item["engine_version"].as_str().map(|s| s.to_string()),
                    agrees_with_local: false,
                    disagrees_with_local: false,
                });
            }
        }

        engines.sort_by(|a, b| {
            let rank = |c: VtEngineCategory| match c {
                VtEngineCategory::Malicious => 0,
                VtEngineCategory::Suspicious => 1,
                VtEngineCategory::Undetected => 2,
                VtEngineCategory::Harmless => 3,
                VtEngineCategory::TimeoutOrError => 4,
            };
            rank(a.category)
                .cmp(&rank(b.category))
                .then_with(|| a.engine_name.cmp(&b.engine_name))
        });

        let last_epoch = attrs["last_analysis_date"].as_i64();
        let last_utc = last_epoch.and_then(|ts| {
            DateTime::<Utc>::from_timestamp(ts, 0).map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        });
        let age_human = last_epoch
            .map(format_report_age)
            .unwrap_or_else(|| "Fecha de análisis no disponible".to_string());

        Ok(VtFileReport {
            sha256: sha256.to_ascii_lowercase(),
            stats,
            engines,
            last_analysis_date_epoch: last_epoch,
            last_analysis_date_utc: last_utc,
            report_age_human: age_human,
            reputation: attrs["reputation"].as_i64(),
            meaning_name: attrs["meaningful_name"].as_str().map(|s| s.to_string()),
            permalink: format!("https://www.virustotal.com/gui/file/{}", sha256),
            cached_at_utc: Utc::now().to_rfc3339(),
        })
    }

    fn correlate_with_vt(
        &self,
        record: &ThreatRecord,
        local_detections: Vec<String>,
        mut report: VtFileReport,
        from_cache: bool,
        is_sensitive_doc: bool,
        privacy_warning: Option<String>,
        quota: &VtQuotaState,
        error_detail: Option<String>,
    ) -> VtCorrelationReport {
        let local_flagged = true; // ThreatRecord proviene de una detección/sospecha local
        let mut agreeing_engines = Vec::new();
        let mut disagreeing_engines = Vec::new();

        for eng in report.engines.iter_mut() {
            let vt_flagged = matches!(
                eng.category,
                VtEngineCategory::Malicious | VtEngineCategory::Suspicious
            );
            if local_flagged && vt_flagged {
                eng.agrees_with_local = true;
                agreeing_engines.push(format!(
                    "{} ({})",
                    eng.engine_name,
                    eng.result.as_deref().unwrap_or(eng.category.label_es())
                ));
            } else if matches!(
                eng.category,
                VtEngineCategory::Undetected | VtEngineCategory::Harmless
            ) {
                eng.disagrees_with_local = true;
                disagreeing_engines.push(eng.engine_name.clone());
            }
        }

        // Regla 10, 12 y 13: Correlación informativa; NUNCA mutar YARA/firmas automáticamente y
        // NUNCA declarar seguro un archivo por tener 0 detecciones en VirusTotal.
        let recommendation = if report.stats.malicious >= 5 {
            format!(
                "Consenso externo elevado ({}/{} motores maliciosos). Corrobora las evidencias locales; se recomienda cuarentena/confirmación.",
                report.stats.malicious, report.stats.total_engines
            )
        } else if report.stats.malicious > 0 || report.stats.suspicious > 0 {
            format!(
                "Detección parcial en VirusTotal ({} malicious, {} suspicious). No basta como prueba definitiva aislada; correlacione con las evidencias locales de SamuLibre (nivel {:?}).",
                report.stats.malicious, report.stats.suspicious, record.confidence_level
            )
        } else {
            format!(
                "0 detecciones en VirusTotal (no garantiza que el archivo sea seguro). Verifique las evidencias locales ({:?}, score={}) antes de descartar o reportar como posible falso positivo.",
                record.confidence_level, record.calibrated_score
            )
        };

        VtCorrelationReport {
            sha256: report.sha256.clone(),
            file_path: record.file_path.clone(),
            local_detections,
            local_confidence: record.confidence_level,
            local_score: record.calibrated_score,
            found_in_vt: true,
            from_cache,
            vt_stats: Some(report.stats.clone()),
            vt_engines: report.engines,
            agreeing_engines,
            disagreeing_engines,
            analysis_date_utc: report.last_analysis_date_utc,
            report_age_human: Some(report.report_age_human),
            samulibre_recommendation: recommendation,
            privacy_status: "Consulta exclusiva por SHA-256 (archivo local NO enviado).".to_string(),
            is_sensitive_document: is_sensitive_doc,
            requires_explicit_consent: false,
            can_offer_upload: false,
            privacy_warning,
            uploaded_analysis_id: None,
            error_detail,
            quota_minute_used: quota.minute_timestamps.len(),
            quota_minute_limit: VT_FREE_PER_MINUTE,
            quota_day_used: quota.day_count,
            quota_day_limit: VT_FREE_PER_DAY,
        }
    }

    fn build_error_report(
        &self,
        record: &ThreatRecord,
        sha256: &str,
        local_detections: Vec<String>,
        is_sensitive_doc: bool,
        privacy_warning: Option<String>,
        quota: &VtQuotaState,
        error_msg: &str,
    ) -> VtCorrelationReport {
        VtCorrelationReport {
            sha256: sha256.to_string(),
            file_path: record.file_path.clone(),
            local_detections,
            local_confidence: record.confidence_level,
            local_score: record.calibrated_score,
            found_in_vt: false,
            from_cache: false,
            vt_stats: None,
            vt_engines: Vec::new(),
            agreeing_engines: Vec::new(),
            disagreeing_engines: Vec::new(),
            analysis_date_utc: None,
            report_age_human: None,
            samulibre_recommendation: "Verificación externa no disponible; mantenga la decisión prudente basada en evidencias locales de SamuLibre.".to_string(),
            privacy_status: if self.policy.hash_only_mode {
                "Modo Solo Hash (sin subida de archivo).".to_string()
            } else {
                "Sin envío de archivo.".to_string()
            },
            is_sensitive_document: is_sensitive_doc,
            requires_explicit_consent: is_sensitive_doc,
            can_offer_upload: false,
            privacy_warning,
            uploaded_analysis_id: None,
            error_detail: Some(error_msg.to_string()),
            quota_minute_used: quota.minute_timestamps.len(),
            quota_minute_limit: VT_FREE_PER_MINUTE,
            quota_day_used: quota.day_count,
            quota_day_limit: VT_FREE_PER_DAY,
        }
    }
}

pub fn format_report_age(epoch_secs: i64) -> String {
    let now = Utc::now().timestamp();
    let diff = (now - epoch_secs).max(0);
    if diff < 60 {
        format!("hace {} seg", diff)
    } else if diff < 3600 {
        format!("hace {} min", diff / 60)
    } else if diff < 86400 {
        format!("hace {} h", diff / 3600)
    } else {
        format!("hace {} día(s)", diff / 86400)
    }
}
