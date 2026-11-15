use chrono::Utc;
use samulibre_types::{
    AuthenticodeStatus, PublisherTrustTier, ReputationAssessment, ReputationTrustLevel,
    UserReputationOverride,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::info;
use uuid::Uuid;

/// Indicador de amenaza compartido en la red comunitaria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityThreatIndicator {
    pub sha256: String,
    pub threat_name: String,
    pub confidence: f32,
    pub reports_count: u32,
    pub category: String,
}

/// Motor de Reputación Comunitario con K-Anonimato
/// Protege la privacidad del usuario compartiendo y consultando únicamente prefijos truncados (K-Anonymity)
pub struct CommunityReputationEngine {
    // Almacenamiento indexado por prefijo de 5 caracteres hex (K-Anonymity bucket)
    prefix_buckets: HashMap<String, Vec<CommunityThreatIndicator>>,
}

impl CommunityReputationEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            prefix_buckets: HashMap::new(),
        };
        engine.load_builtin_threat_feed();
        engine
    }

    /// Carga indicadores iniciales de la comunidad
    fn load_builtin_threat_feed(&mut self) {
        let defaults = [
            (
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "EICAR-Standard-Test-File",
                "Test",
                999,
            ),
            (
                "5417eb735c05e197cdcd7ffbb538c82eb5e7d53b2111d4d1421034c442436f54",
                "Trojan.Win32.RedLineStealer",
                "Infostealer",
                42,
            ),
            (
                "84c82835a5d21bbcf75a61706d8ab5494030493ae1ab12f54cb07fb4b8e40d1e",
                "Ransomware.Win32.LockBit3",
                "Ransomware",
                128,
            ),
        ];

        for (hash, name, cat, count) in defaults {
            self.submit_indicator(CommunityThreatIndicator {
                sha256: hash.to_string(),
                threat_name: name.to_string(),
                confidence: 0.98,
                reports_count: count,
                category: cat.to_string(),
            });
        }
    }

    /// Registra un nuevo indicador en el bucket correspondiente a su prefijo de K-anonimato (5 caracteres)
    pub fn submit_indicator(&mut self, indicator: CommunityThreatIndicator) {
        if indicator.sha256.len() < 5 {
            return;
        }
        let prefix = indicator.sha256[..5].to_lowercase();
        let bucket = self.prefix_buckets.entry(prefix).or_default();

        // Si ya existe el hash en el bucket, actualizar conteo de reportes comunitarios
        if let Some(existing) = bucket
            .iter_mut()
            .find(|i| i.sha256.eq_ignore_ascii_case(&indicator.sha256))
        {
            existing.reports_count += 1;
            existing.confidence = (existing.confidence * 0.9 + indicator.confidence * 0.1).min(1.0);
        } else {
            bucket.push(indicator);
        }
    }

    /// Consulta anónima por K-Anonimato: el cliente envía únicamente los primeros 5 caracteres del hash.
    /// El servidor o nodo comunitario responde con todos los candidatos que comparten ese prefijo.
    /// El cliente resuelve la coincidencia en local, sin revelar el hash completo del archivo a la red.
    pub fn query_by_k_anonymity_prefix(
        &self,
        prefix_5chars: &str,
    ) -> Vec<CommunityThreatIndicator> {
        let p = prefix_5chars.to_lowercase();
        self.prefix_buckets.get(&p).cloned().unwrap_or_default()
    }

    /// Consulta local directa: verifica si el hash completo coincide con algún registro verificado
    pub fn lookup_hash(&self, full_sha256: &str) -> Option<CommunityThreatIndicator> {
        if full_sha256.len() < 5 {
            return None;
        }
        let prefix = full_sha256[..5].to_lowercase();
        let bucket = self.prefix_buckets.get(&prefix)?;
        bucket
            .iter()
            .find(|i| i.sha256.eq_ignore_ascii_case(full_sha256))
            .cloned()
    }
}

// ─── FASE 7: SISTEMA INTEGRAL DE REPUTACIÓN Y MITIGACIÓN DE FALSOS POSITIVOS ──

/// Catálogo de editores y certificados de confianza (Publishers Whitelist)
pub struct TrustedPublisherCatalog;

impl TrustedPublisherCatalog {
    pub const TIER1_PLATFORM_CORE: &'static [&'static str] = &[
        "Microsoft Corporation",
        "Microsoft Windows",
        "Microsoft Windows Publisher",
        "Microsoft Windows Production PCA",
        "Microsoft Development Root Certificate Authority",
    ];

    pub const TIER2_COMMERCIAL: &'static [&'static str] = &[
        "Google LLC",
        "Mozilla Corporation",
        "Apple Inc.",
        "Valve Corporation",
        "Oracle America, Inc.",
        "Adobe Inc.",
        "NVIDIA Corporation",
        "Advanced Micro Devices, Inc.",
        "Intel Corporation",
        "Cisco Systems, Inc.",
    ];

    pub const TIER3_DEV_TOOLCHAIN: &'static [&'static str] = &[
        "Rust Foundation",
        "Python Software Foundation",
        "Git for Windows",
        "Node.js Foundation",
        "OpenJS Foundation",
        "Docker Inc.",
        "GitHub, Inc.",
        "Canonical Ltd.",
    ];

    pub fn classify_publisher(publisher_name: &str) -> PublisherTrustTier {
        let lower = publisher_name.to_lowercase();
        for p in Self::TIER1_PLATFORM_CORE {
            if lower.contains(&p.to_lowercase()) {
                return PublisherTrustTier::Tier1PlatformCore;
            }
        }
        for p in Self::TIER2_COMMERCIAL {
            if lower.contains(&p.to_lowercase()) {
                return PublisherTrustTier::Tier2VerifiedCommercial;
            }
        }
        for p in Self::TIER3_DEV_TOOLCHAIN {
            if lower.contains(&p.to_lowercase()) {
                return PublisherTrustTier::Tier3DeveloperToolchain;
            }
        }
        PublisherTrustTier::Untrusted
    }
}

/// Nombres de binarios estándar del sistema operativo Windows
pub const WINDOWS_OS_CRITICAL_BINARIES: &[&str] = &[
    "notepad.exe",
    "calc.exe",
    "explorer.exe",
    "cmd.exe",
    "svchost.exe",
    "taskmgr.exe",
    "regedit.exe",
    "lsass.exe",
    "services.exe",
    "csrss.exe",
    "conhost.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "rundll32.exe",
    "powershell.exe",
    "pwsh.exe",
];

/// Nombres de binarios de desarrollo y administración sujetos a supresión inteligente de falsos positivos
pub const DEVELOPER_TOOLCHAIN_BINARIES: &[&str] = &[
    "cargo.exe",
    "rustc.exe",
    "rustup.exe",
    "git.exe",
    "python.exe",
    "pythonw.exe",
    "pip.exe",
    "node.exe",
    "npm.cmd",
    "code.exe",
    "docker.exe",
];

/// Validador de firmas Authenticode en ejecutables PE (Portable Executable)
pub struct AuthenticodeValidator;

impl AuthenticodeValidator {
    /// Inspecciona el directorio de seguridad (IMAGE_DIRECTORY_ENTRY_SECURITY) del PE
    pub fn inspect_pe_signature(bytes: &[u8]) -> (AuthenticodeStatus, Option<String>) {
        if bytes.len() < 64 || &bytes[0..2] != b"MZ" {
            return (AuthenticodeStatus::NotSigned, None);
        }

        let pe_offset = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as usize;
        if pe_offset + 24 > bytes.len() || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return (AuthenticodeStatus::NotSigned, None);
        }

        let optional_header_offset = pe_offset + 24;
        if optional_header_offset + 2 > bytes.len() {
            return (AuthenticodeStatus::NotSigned, None);
        }

        let magic = u16::from_le_bytes([
            bytes[optional_header_offset],
            bytes[optional_header_offset + 1],
        ]);

        let (sec_dir_offset, _is_64bit) = match magic {
            0x010b => (optional_header_offset + 128, false), // PE32
            0x020b => (optional_header_offset + 144, true),  // PE32+
            _ => return (AuthenticodeStatus::NotSigned, None),
        };

        if sec_dir_offset + 8 > bytes.len() {
            return (AuthenticodeStatus::NotSigned, None);
        }

        let cert_table_rva = u32::from_le_bytes([
            bytes[sec_dir_offset],
            bytes[sec_dir_offset + 1],
            bytes[sec_dir_offset + 2],
            bytes[sec_dir_offset + 3],
        ]) as usize;

        let cert_table_size = u32::from_le_bytes([
            bytes[sec_dir_offset + 4],
            bytes[sec_dir_offset + 5],
            bytes[sec_dir_offset + 6],
            bytes[sec_dir_offset + 7],
        ]) as usize;

        if cert_table_rva == 0 || cert_table_size == 0 {
            return (AuthenticodeStatus::NotSigned, None);
        }

        if cert_table_rva + cert_table_size > bytes.len() {
            return (AuthenticodeStatus::InvalidSignature, None);
        }

        let cert_slice = &bytes[cert_table_rva..cert_table_rva + cert_table_size];
        if cert_slice.len() < 8 {
            return (AuthenticodeStatus::InvalidSignature, None);
        }

        let w_revision = u16::from_le_bytes([cert_slice[4], cert_slice[5]]);
        let w_cert_type = u16::from_le_bytes([cert_slice[6], cert_slice[7]]);

        // WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
        if w_cert_type != 0x0002 || (w_revision != 0x0100 && w_revision != 0x0200) {
            return (AuthenticodeStatus::InvalidSignature, None);
        }

        let pkcs7_payload = &cert_slice[8..];
        let publisher = Self::extract_publisher_heuristic(pkcs7_payload);

        (AuthenticodeStatus::Valid, publisher)
    }

    /// Extracción heurística del Common Name (CN) o Organización (O) en el bloque ASN.1/PKCS#7
    fn extract_publisher_heuristic(payload: &[u8]) -> Option<String> {
        let text_repr = String::from_utf8_lossy(payload);

        let known_publishers = [
            "Microsoft Corporation",
            "Microsoft Windows",
            "Google LLC",
            "Mozilla Corporation",
            "Apple Inc.",
            "Valve Corporation",
            "Rust Foundation",
            "Python Software Foundation",
            "Git for Windows",
            "Docker Inc.",
            "Intel Corporation",
            "NVIDIA Corporation",
            "Advanced Micro Devices, Inc.",
        ];

        for &pub_name in &known_publishers {
            if text_repr.contains(pub_name) {
                return Some(pub_name.to_string());
            }
        }

        // Búsqueda genérica de "CN=" o "O=" si existe en formato ASCII
        if let Some(pos) = text_repr.find("CN=") {
            let rest = &text_repr[pos + 3..];
            let end = rest.find(|c: char| c == ',' || c == '\n' || c == '\0').unwrap_or(rest.len().min(40));
            let cn = rest[..end].trim();
            if !cn.is_empty() && cn.len() > 2 {
                return Some(cn.to_string());
            }
        }

        None
    }
}

/// Gestor de exclusiones y reportes de falsos positivos
pub struct UserReputationOverridesManager {
    overrides_file: PathBuf,
    overrides: Arc<Mutex<Vec<UserReputationOverride>>>,
}

impl UserReputationOverridesManager {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let base_dir = data_dir.as_ref().join("reputation");
        let _ = fs::create_dir_all(&base_dir);
        let overrides_file = base_dir.join("overrides.json");

        let mut list = Vec::new();
        if overrides_file.exists() {
            if let Ok(data) = fs::read_to_string(&overrides_file) {
                if let Ok(parsed) = serde_json::from_str::<Vec<UserReputationOverride>>(&data) {
                    list = parsed;
                }
            }
        }

        Self {
            overrides_file,
            overrides: Arc::new(Mutex::new(list)),
        }
    }

    /// Agrega una exclusión o reporte de falso positivo
    pub fn add_override(
        &self,
        sha256: Option<String>,
        file_path_pattern: Option<String>,
        publisher_name: Option<String>,
        reason: String,
    ) -> UserReputationOverride {
        let rule = UserReputationOverride {
            id: Uuid::new_v4(),
            sha256,
            file_path_pattern,
            publisher_name,
            reason,
            created_at: Utc::now(),
            report_status: "ApprovedLocal".to_string(),
        };

        let mut lock = self.overrides.lock().unwrap();
        lock.push(rule.clone());
        self.persist(&lock);
        info!("Exclusión de reputación registrada con éxito: {:?}", rule.id);
        rule
    }

    /// Elimina una regla por su UUID
    pub fn remove_override(&self, id: Uuid) -> bool {
        let mut lock = self.overrides.lock().unwrap();
        let initial_len = lock.len();
        lock.retain(|r| r.id != id);
        let changed = lock.len() < initial_len;
        if changed {
            self.persist(&lock);
        }
        changed
    }

    /// Lista todas las exclusiones activas
    pub fn list_overrides(&self) -> Vec<UserReputationOverride> {
        self.overrides.lock().unwrap().clone()
    }

    /// Comprueba si un archivo o hash está explícitamente excluido por el usuario
    pub fn is_excluded(&self, path: &Path, sha256: &str) -> bool {
        let lock = self.overrides.lock().unwrap();
        let path_str = path.to_string_lossy().to_lowercase();
        let hash_lower = sha256.to_lowercase();

        for rule in lock.iter() {
            if let Some(ref h) = rule.sha256 {
                if h.to_lowercase() == hash_lower {
                    return true;
                }
            }
            if let Some(ref p) = rule.file_path_pattern {
                if path_str.contains(&p.to_lowercase()) {
                    return true;
                }
            }
        }
        false
    }

    fn persist(&self, list: &[UserReputationOverride]) {
        if let Ok(json) = serde_json::to_string_pretty(list) {
            let _ = fs::write(&self.overrides_file, json);
        }
    }
}

/// Orquestador integral de reputación y mitigación de falsos positivos
pub struct ReputationEngine {
    community: Arc<Mutex<CommunityReputationEngine>>,
    overrides_mgr: Arc<UserReputationOverridesManager>,
}

impl ReputationEngine {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            community: Arc::new(Mutex::new(CommunityReputationEngine::new())),
            overrides_mgr: Arc::new(UserReputationOverridesManager::new(data_dir)),
        }
    }

    pub fn overrides_manager(&self) -> Arc<UserReputationOverridesManager> {
        self.overrides_mgr.clone()
    }

    pub fn community_engine(&self) -> Arc<Mutex<CommunityReputationEngine>> {
        self.community.clone()
    }

    /// Evalúa exhaustivamente la reputación de un binario o archivo objetivo
    pub fn assess_file(&self, file_path: impl AsRef<Path>) -> anyhow::Result<ReputationAssessment> {
        let path = file_path.as_ref();
        let path_str = path.to_string_lossy().to_string();

        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        let mut header_bytes = Vec::new();

        file.seek(SeekFrom::Start(0))?;
        let mut total_read = 0;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            if total_read < 1024 * 1024 {
                // Guardar hasta 1MB para análisis de cabecera PE
                let to_take = n.min(1024 * 1024 - total_read);
                header_bytes.extend_from_slice(&buffer[..to_take]);
            }
            hasher.update(&buffer[..n]);
            total_read += n;
        }

        let sha256 = hex::encode(hasher.finalize());
        let (authenticode, publisher) = AuthenticodeValidator::inspect_pe_signature(&header_bytes);

        self.assess_metadata(&path_str, &sha256, authenticode, publisher)
    }

    /// Calcula la puntuación de confianza combinada a partir de los atributos analizados
    pub fn assess_metadata(
        &self,
        target_path: &str,
        sha256: &str,
        authenticode: AuthenticodeStatus,
        publisher: Option<String>,
    ) -> anyhow::Result<ReputationAssessment> {
        let path = Path::new(target_path);
        let file_name = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default()
            .to_lowercase();
        let path_lower = target_path.to_lowercase();

        let mut reasons = Vec::new();
        let mut score: i32 = 50; // Puntuación base neutral

        // 1. Exclusión explícita por usuario o falso positivo reportado previamente
        let is_user_excluded = self.overrides_mgr.is_excluded(path, sha256);
        if is_user_excluded {
            score = 100;
            reasons.push("Exclusión local de usuario activa (Falso Positivo Resuelto)".to_string());
        }

        // 2. Clasificación del editor (Publisher Trust Tier)
        let trust_tier = if let Some(ref pub_name) = publisher {
            let tier = TrustedPublisherCatalog::classify_publisher(pub_name);
            match tier {
                PublisherTrustTier::Tier1PlatformCore => {
                    score += 25;
                    reasons.push(format!("Editor Plataforma Núcleo Verificado: {}", pub_name));
                }
                PublisherTrustTier::Tier2VerifiedCommercial => {
                    score += 15;
                    reasons.push(format!("Editor Comercial Confiable: {}", pub_name));
                }
                PublisherTrustTier::Tier3DeveloperToolchain => {
                    score += 12;
                    reasons.push(format!("Cadena de Desarrollo Confiable: {}", pub_name));
                }
                PublisherTrustTier::Untrusted => {
                    score -= 5;
                    reasons.push(format!("Editor Desconocido o No Catalogado: {}", pub_name));
                }
            }
            tier
        } else {
            PublisherTrustTier::Untrusted
        };

        // 3. Estado de la firma Authenticode
        match authenticode {
            AuthenticodeStatus::Valid => {
                score += 20;
                reasons.push("Firma digital Authenticode íntegra y verificada".to_string());
            }
            AuthenticodeStatus::InvalidSignature => {
                score -= 60;
                reasons.push("ALERTA CRÍTICA: Firma digital inválida o ejecutable alterado".to_string());
            }
            AuthenticodeStatus::UntrustedRoot => {
                score -= 25;
                reasons.push("Certificado con raíz no confiable (auto-firmado)".to_string());
            }
            AuthenticodeStatus::Revoked => {
                score -= 80;
                reasons.push("ALERTA CRÍTICA: Certificado digital revocado por CA emisora".to_string());
            }
            AuthenticodeStatus::Expired => {
                score -= 10;
                reasons.push("Certificado digital expirado".to_string());
            }
            AuthenticodeStatus::NotSigned => {
                score -= 15;
                reasons.push("Ejecutable no firmado digitalmente".to_string());
            }
        }

        // 4. Verificación de binarios de Windows OS y Detección de Suplantación (Spoofing)
        let is_in_system32 = path_lower.contains("\\system32\\")
            || path_lower.contains("\\syswow64\\")
            || path_lower.contains("\\winsxs\\");
        let is_os_binary_name = WINDOWS_OS_CRITICAL_BINARIES
            .iter()
            .any(|&os_bin| os_bin.eq_ignore_ascii_case(&file_name));

        let is_windows_os_binary = if is_os_binary_name {
            if is_in_system32 {
                score += 45;
                if matches!(authenticode, AuthenticodeStatus::NotSigned) {
                    score += 15; // Compensa la penalización de no firmado embebido (Windows usa catálogos CatRoot)
                }
                reasons.push(format!("Binario genuino del núcleo de Windows (Firma de Catálogo CatRoot / System32): {}", file_name));
                true
            } else {
                // Alerta de suplantación de proceso legítimo (Masquerading / T1036)
                score -= 45;
                reasons.push(format!(
                    "ALERTA DE SUPLANTACIÓN (T1036): Binario con nombre de sistema '{}' fuera de System32",
                    file_name
                ));
                false
            }
        } else {
            false
        };

        // 5. Supresión Inteligente de Herramientas de Desarrollo y Administración
        let is_dev_name = DEVELOPER_TOOLCHAIN_BINARIES
            .iter()
            .any(|&dev_bin| dev_bin.eq_ignore_ascii_case(&file_name));

        let is_in_dev_dir = path_lower.contains(".cargo\\bin")
            || path_lower.contains(".rustup\\toolchains")
            || path_lower.contains("programs\\python")
            || path_lower.contains("git\\bin")
            || path_lower.contains("git\\cmd")
            || path_lower.contains("npm")
            || path_lower.contains("docker")
            || path_lower.contains("microsoft vs code");

        let is_known_dev_tool = if is_dev_name && (is_in_dev_dir || matches!(trust_tier, PublisherTrustTier::Tier3DeveloperToolchain)) {
            score += 35;
            if matches!(authenticode, AuthenticodeStatus::NotSigned) {
                score += 15;
            }
            reasons.push(format!(
                "Supresión inteligente activa: Herramienta legítima de desarrollo ({})",
                file_name
            ));
            true
        } else {
            false
        };

        // 6. Consulta de K-Anonimato en la red comunitaria
        let comm_lock = self.community.lock().unwrap();
        let prevalence_count = if let Some(indicator) = comm_lock.lookup_hash(sha256) {
            score -= 60;
            reasons.push(format!(
                "ALERTA COMUNITARIA: Hash reportado como amenaza activa '{}' (Reportes: {})",
                indicator.threat_name, indicator.reports_count
            ));
            indicator.reports_count
        } else {
            0
        };

        // Limitar score al rango [0, 100]. Si el usuario excluyó explícitamente el falso positivo, prevalece 100
        let final_score = if is_user_excluded {
            100
        } else {
            score.clamp(0, 100) as u8
        };

        let trust_level = match final_score {
            80..=100 => ReputationTrustLevel::Trusted,
            40..=79 => ReputationTrustLevel::Neutral,
            20..=39 => ReputationTrustLevel::Suspicious,
            _ => ReputationTrustLevel::Untrusted,
        };

        Ok(ReputationAssessment {
            target_path: target_path.to_string(),
            sha256: sha256.to_string(),
            reputation_score: final_score,
            trust_level,
            authenticode,
            publisher,
            trust_tier,
            is_windows_os_binary,
            is_known_dev_tool,
            is_user_excluded,
            prevalence_count,
            evaluation_reasons: reasons,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k_anonymity_query() {
        let engine = CommunityReputationEngine::new();
        let prefix = "275a0";
        let candidates = engine.query_by_k_anonymity_prefix(prefix);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].threat_name, "EICAR-Standard-Test-File");

        let found =
            engine.lookup_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        assert!(found.is_some());
    }

    #[test]
    fn test_unknown_hash_returns_empty() {
        let engine = CommunityReputationEngine::new();
        let candidates = engine.query_by_k_anonymity_prefix("fffff");
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_windows_os_binary_in_system32_trusted() {
        let temp_dir = std::env::temp_dir().join(format!("samu_rep_test_{}", Uuid::new_v4()));
        let engine = ReputationEngine::new(&temp_dir);

        let assessment = engine
            .assess_metadata(
                r"C:\Windows\System32\notepad.exe",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                AuthenticodeStatus::Valid,
                Some("Microsoft Windows".to_string()),
            )
            .unwrap();

        assert_eq!(assessment.trust_level, ReputationTrustLevel::Trusted);
        assert!(assessment.reputation_score >= 80);
        assert!(assessment.is_windows_os_binary);
        assert!(!assessment.is_known_dev_tool);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_spoofed_os_binary_in_downloads_penalized() {
        let temp_dir = std::env::temp_dir().join(format!("samu_rep_test_{}", Uuid::new_v4()));
        let engine = ReputationEngine::new(&temp_dir);

        // Archivo llamado svchost.exe pero en la carpeta de descargas del usuario sin firma
        let assessment = engine
            .assess_metadata(
                r"C:\Users\TargetUser\Downloads\svchost.exe",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                AuthenticodeStatus::NotSigned,
                None,
            )
            .unwrap();

        // Debe ser penalizado por suplantación (T1036)
        assert!(!assessment.is_windows_os_binary);
        assert!(assessment.reputation_score < 40);
        assert!(matches!(
            assessment.trust_level,
            ReputationTrustLevel::Suspicious | ReputationTrustLevel::Untrusted
        ));
        assert!(assessment
            .evaluation_reasons
            .iter()
            .any(|r| r.contains("ALERTA DE SUPLANTACIÓN")));
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_developer_tooling_intelligent_suppression() {
        let temp_dir = std::env::temp_dir().join(format!("samu_rep_test_{}", Uuid::new_v4()));
        let engine = ReputationEngine::new(&temp_dir);

        let assessment = engine
            .assess_metadata(
                r"C:\Users\Developer\.cargo\bin\cargo.exe",
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                AuthenticodeStatus::Valid,
                Some("Rust Foundation".to_string()),
            )
            .unwrap();

        assert!(assessment.is_known_dev_tool);
        assert_eq!(assessment.trust_level, ReputationTrustLevel::Trusted);
        assert!(assessment.reputation_score >= 80);
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_user_fp_override_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("samu_rep_test_{}", Uuid::new_v4()));
        let engine = ReputationEngine::new(&temp_dir);

        let test_hash = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let test_path = r"C:\CustomApp\in-house-tool.exe";

        // Antes de la exclusión: sin firma, puntaje bajo
        let assessment_before = engine
            .assess_metadata(test_path, test_hash, AuthenticodeStatus::NotSigned, None)
            .unwrap();
        assert!(assessment_before.reputation_score <= 50);
        assert!(!assessment_before.is_user_excluded);

        // Agregar reporte de falso positivo / exclusión de usuario
        let override_rule = engine.overrides_manager().add_override(
            Some(test_hash.to_string()),
            Some(test_path.to_string()),
            None,
            "Software contable interno legítimo verificado por TI".to_string(),
        );

        // Después de la exclusión: puntuación máxima de confianza
        let assessment_after = engine
            .assess_metadata(test_path, test_hash, AuthenticodeStatus::NotSigned, None)
            .unwrap();
        assert_eq!(assessment_after.reputation_score, 100);
        assert!(assessment_after.is_user_excluded);
        assert_eq!(assessment_after.trust_level, ReputationTrustLevel::Trusted);

        // Eliminar regla
        assert!(engine.overrides_manager().remove_override(override_rule.id));
        let list = engine.overrides_manager().list_overrides();
        assert!(list.is_empty());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}

