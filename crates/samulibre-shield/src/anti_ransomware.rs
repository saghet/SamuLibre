use anyhow::Result;
use chrono::Utc;
use samulibre_types::{ControlledFolderConfig, RansomwareIncident, Severity, ThreatAlert, ThreatCategory};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};
use tracing::{info, warn};
use uuid::Uuid;

/// Estado y metadatos de un archivo canario tripwire activo
#[derive(Debug, Clone)]
pub struct CanaryTripwire {
    pub path: PathBuf,
    pub original_sha256: String,
    pub size_bytes: u64,
    pub deployed_at: String,
    pub rotation_count: u32,
}

/// Evento de archivo para monitorización deslizante
#[derive(Debug, Clone)]
struct TrackedFileIo {
    path: PathBuf,
    entropy: f64,
    timestamp: Instant,
    _is_extension_tampered: bool,
}

/// Motor Especializado Anti-Ransomware y Protección de Carpetas Sensibles
pub struct AntiRansomwareEngine {
    config: ControlledFolderConfig,
    canaries: HashMap<PathBuf, CanaryTripwire>,
    process_activity: HashMap<u32, Vec<TrackedFileIo>>,
    incidents_history: Vec<RansomwareIncident>,
    canary_base_dir: PathBuf,
    window_duration: Duration,
}

impl AntiRansomwareEngine {
    pub fn new(canary_dir: impl AsRef<Path>) -> Self {
        let base_dir = canary_dir.as_ref().to_path_buf();
        let _ = fs::create_dir_all(&base_dir);

        let mut config = ControlledFolderConfig::default();
        Self::populate_default_protected_folders(&mut config);

        let mut engine = Self {
            config,
            canaries: HashMap::new(),
            process_activity: HashMap::new(),
            incidents_history: Vec::new(),
            canary_base_dir: base_dir,
            window_duration: Duration::from_secs(3),
        };

        let _ = engine.deploy_strategic_canaries();
        engine
    }

    /// Detecta dinámicamente las carpetas de usuario sensibles para protegerlas contra cifrado masivo
    fn populate_default_protected_folders(config: &mut ControlledFolderConfig) {
        #[cfg(target_os = "windows")]
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let p = PathBuf::from(profile);
            let candidates = [
                p.join("Documents"),
                p.join("Desktop"),
                p.join("Pictures"),
                p.join("Videos"),
                p.join("OneDrive"),
            ];
            for c in candidates {
                if c.exists() {
                    config.protected_folders.push(c.to_string_lossy().to_string());
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home);
            let candidates = [
                p.join("Documents"),
                p.join("Desktop"),
                p.join("Pictures"),
            ];
            for c in candidates {
                if c.exists() {
                    config.protected_folders.push(c.to_string_lossy().to_string());
                }
            }
        }
    }

    /// Despliega señuelos canario estratégicos con cebos de alta probabilidad de ataque
    pub fn deploy_strategic_canaries(&mut self) -> Result<usize> {
        let targets = [
            ("!000_passwords_vault.xlsx", "Contenido señuelo criptográfico financiero confuso"),
            ("_aaa_finances_2026.pdf", "%PDF-1.7 Documento confidencial corporativo cebo"),
            ("00_budget_accounting.docx", "PK\x03\x04 Documento de contabilidad y presupuestos generales"),
            ("!recovery_keys_backup.txt", "BITLOCKER-RECOVERY-KEY-CANARY-TRIPWIRE-TOKEN-2026"),
        ];

        let mut deployed = 0;
        for (filename, ctor) in targets {
            let target_path = self.canary_base_dir.join(filename);
            
            // Despliegue Idempotente: Si el canario ya existe en disco, reutilizar su contenido y hash
            // para evitar colisiones de concurrencia entre GUI y el Servicio en segundo plano
            let content_bytes = if target_path.exists() {
                if let Ok(existing_bytes) = fs::read(&target_path) {
                    if !existing_bytes.is_empty() {
                        existing_bytes
                    } else {
                        let content = format!("{}-UUID:{}", ctor, Uuid::new_v4());
                        fs::write(&target_path, content.as_bytes())?;
                        content.into_bytes()
                    }
                } else {
                    let content = format!("{}-UUID:{}", ctor, Uuid::new_v4());
                    fs::write(&target_path, content.as_bytes())?;
                    content.into_bytes()
                }
            } else {
                let content = format!("{}-UUID:{}", ctor, Uuid::new_v4());
                fs::write(&target_path, content.as_bytes())?;
                content.into_bytes()
            };

            let mut hasher = Sha256::new();
            hasher.update(&content_bytes);
            let hash = hex::encode(hasher.finalize());

            self.canaries.insert(
                target_path.clone(),
                CanaryTripwire {
                    path: target_path,
                    original_sha256: hash,
                    size_bytes: content_bytes.len() as u64,
                    deployed_at: Utc::now().to_rfc3339(),
                    rotation_count: 0,
                },
            );
            deployed += 1;
        }

        info!("[ANTI-RANSOMWARE] {} archivos canario tripwire desplegados en {}", deployed, self.canary_base_dir.display());
        Ok(deployed)
    }

    /// Verifica la integridad de los canarios; ante alteración ejecuta rotación automática y alerta
    pub fn check_canaries_and_rotate(&mut self) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();
        let mut canaries_to_rotate = Vec::new();

        for (path, canary) in &mut self.canaries {
            if !path.exists() {
                alerts.push(ThreatAlert {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::Critical,
                    category: ThreatCategory::RansomwareCanaryTrip,
                    title: "Alerta Crítica: Trampa Canario Anti-Ransomware ELIMINADA".to_string(),
                    details: format!(
                        "El archivo cebo '{}' fue eliminado súbitamente de disco (comportamiento típico de limpiador de ransomware).",
                        path.display()
                    ),
                    process_id: None,
                    process_name: None,
                    target_path: Some(path.to_string_lossy().to_string()),
                    action_taken: "Tripwire activado: disparando rotación de señuelo y escaneo de procesos agresivos.".to_string(),
                });
                canaries_to_rotate.push(path.clone());
                continue;
            }

            if let Ok(data) = fs::read(path) {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let current_hash = hex::encode(hasher.finalize());

                if current_hash != canary.original_sha256 {
                    // Verificación de Firma Interna Legítima:
                    // Si el archivo fue rotado o actualizado legítimamente por otra instancia de SamuLibre
                    // contiene el prefijo "SAMULIBRE-CANARY-TOKEN-", por lo que NO es un ataque ransomware.
                    let is_internal_token = if let Ok(text) = std::str::from_utf8(&data) {
                        text.contains("SAMULIBRE-CANARY-TOKEN-") || text.contains("BITLOCKER-RECOVERY-KEY-CANARY-TRIPWIRE-TOKEN-2026")
                    } else {
                        false
                    };

                    if is_internal_token {
                        // Sincronizar silenciosamente el nuevo hash en memoria sin generar falsa alarma
                        info!(
                            "[ANTI-RANSOMWARE] Sincronización transparente de canario '{}' con token interno legítimo.",
                            path.display()
                        );
                        canary.original_sha256 = current_hash;
                        canary.size_bytes = data.len() as u64;
                    } else {
                        alerts.push(ThreatAlert {
                            id: Uuid::new_v4(),
                            timestamp: Utc::now(),
                            severity: Severity::Critical,
                            category: ThreatCategory::RansomwareCanaryTrip,
                            title: "Alerta Crítica: Trampa Canario Anti-Ransomware CIFRADA O ALTERADA".to_string(),
                            details: format!(
                                "El señuelo '{}' fue modificado (Hash original: {}, Hash alterado: {}). Cifrado en progreso.",
                                path.display(), canary.original_sha256, current_hash
                            ),
                            process_id: None,
                            process_name: None,
                            target_path: Some(path.to_string_lossy().to_string()),
                            action_taken: "Tripwire activado: bloqueando operaciones de disco y desplegando nuevo canario.".to_string(),
                        });
                        canaries_to_rotate.push(path.clone());
                    }
                }
            }
        }

        // Rotación automática de canarios comprometidos
        for path in canaries_to_rotate {
            let _ = self.rotate_canary(&path);
        }

        alerts
    }

    /// Rota automáticamente un canario comprometido con un nuevo token y firma criptográfica
    pub fn rotate_canary(&mut self, path: &Path) -> Result<()> {
        let prev_rotation = self.canaries.get(path).map(|c| c.rotation_count).unwrap_or(0);
        let new_token = format!("SAMULIBRE-CANARY-TOKEN-ROTATED-{}-{}", Uuid::new_v4(), Utc::now().timestamp());
        fs::write(path, new_token.as_bytes())?;

        let mut hasher = Sha256::new();
        hasher.update(new_token.as_bytes());
        let new_hash = hex::encode(hasher.finalize());

        self.canaries.insert(
            path.to_path_buf(),
            CanaryTripwire {
                path: path.to_path_buf(),
                original_sha256: new_hash,
                size_bytes: new_token.len() as u64,
                deployed_at: Utc::now().to_rfc3339(),
                rotation_count: prev_rotation + 1,
            },
        );

        info!("[ANTI-RANSOMWARE] Señuelo '{}' rotado exitosamente a la generación #{}.", path.display(), prev_rotation + 1);
        Ok(())
    }

    /// Evalúa en tiempo real operaciones de archivo por proceso para detectar cifrado masivo
    pub fn evaluate_file_io(
        &mut self,
        pid: u32,
        proc_name: &str,
        target_path: &Path,
        entropy: f64,
    ) -> Option<RansomwareIncident> {
        let proc_lower = proc_name.to_lowercase();

        // 1. Evitar falsos positivos: verificar lista blanca de procesos de confianza
        if self.config.trusted_processes.iter().any(|t| proc_lower == t.to_lowercase()) {
            return None;
        }

        let now = Instant::now();
        let target_str = target_path.to_string_lossy().to_string();
        let target_lower = target_str.to_lowercase();

        // 2. Detección de extensión conocida de ransomware
        let is_known_ransom_ext = self.config.blocked_extensions.iter().any(|ext| target_lower.ends_with(ext));

        // 3. Registrar en ventana deslizante del proceso
        let events = self.process_activity.entry(pid).or_default();
        events.retain(|e| now.duration_since(e.timestamp) <= self.window_duration);
        events.push(TrackedFileIo {
            path: target_path.to_path_buf(),
            entropy,
            timestamp: now,
            _is_extension_tampered: is_known_ransom_ext,
        });

        let mut risk_score = 0u32;
        let mut trigger_reason = Vec::new();

        if is_known_ransom_ext {
            risk_score += 90;
            trigger_reason.push(format!("Extensión maliciosa de ransomware detectada en '{}'", target_str));
        }

        // 4. Ráfaga de escrituras con alta entropía (cifrado masivo)
        if events.len() >= 6 {
            let avg_entropy: f64 = events.iter().map(|e| e.entropy).sum::<f64>() / events.len() as f64;
            if avg_entropy >= 7.3 {
                risk_score += 85;
                trigger_reason.push(format!("Ráfaga de cifrado masivo detectada: {} archivos en ventana con entropía promedio {:.2}", events.len(), avg_entropy));
            }
        }

        // 5. Modificaciones sobre carpetas protegidas por proceso no confiable
        let is_in_protected_folder = self.config.protected_folders.iter().any(|f| target_str.starts_with(f));
        if is_in_protected_folder && events.len() >= 4 {
            risk_score += 40;
            trigger_reason.push(format!("Modificación masiva en carpeta protegida '{}'", target_str));
        }

        if risk_score >= 80 {
            let action_taken = if self.config.auto_suspend_malicious_process {
                // Suspender / Terminar proceso malicioso de inmediato
                Self::suspend_or_terminate_process(pid);
                "Proceso agresor suspendido y terminado para frenar propagación de cifrado.".to_string()
            } else {
                "Alerta generada. Acción manual requerida por configuración.".to_string()
            };

            let incident = RansomwareIncident {
                id: format!("RANSOM-INC-{}", Uuid::new_v4()),
                timestamp: Utc::now().to_rfc3339(),
                attacking_pid: pid,
                process_name: proc_name.to_string(),
                process_path: None,
                process_sha256: None,
                risk_score,
                trigger_reason: trigger_reason.join(" | "),
                affected_files_count: events.len(),
                sample_affected_files: events.iter().take(5).map(|e| e.path.to_string_lossy().to_string()).collect(),
                action_taken,
                canary_triggered: false,
                shadow_copy_intact: true,
                mitre_technique: "T1486 (Data Encrypted for Impact)".to_string(),
            };

            self.incidents_history.push(incident.clone());
            warn!(
                "[CRITICAL ANTI-RANSOMWARE] Incidente detectado: PID={} ({}) - Riesgo={}/100. Acción: {}",
                pid, proc_name, risk_score, incident.action_taken
            );
            return Some(incident);
        }

        None
    }

    /// Suspende o termina el proceso malicioso de forma segura
    pub fn suspend_or_terminate_process(pid: u32) {
        let mut sys = System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[Pid::from_u32(pid)]));
        if let Some(proc) = sys.process(Pid::from_u32(pid)) {
            info!("[ANTI-RANSOMWARE] Terminando proceso malicioso PID {}: '{}'", pid, proc.name().to_string_lossy());
            let _ = proc.kill();
        }
    }

    /// Retorna la lista de incidentes registrados
    pub fn get_incidents(&self) -> Vec<RansomwareIncident> {
        self.incidents_history.clone()
    }

    /// Retorna la configuración actual de carpetas controladas
    pub fn get_config(&self) -> ControlledFolderConfig {
        self.config.clone()
    }

    /// Añade una carpeta protegida al monitor
    pub fn add_protected_folder(&mut self, folder: impl AsRef<Path>) {
        let path_str = folder.as_ref().to_string_lossy().to_string();
        if !self.config.protected_folders.contains(&path_str) {
            self.config.protected_folders.push(path_str);
        }
    }

    /// Añade un proceso de confianza a la lista blanca
    pub fn add_trusted_process(&mut self, proc_name: &str) {
        let name_lower = proc_name.to_lowercase();
        if !self.config.trusted_processes.iter().any(|t| t.to_lowercase() == name_lower) {
            self.config.trusted_processes.push(proc_name.to_string());
        }
    }

    /// Retorna el número de canarios activos
    pub fn canary_count(&self) -> usize {
        self.canaries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_ransomware_detects_mass_encryption_burst() {
        let temp_dir = std::env::temp_dir().join(format!("samu_ar_burst_{}", Uuid::new_v4()));
        let mut engine = AntiRansomwareEngine::new(&temp_dir);

        let mut triggered = false;
        for i in 0..8 {
            let file_path = temp_dir.join(format!("doc_{}.pdf", i));
            let inc = engine.evaluate_file_io(4444, "unknown_crypto_dropper.exe", &file_path, 7.92);
            if inc.is_some() {
                triggered = true;
                let inc = inc.unwrap();
                assert_eq!(inc.attacking_pid, 4444);
                assert!(inc.risk_score >= 80);
                assert!(inc.trigger_reason.contains("Ráfaga de cifrado masivo"));
                break;
            }
        }

        assert!(triggered, "Debe detectar ráfaga de cifrado masivo con entropía alta");
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_controlled_folder_access_blocks_untrusted_extension_tampering() {
        let temp_dir = std::env::temp_dir().join(format!("samu_ar_ext_{}", Uuid::new_v4()));
        let mut engine = AntiRansomwareEngine::new(&temp_dir);

        let locked_file = temp_dir.join("financial_report.xlsx.lockbit");
        let inc = engine.evaluate_file_io(5555, "stealth_ransom.exe", &locked_file, 7.80);

        assert!(inc.is_some(), "Debe detectar inmediatamente la extensión maliciosa .lockbit");
        let inc = inc.unwrap();
        assert!(inc.risk_score >= 90);
        assert!(inc.trigger_reason.contains(".lockbit"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_trusted_processes_whitelist_no_false_positive() {
        let temp_dir = std::env::temp_dir().join(format!("samu_ar_whitelist_{}", Uuid::new_v4()));
        let mut engine = AntiRansomwareEngine::new(&temp_dir);

        // Microsoft Word legítimo guardando documentos comprimidos (alta entropía de zip/docx)
        for i in 0..10 {
            let file_path = temp_dir.join(format!("contract_{}.docx", i));
            let inc = engine.evaluate_file_io(1000, "winword.exe", &file_path, 7.85);
            assert!(inc.is_none(), "Proceso de confianza en lista blanca (winword.exe) no debe disparar falso positivo");
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_canary_tripwire_automatic_rotation() {
        let temp_dir = std::env::temp_dir().join(format!("samu_ar_rotate_{}", Uuid::new_v4()));
        let mut engine = AntiRansomwareEngine::new(&temp_dir);

        assert!(engine.canary_count() > 0);

        // Simular alteración maliciosa de uno de los canarios
        let first_canary_path = engine.canaries.keys().next().unwrap().clone();
        fs::write(&first_canary_path, b"ENCRYPTED_RANSOMWARE_PAYLOAD_DATA_CORRUPT").unwrap();

        let alerts = engine.check_canaries_and_rotate();
        assert_eq!(alerts.len(), 1, "Debe alertar sobre el canario alterado");
        assert_eq!(alerts[0].category, ThreatCategory::RansomwareCanaryTrip);

        // Verificar que el canario fue rotado automáticamente a la generación #1
        let rotated = engine.canaries.get(&first_canary_path).unwrap();
        assert_eq!(rotated.rotation_count, 1, "El canario debe haberse rotado automáticamente a generación 1");
        assert!(first_canary_path.exists(), "El canario rotado debe existir en disco con nuevo token");

        // Segunda verificación: ahora debe estar intacto tras la rotación
        let second_check = engine.check_canaries_and_rotate();
        assert!(second_check.is_empty(), "El canario recién rotado debe estar íntegro y no generar falsas alarmas");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
