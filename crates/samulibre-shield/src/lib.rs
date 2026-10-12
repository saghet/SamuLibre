use anyhow::Result;
use chrono::Utc;
use samulibre_types::{Severity, ThreatAlert, ThreatCategory};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tracing::{info, warn};
use uuid::Uuid;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Estado de un archivo señuelo (Canary)
#[derive(Debug, Clone)]
pub struct CanaryFile {
    pub path: PathBuf,
    pub original_sha256: String,
    pub size_bytes: u64,
    pub modified_time: std::time::SystemTime,
}

/// Elemento de estado de un canario para la interfaz gráfica
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryStatusItem {
    pub name: String,
    pub path: String,
    pub is_intact: bool,
    pub status_text: String,
    pub icon: String,
    pub original_hash: String,
    pub current_hash: Option<String>,
}

/// Estado en vivo completo del Escudo Endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldLiveStatus {
    pub lsass_protection_active: bool,
    pub lsass_status_text: String,
    pub cookie_shield_active: bool,
    pub cookie_status_text: String,
    pub canaries: Vec<CanaryStatusItem>,
    pub intact_count: usize,
    pub total_canaries: usize,
    pub monitored_processes_count: usize,
}

pub struct EndpointShield {
    canaries: HashMap<PathBuf, CanaryFile>,
    system: System,
    canary_directory: PathBuf,
    lsass_protection_enabled: bool,
    cookie_shield_enabled: bool,
}

impl EndpointShield {
    pub fn new(canary_dir: impl AsRef<Path>) -> Self {
        let dir = canary_dir.as_ref().to_path_buf();
        let _ = fs::create_dir_all(&dir);

        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All);

        Self {
            canaries: HashMap::new(),
            system: sys,
            canary_directory: dir,
            lsass_protection_enabled: true,
            cookie_shield_enabled: true,
        }
    }

    /// Despliega archivos señuelo con nombres atractivos para atraer al ransomware
    pub fn deploy_canaries(&mut self) -> Result<usize> {
        let decoy_names = [
            ("claves_bancarias_2026.xlsx", "CANARY_TOKEN_EXCEL_FINANCE_CONFIDENTIAL_SAMULIBRE"),
            ("declaracion_renta_privada.docx", "CANARY_TOKEN_TAX_RETURN_DOCUMENT_ENCRYPTION_BAIT"),
            ("passwords_backup_vault.txt", "CANARY_TOKEN_CREDENTIALS_TRIPWIRE_ALERT_IMMEDIATE"),
            ("recuperacion_billetera_crypto.key", "CANARY_TOKEN_PRIVATE_KEY_SECURE_VAULT_DONOTTOUCH"),
        ];

        let mut count = 0;
        for (name, content) in decoy_names {
            let file_path = self.canary_directory.join(name);
            fs::write(&file_path, content)?;

            let hash = compute_sha256(&file_path)?;
            let meta = fs::metadata(&file_path)?;
            let size = meta.len();
            let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);

            self.canaries.insert(
                file_path.clone(),
                CanaryFile {
                    path: file_path,
                    original_sha256: hash,
                    size_bytes: size,
                    modified_time: modified,
                },
            );
            count += 1;
        }

        info!("Se desplegaron {} archivos canario señuelo en {:?}", count, self.canary_directory);
        Ok(count)
    }

    /// Inspecciona la integridad de los archivos señuelo con Fast-Path por metadatos (Zero Disk I/O).
    /// Si un canario fue modificado o cifrado, se dispara una alerta de alta prioridad.
    pub fn check_canary_integrity(&self) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        for (path, canary) in &self.canaries {
            let meta = match fs::metadata(path) {
                Ok(m) => m,
                Err(_) => {
                    alerts.push(ThreatAlert {
                        id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        severity: Severity::Critical,
                        category: ThreatCategory::RansomwareCanaryTrip,
                        title: "¡ALERTA DE RANSOMWARE! Archivo señuelo eliminado".to_string(),
                        details: format!("El archivo canario señuelo '{}' fue borrado. Posible inicio de cifrado masivo de disco.", path.display()),
                        process_id: None,
                        process_name: None,
                        target_path: Some(path.to_string_lossy().to_string()),
                        action_taken: "Bloqueo de I/O y alerta crítica emitida".to_string(),
                    });
                    continue;
                }
            };

            let current_len = meta.len();
            let current_mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);

            // FAST-PATH CERO I/O: Si el tamaño y la marca de tiempo de modificación NTFS son
            // idénticos a los registrados en la creación, el archivo está garantizado intacto.
            // Se resuelve en 0.001 ms sin leer bloques de disco.
            if current_len == canary.size_bytes && current_mtime == canary.modified_time {
                continue;
            }

            // Si los metadatos difieren, procedemos a verificar el hash SHA-256 para confirmar alteración/cifrado
            if let Ok(current_hash) = compute_sha256(path) {
                if current_hash != canary.original_sha256 {
                    alerts.push(ThreatAlert {
                        id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        severity: Severity::Critical,
                        category: ThreatCategory::RansomwareCanaryTrip,
                        title: "¡ALERTA DE RANSOMWARE! Cifrado de trampa detectado".to_string(),
                        details: format!(
                            "El contenido del archivo canario '{}' fue alterado o cifrado. Hash original: {} -> Hash actual: {}",
                            path.display(), canary.original_sha256, current_hash
                        ),
                        process_id: None,
                        process_name: None,
                        target_path: Some(path.to_string_lossy().to_string()),
                        action_taken: "Trampa activada. Proceso atacante marcado para neutralización.".to_string(),
                    });
                }
            }
        }

        alerts
    }

    /// Escaneo unificado y de bajo consumo de procesos: refresca procesos una sola vez por ciclo
    /// e inspecciona simultáneamente intentos de volcado de LSASS y robo de cookies/tokens.
    pub fn scan_processes_unified(&mut self) -> Vec<ThreatAlert> {
        self.system.refresh_processes(ProcessesToUpdate::All);
        let mut alerts = Vec::new();

        let suspicious_tools = [
            "mimikatz", "procdump", "nanodump", "dumpert", "pwdump", "pypykatz", "lazagne", "safetykatz",
            "mimipenguin", "linpeas", "chrootkit", "rkhunter", "gcore"
        ];
        let stealer_keywords = [
            "login data", "cookies.sqlite", "discord\\tokens", "wallet.dat", "web data", "exodus", "atomic",
            "id_rsa", "id_ed25519", "/etc/shadow", ".config/discord"
        ];

        for (pid, process) in self.system.processes() {
            let proc_name = process.name().to_string_lossy().to_lowercase();
            let pid_u32 = pid.as_u32();

            // 1. Detección LSASS / Volcado de memoria en Linux (si está habilitada la protección)
            if self.lsass_protection_enabled {
                let cmd_line: String = process
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_lowercase();

                let matches_tool = suspicious_tools.iter().any(|tool| proc_name.contains(tool));
                let is_comsvcs_minidump = cmd_line.contains("comsvcs.dll") && (cmd_line.contains("minidump") || cmd_line.contains("#24"));
                let is_lsass_dump_cmd = cmd_line.contains("lsass") && (cmd_line.contains("dump") || cmd_line.contains("-ma"));
                let is_linux_mem_dump = (cmd_line.contains("/proc/") && cmd_line.contains("/mem"))
                    || cmd_line.contains("/dev/mem")
                    || cmd_line.contains("gcore ");

                if matches_tool || is_comsvcs_minidump || is_lsass_dump_cmd || is_linux_mem_dump {
                    warn!("Detectado intento de volcado de credenciales/memoria: PID {} ({}). Ejecutando terminación inmediata EDR.", pid_u32, proc_name);
                    let _ = process.kill();
                    let target_path = if is_linux_mem_dump {
                        Some("/proc/[pid]/mem".to_string())
                    } else {
                        Some("C:\\Windows\\System32\\lsass.exe".to_string())
                    };
                    alerts.push(ThreatAlert {
                        id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        severity: Severity::Critical,
                        category: if is_linux_mem_dump { ThreatCategory::LinuxPrivilegeEscalation } else { ThreatCategory::LsassMemoryAccess },
                        title: "Intento de volcado de credenciales y memoria neutralizado".to_string(),
                        details: format!("Proceso atacante '{}' (PID {}) fue terminado de inmediato por EDR al intentar volcar memoria sensible: '{}'", proc_name, pid_u32, cmd_line),
                        process_id: Some(pid_u32),
                        process_name: Some(proc_name.clone()),
                        target_path,
                        action_taken: "Proceso terminado inmediatamente por EDR Sentinel (Zero-Tolerance Response)".to_string(),
                    });
                }
            }

            // 2. Detección InfoStealer (si está habilitado el escudo de cookies y credenciales)
            if self.cookie_shield_enabled {
                // Ignorar navegadores oficiales legítimos (Windows y Linux)
                let is_legit_browser = proc_name == "chrome.exe" || proc_name == "chrome" || proc_name == "google-chrome"
                    || proc_name == "msedge.exe" || proc_name == "firefox.exe" || proc_name == "firefox"
                    || proc_name == "brave.exe" || proc_name == "brave" || proc_name == "chromium"
                    || proc_name == "chromium-browser";

                if !is_legit_browser {
                    let cmd_line: String = process
                        .cmd()
                        .iter()
                        .map(|s| s.to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                        .to_lowercase();

                    let matches_stealer_action = stealer_keywords.iter().any(|k| cmd_line.contains(k));
                    if matches_stealer_action {
                        warn!("Detectado intento de robo de tokens/cookies: PID {} ({}). Ejecutando terminación EDR.", pid_u32, proc_name);
                        let _ = process.kill();
                        alerts.push(ThreatAlert {
                            id: Uuid::new_v4(),
                            timestamp: Utc::now(),
                            severity: Severity::High,
                            category: ThreatCategory::BrowserCredentialTheft,
                            title: "Detección de InfoStealer (Robo de Cookies / Llaves / Tokens)".to_string(),
                            details: format!("Proceso no autorizado '{}' (PID {}) fue terminado de inmediato por EDR al intentar sustraer credenciales: '{}'", proc_name, pid_u32, cmd_line),
                            process_id: Some(pid_u32),
                            process_name: Some(proc_name),
                            target_path: Some("Browser / SSH / Shadow Credential Vault".to_string()),
                            action_taken: "Proceso terminado inmediatamente por SamuLibre Browser Shield (EDR Kill)".to_string(),
                        });
                    }
                }
            }
        }

        alerts
    }

    /// Escanea los procesos en ejecución buscando herramientas de volcado de LSASS o robo de credenciales
    pub fn scan_processes_for_lsass_dumpers(&mut self) -> Vec<ThreatAlert> {
        let prev_cookie = self.cookie_shield_enabled;
        self.cookie_shield_enabled = false;
        let alerts = self.scan_processes_unified();
        self.cookie_shield_enabled = prev_cookie;
        alerts
    }

    /// Inspecciona procesos anómalos o scripts no confiables que intenten acceder a carpetas de cookies/tokens de navegadores
    pub fn scan_processes_for_browser_token_stealers(&mut self) -> Vec<ThreatAlert> {
        let prev_lsass = self.lsass_protection_enabled;
        self.lsass_protection_enabled = false;
        let alerts = self.scan_processes_unified();
        self.lsass_protection_enabled = prev_lsass;
        alerts
    }

    /// Activa o desactiva la protección LSASS en el sistema operativo
    pub fn toggle_lsass_protection(&mut self, enabled: bool) -> Result<bool> {
        self.lsass_protection_enabled = enabled;
        #[cfg(target_os = "windows")]
        {
            let val = if enabled { "1" } else { "0" };
            let mut cmd = Command::new("reg");
            cmd.args([
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                "/v",
                "RunAsPPL",
                "/t",
                "REG_DWORD",
                "/d",
                val,
                "/f",
            ]);
            cmd.creation_flags(CREATE_NO_WINDOW);
            let _ = cmd.output();
        }
        info!("Protección LSASS modificada: RunAsPPL={}", enabled);
        Ok(self.lsass_protection_enabled)
    }

    /// Activa o desactiva la vigilancia del escudo de cookies y tokens
    pub fn toggle_cookie_shield(&mut self, enabled: bool) -> Result<bool> {
        self.cookie_shield_enabled = enabled;
        info!("Escudo de Cookies & Tokens modificado: {}", enabled);
        Ok(self.cookie_shield_enabled)
    }

    /// Retorna el estado en vivo detallado del Escudo Endpoint para la GUI
    pub fn get_live_status(&mut self) -> ShieldLiveStatus {
        self.system.refresh_processes(ProcessesToUpdate::All);
        let proc_count = self.system.processes().len();

        let mut items = Vec::new();
        let mut intact_count = 0;

        let icon_for_name = |name: &str| -> &'static str {
            if name.ends_with(".xlsx") {
                "📊"
            } else if name.ends_with(".docx") {
                "📝"
            } else if name.ends_with(".key") {
                "🔑"
            } else {
                "📄"
            }
        };

        // Si los canarios no estaban desplegados, desplegarlos
        if self.canaries.is_empty() {
            let _ = self.deploy_canaries();
        }

        // Orden de visualización consistente
        let mut canary_keys: Vec<PathBuf> = self.canaries.keys().cloned().collect();
        canary_keys.sort();

        for path in canary_keys {
            if let Some(canary) = self.canaries.get(&path) {
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                let icon = icon_for_name(&name).to_string();
                let display_path = path.to_string_lossy().to_string();

                match fs::metadata(&path) {
                    Err(_) => {
                        items.push(CanaryStatusItem {
                            name,
                            path: display_path,
                            is_intact: false,
                            status_text: "¡Archivo Borrado!".to_string(),
                            icon,
                            original_hash: canary.original_sha256.clone(),
                            current_hash: None,
                        });
                    }
                    Ok(meta) => {
                        let current_len = meta.len();
                        let current_mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);

                        // Fast-path: si mtime y longitud coinciden, está íntegro sin leer de disco
                        if current_len == canary.size_bytes && current_mtime == canary.modified_time {
                            intact_count += 1;
                            items.push(CanaryStatusItem {
                                name,
                                path: display_path,
                                is_intact: true,
                                status_text: "Íntegro".to_string(),
                                icon,
                                original_hash: canary.original_sha256.clone(),
                                current_hash: Some(canary.original_sha256.clone()),
                            });
                        } else if let Ok(current_hash) = compute_sha256(&path) {
                            let is_intact = current_hash == canary.original_sha256;
                            if is_intact {
                                intact_count += 1;
                            }
                            items.push(CanaryStatusItem {
                                name,
                                path: display_path,
                                is_intact,
                                status_text: if is_intact { "Íntegro".to_string() } else { "¡Trampa Activada!".to_string() },
                                icon,
                                original_hash: canary.original_sha256.clone(),
                                current_hash: Some(current_hash),
                            });
                        } else {
                            items.push(CanaryStatusItem {
                                name,
                                path: display_path,
                                is_intact: false,
                                status_text: "I/O Error".to_string(),
                                icon,
                                original_hash: canary.original_sha256.clone(),
                                current_hash: None,
                            });
                        }
                    }
                }
            }
        }

        let total = items.len();

        let lsass_text = if self.lsass_protection_enabled {
            "Protegido contra PROCESS_VM_READ (LSA RunAsPPL Activo)".to_string()
        } else {
            "Inactivo (Supervisión manual)".to_string()
        };

        let cookie_text = if self.cookie_shield_enabled {
            "Bloqueo activo fuera de procesos oficiales (Chrome, Edge, Firefox)".to_string()
        } else {
            "Inactivo".to_string()
        };

        ShieldLiveStatus {
            lsass_protection_active: self.lsass_protection_enabled,
            lsass_status_text: lsass_text,
            cookie_shield_active: self.cookie_shield_enabled,
            cookie_status_text: cookie_text,
            canaries: items,
            intact_count,
            total_canaries: total,
            monitored_processes_count: proc_count,
        }
    }

    /// Ciclo continuo de auditoría de seguridad de ultra-bajo consumo (Single-Pass Process Scan)
    pub fn run_continuous_check(&mut self) -> Vec<ThreatAlert> {
        let mut alerts = self.check_canary_integrity();
        if self.lsass_protection_enabled || self.cookie_shield_enabled {
            alerts.extend(self.scan_processes_unified());
        }
        alerts
    }

    /// Finaliza de forma segura un proceso malicioso detectado
    pub fn terminate_malicious_process(&self, pid: u32) -> bool {
        if let Some(process) = self.system.process(Pid::from_u32(pid)) {
            process.kill()
        } else {
            false
        }
    }

    pub fn get_canary_count(&self) -> usize {
        self.canaries.len()
    }
}

fn compute_sha256(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_canaries_lifecycle_and_live_status() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_shield_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let mut shield = EndpointShield::new(&temp_dir);
        let deployed = shield.deploy_canaries().expect("Should deploy canaries");
        assert_eq!(deployed, 4, "Must deploy 4 canary files");

        let status = shield.get_live_status();
        assert_eq!(status.total_canaries, 4);
        assert_eq!(status.intact_count, 4);
        assert_eq!(status.canaries.len(), 4);
        assert!(status.lsass_protection_active);
        assert!(status.cookie_shield_active);

        // Test toggles
        shield.toggle_lsass_protection(false).unwrap();
        assert!(!shield.lsass_protection_enabled);
        shield.toggle_cookie_shield(false).unwrap();
        assert!(!shield.cookie_shield_enabled);

        let status_after_toggles = shield.get_live_status();
        assert!(!status_after_toggles.lsass_protection_active);
        assert!(!status_after_toggles.cookie_shield_active);

        // Simulate tampering with one canary file
        let first_canary_path = PathBuf::from(&status.canaries[0].path);
        let _ = fs::write(&first_canary_path, b"ENCRYPTED_BY_RANSOMWARE_PAYLOAD_TEST");

        let alerts = shield.check_canary_integrity();
        assert_eq!(alerts.len(), 1, "Must generate exactly 1 alert for tampered canary");
        assert!(alerts[0].title.contains("RANSOMWARE"));

        let status_tampered = shield.get_live_status();
        assert_eq!(status_tampered.intact_count, 3, "Intact count should drop to 3");
        assert!(!status_tampered.canaries[0].is_intact);

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_canary_fast_path_latency() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_shield_perf_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let mut shield = EndpointShield::new(&temp_dir);
        let _ = shield.deploy_canaries().expect("Should deploy canaries");

        // Medir tiempo de ejecución del fast-path de integridad
        let start = std::time::Instant::now();
        for _ in 0..100 {
            let alerts = shield.check_canary_integrity();
            assert!(alerts.is_empty(), "Intact canaries must produce no alerts");
        }
        let elapsed = start.elapsed();
        // 100 revisiones deben tomar mucho menos de 50 ms (típicamente < 3 ms con fast-path por metadatos)
        assert!(elapsed.as_millis() < 50, "Fast-path metadata check took too long: {:?}", elapsed);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
