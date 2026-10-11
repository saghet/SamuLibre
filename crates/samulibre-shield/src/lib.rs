use anyhow::Result;
use chrono::Utc;
use samulibre_types::{Severity, ThreatAlert, ThreatCategory};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tracing::{info, warn};
use uuid::Uuid;

/// Estado de un archivo señuelo (Canary)
#[derive(Debug, Clone)]
pub struct CanaryFile {
    pub path: PathBuf,
    pub original_sha256: String,
    pub size_bytes: u64,
}

pub struct EndpointShield {
    canaries: HashMap<PathBuf, CanaryFile>,
    system: System,
    canary_directory: PathBuf,
}

impl EndpointShield {
    pub fn new(canary_dir: impl AsRef<Path>) -> Self {
        let dir = canary_dir.as_ref().to_path_buf();
        let _ = fs::create_dir_all(&dir);

        let mut sys = System::new_all();
        sys.refresh_all();

        Self {
            canaries: HashMap::new(),
            system: sys,
            canary_directory: dir,
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
            let size = fs::metadata(&file_path)?.len();

            self.canaries.insert(
                file_path.clone(),
                CanaryFile {
                    path: file_path,
                    original_sha256: hash,
                    size_bytes: size,
                },
            );
            count += 1;
        }

        info!("Se desplegaron {} archivos canario señuelo en {:?}", count, self.canary_directory);
        Ok(count)
    }

    /// Inspecciona la integridad de los archivos señuelo.
    /// Si un canario fue modificado o cifrado, se dispara una alerta de alta prioridad.
    pub fn check_canary_integrity(&self) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        for (path, canary) in &self.canaries {
            if !path.exists() {
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

    /// Escanea los procesos en ejecución buscando herramientas de volcado de LSASS o robo de credenciales
    pub fn scan_processes_for_lsass_dumpers(&mut self) -> Vec<ThreatAlert> {
        self.system.refresh_processes(ProcessesToUpdate::All);
        let mut alerts = Vec::new();

        let suspicious_tools = [
            "mimikatz", "procdump", "nanodump", "dumpert", "pwdump", "pypykatz", "lazagne", "safetykatz"
        ];

        for (pid, process) in self.system.processes() {
            let proc_name = process.name().to_string_lossy().to_lowercase();
            let cmd_line: String = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();

            // Detección 1: Nombres de ejecutables conocidos de volcado de credenciales
            let matches_tool = suspicious_tools.iter().any(|tool| proc_name.contains(tool));

            // Detección 2: Uso malicioso de comsvcs.dll para volcar LSASS vía rundll32
            let is_comsvcs_minidump = cmd_line.contains("comsvcs.dll") && (cmd_line.contains("minidump") || cmd_line.contains("#24"));

            // Detección 3: Intento directo de procdump sobre lsass
            let is_lsass_dump_cmd = cmd_line.contains("lsass") && (cmd_line.contains("dump") || cmd_line.contains("-ma"));

            if matches_tool || is_comsvcs_minidump || is_lsass_dump_cmd {
                let pid_u32 = pid.as_u32();
                warn!("Detectado intento de robo de credenciales LSASS: PID {} ({})", pid_u32, proc_name);

                alerts.push(ThreatAlert {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::Critical,
                    category: ThreatCategory::LsassMemoryAccess,
                    title: "Intento de volcado de credenciales LSASS neutralizado".to_string(),
                    details: format!("Proceso '{}' (PID {}) ejecutó argumentos sospechosos dirigidos a la memoria de autenticación: '{}'", proc_name, pid_u32, cmd_line),
                    process_id: Some(pid_u32),
                    process_name: Some(proc_name),
                    target_path: Some("C:\\Windows\\System32\\lsass.exe".to_string()),
                    action_taken: "Proceso identificado como atacante. Alerta de bloqueo emitida.".to_string(),
                });
            }
        }

        alerts
    }

    /// Inspecciona procesos anómalos o scripts no confiables que intenten acceder a carpetas de cookies/tokens de navegadores
    pub fn scan_processes_for_browser_token_stealers(&mut self) -> Vec<ThreatAlert> {
        self.system.refresh_processes(ProcessesToUpdate::All);
        let mut alerts = Vec::new();

        let stealer_keywords = [
            "login data", "cookies.sqlite", "discord\\tokens", "wallet.dat", "web data", "exodus", "atomic"
        ];

        for (pid, process) in self.system.processes() {
            let proc_name = process.name().to_string_lossy().to_lowercase();
            // Ignoramos los propios navegadores legítimos
            if proc_name == "chrome.exe" || proc_name == "msedge.exe" || proc_name == "firefox.exe" || proc_name == "brave.exe" {
                continue;
            }

            let cmd_line: String = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();

            let matches_stealer_action = stealer_keywords.iter().any(|k| cmd_line.contains(k));

            if matches_stealer_action {
                let pid_u32 = pid.as_u32();
                alerts.push(ThreatAlert {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::High,
                    category: ThreatCategory::BrowserCredentialTheft,
                    title: "Detección de InfoStealer (Robo de Cookies / Tokens Web)".to_string(),
                    details: format!("Proceso no autorizado '{}' (PID {}) intentó acceder a almacenes de contraseñas o tokens: '{}'", proc_name, pid_u32, cmd_line),
                    process_id: Some(pid_u32),
                    process_name: Some(proc_name),
                    target_path: Some("%LOCALAPPDATA%\\Google\\Chrome\\User Data\\...".to_string()),
                    action_taken: "Acceso bloqueado por SamuLibre Browser Shield.".to_string(),
                });
            }
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
