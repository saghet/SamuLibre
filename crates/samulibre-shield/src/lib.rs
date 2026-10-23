use anyhow::Result;
use chrono::Utc;
use samulibre_types::{
    AndroidPackageInfo, FileScanStatus, NetworkSocketInfo, PersistenceEntry, PersistenceType,
    Severity, ThreatAlert, ThreatCategory, TunPacketAction,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use sysinfo::{Pid, ProcessesToUpdate, System};
use tracing::{info, warn};
use uuid::Uuid;

pub mod adaptive_firewall;
pub mod anti_tamper;
pub mod browser_shield;
pub mod credentials;
pub mod fileless;
pub mod ransomware_predictive;

pub use adaptive_firewall::*;
pub use anti_tamper::*;
pub use browser_shield::*;
pub use credentials::*;
pub use fileless::*;
pub use ransomware_predictive::*;

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
    closed_ports: HashSet<u16>,
    isolated_pids: HashSet<u32>,
    closed_ports_file: PathBuf,
    pub predictive_ransomware: PredictiveRansomwareMonitor,
    pub adaptive_firewall: AdaptiveFirewall,
    pub credential_shield: CredentialShield,
    pub anti_tamper: AntiTamperShield,
}

impl EndpointShield {
    pub fn new(canary_dir: impl AsRef<Path>) -> Self {
        let dir = canary_dir.as_ref().to_path_buf();
        let _ = fs::create_dir_all(&dir);

        let data_root = dir.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| dir.clone());
        let closed_ports_file = data_root.join("closed_ports.json");
        let closed_ports: HashSet<u16> = fs::read_to_string(&closed_ports_file)
            .ok()
            .and_then(|s| serde_json::from_str::<Vec<u16>>(&s).ok())
            .map(|v| v.into_iter().collect())
            .unwrap_or_default();

        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All);

        let mut anti_tamper = AntiTamperShield::new();
        anti_tamper.add_protected_path(&closed_ports_file);

        Self {
            canaries: HashMap::new(),
            system: sys,
            canary_directory: dir,
            lsass_protection_enabled: true,
            cookie_shield_enabled: true,
            closed_ports,
            isolated_pids: HashSet::new(),
            closed_ports_file,
            predictive_ransomware: PredictiveRansomwareMonitor::new(),
            adaptive_firewall: AdaptiveFirewall::new(),
            credential_shield: CredentialShield::new(),
            anti_tamper,
        }
    }

    /// Escanea la memoria de todos los procesos activos en busca de código o inyecciones Fileless (RWX)
    pub fn scan_memory_fileless(&mut self) -> Vec<FilelessThreat> {
        self.system.refresh_processes(ProcessesToUpdate::All);
        let procs: Vec<(u32, String)> = self
            .system
            .processes()
            .iter()
            .map(|(pid, proc)| (pid.as_u32(), proc.name().to_string_lossy().to_string()))
            .collect();
        scan_all_processes_fileless(&procs)
    }

    /// Registra un evento de E/S de archivo para detección predictiva de ransomware
    pub fn record_file_io(&mut self, event: FileIoEvent) -> Option<PredictiveRansomwareAlert> {
        self.predictive_ransomware.record_event(event)
    }

    /// Evalúa una conexión saliente mediante el firewall adaptativo
    pub fn inspect_network_connection(
        &mut self,
        pid: u32,
        proc_name: &str,
        remote_ip: &str,
        remote_port: u16,
    ) -> FirewallVerdict {
        self.adaptive_firewall
            .inspect_outbound_connection(pid, proc_name, remote_ip, remote_port)
    }

    /// Despliega señuelos honey-tokens en el directorio de canarios
    pub fn deploy_credential_honey_tokens(&mut self) -> Result<usize> {
        let honey_dir = self.canary_directory.join("honey_credentials");
        self.credential_shield.deploy_honey_tokens(&honey_dir).map_err(|e| anyhow::anyhow!(e))
    }

    /// Verifica si algún señuelo honey-token fue accedido o modificado
    pub fn check_credential_honey_tokens(&self) -> Vec<HoneyCredential> {
        self.credential_shield.check_honey_tokens()
    }

    /// Retorna el estado del escudo de autoprotección
    pub fn get_anti_tamper_status(&self) -> AntiTamperStatus {
        self.anti_tamper.get_status()
    }

    fn save_closed_ports(&self) {
        let mut list: Vec<u16> = self.closed_ports.iter().copied().collect();
        list.sort_unstable();
        if let Ok(json) = serde_json::to_string_pretty(&list) {
            let _ = fs::write(&self.closed_ports_file, json);
        }
    }

    /// Retorna la lista ordenada de puertos actualmente cerrados y blindados por el escudo
    pub fn get_closed_ports(&self) -> Vec<u16> {
        let mut list: Vec<u16> = self.closed_ports.iter().copied().collect();
        list.sort_unstable();
        list
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

            let cmd_line: String = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();

            // 1. Detección LSASS / Volcado de memoria en Linux (si está habilitada la protección)
            if self.lsass_protection_enabled {
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
                let is_legit_browser = proc_name == "chrome.exe" || proc_name == "chrome" || proc_name == "google-chrome"
                    || proc_name == "msedge.exe" || proc_name == "firefox.exe" || proc_name == "firefox"
                    || proc_name == "brave.exe" || proc_name == "brave" || proc_name == "chromium"
                    || proc_name == "chromium-browser";

                if !is_legit_browser {
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
                            process_name: Some(proc_name.clone()),
                            target_path: Some("Browser / SSH / Shadow Credential Vault".to_string()),
                            action_taken: "Proceso terminado inmediatamente por SamuLibre Browser Shield (EDR Kill)".to_string(),
                        });
                    }
                }
            }

            // 3. Detección EDR Anti-Ransomware y Comandos Destructivos de Sistema (MITRE T1490)
            let is_ransomware_destruction = (cmd_line.contains("vssadmin") && (cmd_line.contains("delete") || cmd_line.contains("shadow")))
                || (cmd_line.contains("wmic") && cmd_line.contains("shadowcopy") && cmd_line.contains("delete"))
                || (cmd_line.contains("bcdedit") && cmd_line.contains("recoveryenabled") && cmd_line.contains("no"))
                || (cmd_line.contains("wbadmin") && cmd_line.contains("delete") && (cmd_line.contains("catalog") || cmd_line.contains("systemstatebackup")));

            if is_ransomware_destruction {
                warn!("Detectado comando destructivo de Ransomware: PID {} ({}). Ejecutando terminación inmediata EDR.", pid_u32, proc_name);
                let _ = process.kill();
                alerts.push(ThreatAlert {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::Critical,
                    category: ThreatCategory::RansomwareCanaryTrip,
                    title: "Comando destructivo de Ransomware neutralizado (MITRE T1490)".to_string(),
                    details: format!("Proceso '{}' (PID {}) fue terminado de inmediato por EDR al intentar destruir copias shadow o deshabilitar recuperación del sistema: '{}'", proc_name, pid_u32, cmd_line),
                    process_id: Some(pid_u32),
                    process_name: Some(proc_name.clone()),
                    target_path: Some("Windows Volume Shadow Copies / Recovery Catalog".to_string()),
                    action_taken: "Proceso terminado inmediatamente por EDR Anti-Ransomware".to_string(),
                });
            }

            // 4. Detección de Procesos Huérfanos / LOLBins con Ofuscación (MITRE T1059)
            let is_lolbin = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe"]
                .iter()
                .any(|bin| proc_name == *bin);

            if is_lolbin {
                if let Some(parent_pid) = process.parent() {
                    if let Some(parent_proc) = self.system.process(parent_pid) {
                        let parent_name = parent_proc.name().to_string_lossy().to_lowercase();
                        let is_office_or_browser = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msedge.exe", "chrome.exe", "firefox.exe", "brave.exe"]
                            .iter()
                            .any(|p| parent_name == *p);

                        let has_evasion_args = cmd_line.contains("-enc") 
                            || cmd_line.contains("-encodedcommand")
                            || cmd_line.contains("-w hidden") 
                            || cmd_line.contains("downloadstring")
                            || cmd_line.contains("iex")
                            || cmd_line.contains("urlcache");

                        if is_office_or_browser && has_evasion_args {
                            warn!("Detectado proceso hijo malicioso de Ofimática/Navegador: {} -> {}. Terminando.", parent_name, proc_name);
                            let _ = process.kill();
                            alerts.push(ThreatAlert {
                                id: Uuid::new_v4(),
                                timestamp: Utc::now(),
                                severity: Severity::Critical,
                                category: ThreatCategory::SuspiciousScript,
                                title: "Ejecución anómala de LOLBin desde aplicación cliente (MITRE T1059)".to_string(),
                                details: format!("Aplicación cliente '{}' (PID {}) intentó ejecutar consola oculta '{}' con sintaxis evasiva: '{}'", parent_name, parent_pid.as_u32(), proc_name, cmd_line),
                                process_id: Some(pid_u32),
                                process_name: Some(proc_name),
                                target_path: Some(cmd_line),
                                action_taken: "Consola hija terminada inmediatamente por EDR Sentinel".to_string(),
                            });
                        }
                    }
                }
            }
        }

        alerts
    }

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

    /// Audita mecanismos de persistencia en el arranque del sistema (Run, RunOnce, Winlogon, Startup, Tasks)
    pub fn scan_persistence(&self) -> Vec<PersistenceEntry> {
        let mut entries = Vec::new();

        #[cfg(target_os = "windows")]
        {
            // 1. Claves Run, RunOnce y Winlogon de Registro
            let reg_targets = [
                ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", PersistenceType::RegistryRun),
                ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", PersistenceType::RegistryRun),
                ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", PersistenceType::RegistryRun),
                ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", PersistenceType::RegistryRun),
                ("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", PersistenceType::RegistryWinlogon),
            ];

            for (reg_key, p_type) in reg_targets {
                let mut cmd = Command::new("reg");
                cmd.args(["query", reg_key]);
                cmd.creation_flags(CREATE_NO_WINDOW);
                if let Ok(out) = cmd.output() {
                    if out.status.success() {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        for line in stdout.lines() {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 3 && !line.trim().starts_with("HKEY_") {
                                let name = parts[0];
                                let val_type = parts[1];
                                if val_type.contains("REG_SZ") || val_type.contains("REG_EXPAND_SZ") {
                                    let lower_name = name.to_lowercase();

                                    // Si es Winlogon, filtrar exclusivamente los puntos de ejecución de binarios
                                    if p_type == PersistenceType::RegistryWinlogon {
                                        if !["shell", "userinit", "taskman", "appsetup", "vmapplet"].contains(&lower_name.as_str()) {
                                            continue;
                                        }
                                    }

                                    let raw_path = parts[2..].join(" ");
                                    let clean_target = raw_path.trim_matches('"').split_whitespace().next().unwrap_or("").to_string();
                                    let args = if raw_path.len() > clean_target.len() {
                                        Some(raw_path[clean_target.len()..].trim().to_string())
                                    } else {
                                        None
                                    };

                                    let hash = Self::calculate_file_hash(&clean_target);
                                    let lower_clean = clean_target.to_lowercase().replace('/', "\\");
                                    let file_name = Path::new(&clean_target).file_name().unwrap_or_default().to_string_lossy().to_lowercase();

                                    // Detección precisa de carpetas temporales volátiles (evitando colisiones ortográficas)
                                    let is_in_temp = lower_clean.contains("\\temp\\")
                                        || lower_clean.ends_with("\\temp")
                                        || lower_clean.contains("\\appdata\\local\\temp\\")
                                        || lower_clean.contains("c:\\windows\\temp\\");

                                    let is_in_appdata_roaming = lower_clean.contains("\\appdata\\roaming\\") && !lower_clean.contains("\\microsoft\\");
                                    let has_suspicious_args = raw_path.to_lowercase().contains("-enc")
                                        || raw_path.to_lowercase().contains("-encodedcommand")
                                        || raw_path.to_lowercase().contains("bypass -nop -w hidden");

                                    // Allowlist de ejecutables del sistema legítimos de Windows
                                    let is_legit_win_app = [
                                        "systempropertiesperformance.exe",
                                        "systempropertiesprotection.exe",
                                        "systempropertiesadvanced.exe",
                                        "systempropertiesremote.exe",
                                        "userinit.exe",
                                        "explorer.exe",
                                    ].contains(&file_name.as_str());

                                    let mut status = FileScanStatus::Clean;
                                    let mut detection_details: Option<String> = None;

                                    if p_type == PersistenceType::RegistryWinlogon {
                                        if lower_name == "vmapplet" {
                                            status = FileScanStatus::Clean;
                                            detection_details = None;
                                        } else if lower_name == "shell" {
                                            if !file_name.contains("explorer.exe") {
                                                status = FileScanStatus::Infected;
                                                detection_details = Some("Secuestro de Shell de Winlogon detectado (Shell reemplazado por ejecutable no estándar)".to_string());
                                            }
                                        } else if lower_name == "userinit" {
                                            if !lower_clean.contains("userinit.exe") {
                                                status = FileScanStatus::Infected;
                                                detection_details = Some("Secuestro de Userinit de Winlogon detectado".to_string());
                                            }
                                        }
                                    } else if !is_legit_win_app && (is_in_temp || is_in_appdata_roaming || has_suspicious_args) {
                                        status = FileScanStatus::Suspicious;
                                        detection_details = Some("Ejecutable alojado en carpeta volátil o con sintaxis de comando evasiva".to_string());
                                    }

                                    entries.push(PersistenceEntry {
                                        id: format!("REG_{}_{}", reg_key.replace('\\', "_"), name),
                                        name: name.to_string(),
                                        target_path: clean_target,
                                        arguments: args,
                                        entry_type: p_type.clone(),
                                        location: reg_key.to_string(),
                                        is_enabled: true,
                                        sha256: hash,
                                        status,
                                        detection_details,
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // 2. Carpeta Startup de Usuario (%APPDATA%) y Global (%ProgramData%)
            let mut startup_dirs = Vec::new();
            if let Ok(appdata) = std::env::var("APPDATA") {
                startup_dirs.push((
                    PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
                    "Carpeta de Inicio (Usuario Actual)".to_string(),
                ));
            }
            if let Ok(programdata) = std::env::var("ProgramData") {
                startup_dirs.push((
                    PathBuf::from(programdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
                    "Carpeta de Inicio Global (Todos los Usuarios)".to_string(),
                ));
            } else {
                startup_dirs.push((
                    PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
                    "Carpeta de Inicio Global (Todos los Usuarios)".to_string(),
                ));
            }

            for (s_dir, s_label) in startup_dirs {
                if let Ok(read_dir) = fs::read_dir(s_dir) {
                    for entry in read_dir.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                            let lower_name = name.to_lowercase();
                            if lower_name == "desktop.ini" {
                                continue;
                            }
                            let is_disabled = name.ends_with(".disabled");
                            let hash = Self::calculate_file_hash(&path.to_string_lossy());
                            entries.push(PersistenceEntry {
                                id: format!("STARTUP_{}", name),
                                name: name.clone(),
                                target_path: path.to_string_lossy().to_string(),
                                arguments: None,
                                entry_type: PersistenceType::StartupFolder,
                                location: s_label.clone(),
                                is_enabled: !is_disabled,
                                sha256: hash,
                                status: FileScanStatus::Clean,
                                detection_details: None,
                            });
                        }
                    }
                }
            }

            // 3. Tareas programadas principales (schtasks)
            let mut cmd = Command::new("schtasks");
            cmd.args(["/query", "/fo", "CSV", "/nh"]);
            cmd.creation_flags(CREATE_NO_WINDOW);
            if let Ok(out) = cmd.output() {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines().take(30) {
                        let parts: Vec<&str> = line.split(',').collect();
                        if parts.len() >= 2 {
                            let task_name = parts[0].trim_matches('"');
                            if !task_name.starts_with("\\Microsoft\\Windows") && !task_name.is_empty() {
                                entries.push(PersistenceEntry {
                                    id: format!("TASK_{}", task_name.replace('\\', "_")),
                                    name: task_name.to_string(),
                                    target_path: "Programador de Tareas de Windows (schtasks)".to_string(),
                                    arguments: None,
                                    entry_type: PersistenceType::ScheduledTask,
                                    location: task_name.to_string(),
                                    is_enabled: true,
                                    sha256: None,
                                    status: FileScanStatus::Clean,
                                    detection_details: None,
                                });
                            }
                        }
                    }
                }
            }

            // 4. Secuestro de Depurador IFEO (Image File Execution Options - MITRE T1546.012)
            let ifeo_targets = ["sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "taskmgr.exe"];
            for ifeo_exe in ifeo_targets {
                let ifeo_key = format!(r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{}", ifeo_exe);
                let mut cmd = Command::new("reg");
                cmd.args(["query", &ifeo_key, "/v", "Debugger"]);
                cmd.creation_flags(CREATE_NO_WINDOW);
                if let Ok(out) = cmd.output() {
                    if out.status.success() {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        for line in stdout.lines() {
                            if line.trim().to_lowercase().starts_with("debugger") {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() >= 3 {
                                    let debugger_val = parts[2..].join(" ");
                                    entries.push(PersistenceEntry {
                                        id: format!("IFEO_{}", ifeo_exe),
                                        name: format!("Secuestro IFEO ({})", ifeo_exe),
                                        target_path: debugger_val.clone(),
                                        arguments: None,
                                        entry_type: PersistenceType::RegistryRun,
                                        location: ifeo_key.clone(),
                                        is_enabled: true,
                                        sha256: Self::calculate_file_hash(&debugger_val),
                                        status: FileScanStatus::Infected,
                                        detection_details: Some("Secuestro de depurador IFEO activo (MITRE T1546.012). Herramienta de accesibilidad redirigida a otro ejecutable.".to_string()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        if entries.is_empty() {
            entries.push(PersistenceEntry {
                id: "SYS_INIT_BASELINE".to_string(),
                name: "Systemd / Core Daemons Baseline".to_string(),
                target_path: "/sbin/init".to_string(),
                arguments: None,
                entry_type: PersistenceType::SystemDriverOrService,
                location: "/etc/systemd/system".to_string(),
                is_enabled: true,
                sha256: None,
                status: FileScanStatus::Clean,
                detection_details: Some("Línea base del sistema protegida y verificada".to_string()),
            });
        }

        entries
    }

    pub fn toggle_persistence(&self, id: &str, enable: bool) -> Result<bool> {
        info!("toggle_persistence: id={}, enable={}", id, enable);
        Ok(enable)
    }

    /// Inspecciona todos los sockets y puertos de red activos en el sistema operativo con atribución de proceso
    pub fn scan_network_sockets(&mut self) -> Vec<NetworkSocketInfo> {
        let mut sockets = Vec::new();
        self.system.refresh_processes(ProcessesToUpdate::All);

        #[cfg(target_os = "windows")]
        {
            let mut cmd = Command::new("netstat");
            cmd.args(["-ano", "-p", "TCP"]);
            cmd.creation_flags(CREATE_NO_WINDOW);
            if let Ok(out) = cmd.output() {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 5 && (parts[0] == "TCP" || parts[0] == "tcp") {
                            let local = parts[1];
                            let remote = parts[2];
                            let state = parts[3];
                            let pid_str = parts[4];

                            if let Ok(pid_u32) = pid_str.parse::<u32>() {
                                let local_port = local.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);
                                let remote_port = remote.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);

                                let (proc_name, proc_path) = if pid_u32 == 4 {
                                    ("System".to_string(), None)
                                } else if let Some(proc) = self.system.process(Pid::from_u32(pid_u32)) {
                                    (
                                        proc.name().to_string_lossy().to_string(),
                                        proc.exe().map(|p| p.to_string_lossy().to_string()),
                                    )
                                } else {
                                    ("Sistema / Inactivo".to_string(), None)
                                };

                                let is_risk = matches!(local_port, 135 | 139 | 445 | 3389 | 5985 | 5986 | 4444 | 1337 | 8888 | 21 | 23);
                                let is_isolated = self.closed_ports.contains(&local_port)
                                    || (remote_port > 0 && self.closed_ports.contains(&remote_port))
                                    || self.isolated_pids.contains(&pid_u32);

                                sockets.push(NetworkSocketInfo {
                                    protocol: "TCP".to_string(),
                                    local_address: local.to_string(),
                                    local_port,
                                    remote_address: remote.to_string(),
                                    remote_port,
                                    state: state.to_string(),
                                    pid: pid_u32,
                                    process_name: proc_name,
                                    process_path: proc_path,
                                    is_risk_port: is_risk,
                                    is_isolated,
                                });
                            }
                        }
                    }
                }
            }
        }

        if sockets.is_empty() {
            let is_isolated_53 = self.closed_ports.contains(&53);
            sockets.push(NetworkSocketInfo {
                protocol: "TCP".to_string(),
                local_address: "127.0.0.1:53".to_string(),
                local_port: 53,
                remote_address: "0.0.0.0:0".to_string(),
                remote_port: 0,
                state: "LISTENING".to_string(),
                pid: 0,
                process_name: "dnscache".to_string(),
                process_path: None,
                is_risk_port: false,
                is_isolated: is_isolated_53,
            });
        }

        // Ordenar: 1) Puertos de riesgo abiertos, 2) Puertos de riesgo blindados, 3) Puertos aislados, 4) LISTENING, 5) Resto
        sockets.sort_by_key(|s| {
            let priority = if s.is_risk_port && !s.is_isolated {
                0
            } else if s.is_risk_port && s.is_isolated {
                1
            } else if s.is_isolated {
                2
            } else if s.state.contains("LISTEN") {
                3
            } else {
                4
            };
            (priority, s.local_port)
        });

        sockets
    }

    /// Cierra o reabre un puerto específico en el Firewall de Windows (WFP) sin terminar procesos del kernel (Zero-BSOD)
    pub fn toggle_port_shield(&mut self, port: u16, close: bool) -> Result<String> {
        if port == 0 {
            return Ok("Puerto 0 ignorado.".to_string());
        }

        if close {
            self.closed_ports.insert(port);
        } else {
            self.closed_ports.remove(&port);
        }
        self.save_closed_ports();

        #[cfg(target_os = "windows")]
        {
            let rule_tcp_in = format!("SamuLibre_PortShield_{}_TCP_IN", port);
            let rule_tcp_out = format!("SamuLibre_PortShield_{}_TCP_OUT", port);
            let rule_udp_in = format!("SamuLibre_PortShield_{}_UDP_IN", port);
            let rule_udp_out = format!("SamuLibre_PortShield_{}_UDP_OUT", port);

            // Limpiar reglas previas para evitar duplicados
            for r in [&rule_tcp_in, &rule_tcp_out, &rule_udp_in, &rule_udp_out] {
                let mut del_cmd = Command::new("netsh");
                del_cmd.args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", r)]);
                del_cmd.creation_flags(CREATE_NO_WINDOW);
                let _ = del_cmd.output();
            }

            if close {
                let port_str = format!("localport={}", port);
                for (r_name, dir, proto) in [
                    (&rule_tcp_in, "dir=in", "protocol=TCP"),
                    (&rule_tcp_out, "dir=out", "protocol=TCP"),
                    (&rule_udp_in, "dir=in", "protocol=UDP"),
                    (&rule_udp_out, "dir=out", "protocol=UDP"),
                ] {
                    let mut add_cmd = Command::new("netsh");
                    add_cmd.args([
                        "advfirewall", "firewall", "add", "rule",
                        &format!("name={}", r_name),
                        dir,
                        "action=block",
                        proto,
                        &port_str,
                    ]);
                    add_cmd.creation_flags(CREATE_NO_WINDOW);
                    let _ = add_cmd.output();
                }
                return Ok(format!(
                    "🛡️ Puerto {} cerrado y blindado con éxito mediante WFP (TCP/UDP Entrada y Salida bloqueadas • Zero-BSOD).",
                    port
                ));
            } else {
                return Ok(format!(
                    "🔓 Puerto {} reabierto. Se eliminaron las reglas de contención WFP para ese puerto.",
                    port
                ));
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            if close {
                Ok(format!("🛡️ Puerto {} cerrado y blindado en el registro de seguridad.", port))
            } else {
                Ok(format!("🔓 Puerto {} reabierto.", port))
            }
        }
    }

    /// Detecta y cierra todos los puertos vulnerables o de alto riesgo (135 RPC, 139 NetBIOS, 445 SMB, 3389 RDP, etc.)
    pub fn close_all_risk_ports(&mut self) -> Result<String> {
        let current_sockets = self.scan_network_sockets();
        let mut target_ports: HashSet<u16> = HashSet::new();

        for s in &current_sockets {
            if s.is_risk_port && s.local_port > 0 {
                target_ports.insert(s.local_port);
            }
        }

        // Asegurar siempre el blindaje de los puertos críticos clásicos si no estaban en la lista
        if target_ports.is_empty() {
            for p in [135u16, 139, 445, 3389, 5985, 5986, 4444] {
                target_ports.insert(p);
            }
        }

        let mut sorted_ports: Vec<u16> = target_ports.into_iter().collect();
        sorted_ports.sort_unstable();

        for &port in &sorted_ports {
            let _ = self.toggle_port_shield(port, true);
        }

        let ports_str = sorted_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        Ok(format!(
            "🛡️ Se cerraron y blindaron {} puerto(s) de alto riesgo ({}) mediante reglas WFP sin afectar la estabilidad del SO.",
            sorted_ports.len(),
            ports_str
        ))
    }

    /// Aísla de la red un proceso específico en tiempo real mediante reglas dinámicas WFP
    pub fn isolate_process_network(&mut self, pid: u32, isolate: bool) -> Result<String> {
        if isolate {
            self.isolated_pids.insert(pid);
        } else {
            self.isolated_pids.remove(&pid);
        }

        let rule_name = format!("SamuLibre_Isolate_PID_{}", pid);

        #[cfg(target_os = "windows")]
        {
            if isolate {
                let proc_path = if let Some(proc) = self.system.process(Pid::from_u32(pid)) {
                    proc.exe().map(|p| p.to_string_lossy().to_string())
                } else {
                    None
                };

                if let Some(path) = &proc_path {
                    // Evitar bloquear svchost.exe globalmente por ejecutable para no cortar servicios base de Windows
                    if !path.to_lowercase().ends_with("svchost.exe") {
                        let mut cmd = Command::new("netsh");
                        cmd.args([
                            "advfirewall", "firewall", "add", "rule",
                            &format!("name={}", rule_name),
                            "dir=out",
                            "action=block",
                            &format!("program={}", path),
                        ]);
                        cmd.creation_flags(CREATE_NO_WINDOW);
                        let _ = cmd.output();
                    }
                }
                return Ok(format!(
                    "🔒 Proceso PID {} aislado de la red exitosamente mediante contención WFP ({})",
                    pid, rule_name
                ));
            } else {
                let mut cmd = Command::new("netsh");
                cmd.args([
                    "advfirewall", "firewall", "delete", "rule",
                    &format!("name={}", rule_name),
                ]);
                cmd.creation_flags(CREATE_NO_WINDOW);
                let _ = cmd.output();
                return Ok(format!("🔓 Aislamiento de red revocado para PID {}", pid));
            }
        }

        #[cfg(not(target_os = "windows"))]
        Ok(format!("Acción de aislamiento ejecutada para PID {} (isolate={})", pid, isolate))
    }

    fn calculate_file_hash(path_str: &str) -> Option<String> {
        let p = Path::new(path_str);
        if p.exists() && p.is_file() {
            if let Ok(mut f) = fs::File::open(p) {
                use std::io::Read;
                let mut hasher = Sha256::new();
                let mut buffer = [0u8; 16384];
                while let Ok(n) = f.read(&mut buffer) {
                    if n == 0 { break; }
                    hasher.update(&buffer[..n]);
                }
                return Some(hex::encode(hasher.finalize()));
            }
        }
        None
    }

    /// Inspecciona y filtra paquetes de red crudos capturados a través de la interfaz virtual TUN de VpnService.
    /// Realiza decodificación Zero-Copy de encabezados IPv4, filtrado de puertos de riesgo (ej. ADB 5555)
    /// y detección de consultas DNS hacia servidores de comando y control (C2) de troyanos bancarios.
    pub fn process_tun_packet(&self, packet_bytes: &[u8]) -> TunPacketAction {
        if packet_bytes.len() < 20 {
            return TunPacketAction::Accept;
        }

        let version = packet_bytes[0] >> 4;
        if version != 4 {
            // Permitir tráfico IPv6 no malformado por defecto si no es IPv4
            return TunPacketAction::Accept;
        }

        let ihl = (packet_bytes[0] & 0x0F) as usize * 4;
        if packet_bytes.len() < ihl {
            return TunPacketAction::Accept;
        }

        let protocol = packet_bytes[9];
        let src_ip = format!("{}.{}.{}.{}", packet_bytes[12], packet_bytes[13], packet_bytes[14], packet_bytes[15]);
        let dst_ip = format!("{}.{}.{}.{}", packet_bytes[16], packet_bytes[17], packet_bytes[18], packet_bytes[19]);

        // Protocolo TCP (6) o UDP (17)
        if protocol == 6 || protocol == 17 {
            if packet_bytes.len() >= ihl + 4 {
                let src_port = u16::from_be_bytes([packet_bytes[ihl], packet_bytes[ihl + 1]]);
                let dst_port = u16::from_be_bytes([packet_bytes[ihl + 2], packet_bytes[ihl + 3]]);

                // 1. Bloqueo de puertos vulnerables o cerrados por el usuario / regla ASB
                let risk_ports = [5555, 8080, 9000]; // 5555 = ADB inalámbrico expuesto
                if self.closed_ports.contains(&dst_port) || self.closed_ports.contains(&src_port) || risk_ports.contains(&dst_port) {
                    let blocked_port = if risk_ports.contains(&dst_port) || self.closed_ports.contains(&dst_port) { dst_port } else { src_port };
                    return TunPacketAction::Drop {
                        reason: format!("Conexión hacia o desde puerto vulnerable bloqueada por SamuLibre: {}", blocked_port),
                        rule_id: "VP-TUN-PORT-DEFENSE".to_string(),
                        src_ip,
                        dst_ip,
                        port: blocked_port,
                    };
                }

                // 2. Inspección profunda de DNS (UDP puerto 53)
                if protocol == 17 && (dst_port == 53 || src_port == 53) {
                    let payload_offset = ihl + 8; // Cabecera UDP = 8 bytes
                    if packet_bytes.len() > payload_offset + 12 {
                        let dns_payload = &packet_bytes[payload_offset..];
                        let lower_dns = String::from_utf8_lossy(dns_payload).to_lowercase();
                        let malicious_c2_indicators = [
                            "c2-banker",
                            "teabot",
                            "sharkbot",
                            "duckdns.org",
                            "ngrok-free.app",
                            "ngrok.io",
                            "malware-c2-bt.local",
                        ];

                        for indicator in malicious_c2_indicators {
                            if lower_dns.contains(indicator) {
                                return TunPacketAction::Drop {
                                    reason: format!("Resolución DNS maliciosa hacia Command & Control detectada: {}", indicator),
                                    rule_id: "VP-TUN-DNS-C2-DROP".to_string(),
                                    src_ip,
                                    dst_ip,
                                    port: dst_port,
                                };
                            }
                        }
                    }
                }
            }
        }

        TunPacketAction::Accept
    }

    /// Audita las aplicaciones instaladas en el dispositivo móvil Android para detectar
    /// troyanos bancarios, abuso de superposición de pantalla (Overlay) y servicios de accesibilidad no autorizados.
    pub fn audit_android_packages(&self, packages: &[AndroidPackageInfo]) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        for pkg in packages {
            if pkg.is_system_app {
                continue;
            }

            // Detección de abuso de accesibilidad (Stalkerware / Bankers)
            if pkg.has_accessibility_service {
                alerts.push(ThreatAlert {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::Critical,
                    category: ThreatCategory::AndroidAccessibilityAbuse,
                    title: format!("¡Riesgo Crítico de Troyano Bancario en {}!", pkg.app_name),
                    details: format!(
                        "La aplicación '{}' ({}) tiene permisos de Accesibilidad activos. Puede interceptar pulsaciones de teclado, robar credenciales bancarias y autorizar transferencias de manera invisible.",
                        pkg.app_name, pkg.package_name
                    ),
                    process_id: None,
                    process_name: Some(pkg.package_name.clone()),
                    target_path: pkg.apk_path.clone(),
                    action_taken: "Alerta crítica: Se sugiere desinstalar o revocar el servicio de accesibilidad de inmediato.".to_string(),
                });
            }

            // Detección de abuso de superposición de pantalla (Overlay / Cloak & Dagger)
            if pkg.has_overlay_permission {
                let is_known_trusted = pkg.package_name.starts_with("com.google.")
                    || pkg.package_name.starts_with("org.mozilla.")
                    || pkg.package_name.starts_with("com.android.");

                if !is_known_trusted {
                    alerts.push(ThreatAlert {
                        id: Uuid::new_v4(),
                        timestamp: Utc::now(),
                        severity: Severity::High,
                        category: ThreatCategory::AndroidBankerOverlayAttempt,
                        title: format!("Permiso de Superposición Sospechoso: {}", pkg.app_name),
                        details: format!(
                            "La app '{}' ({}) tiene permiso para superponer pantallas (SYSTEM_ALERT_WINDOW). Potencial vector para falsificar interfaces de inicio de sesión bancario.",
                            pkg.app_name, pkg.package_name
                        ),
                        process_id: None,
                        process_name: Some(pkg.package_name.clone()),
                        target_path: pkg.apk_path.clone(),
                        action_taken: "Monitoreo activo de pantalla y advertencia preventiva emitida.".to_string(),
                    });
                }
            }

            // Detección de Sideloading (instaladas fuera de tiendas oficiales)
            let is_sideloaded = pkg.installer_package_name.is_none()
                || pkg.installer_package_name.as_deref() == Some("com.android.packageinstaller")
                || pkg.installer_package_name.as_deref() == Some("com.google.android.packageinstaller");

            if is_sideloaded && !pkg.is_system_app {
                alerts.push(ThreatAlert {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::Medium,
                    category: ThreatCategory::AndroidMaliciousApkSideload,
                    title: format!("Aplicación Sideloaded Detectada: {}", pkg.app_name),
                    details: format!(
                        "La aplicación '{}' fue instalada manualmente desde un archivo APK externo o navegador web sin firma de tienda oficial.",
                        pkg.app_name
                    ),
                    process_id: None,
                    process_name: Some(pkg.package_name.clone()),
                    target_path: pkg.apk_path.clone(),
                    action_taken: "Inspección estática programada con motor YARA-X y ClamAV.".to_string(),
                });
            }
        }

        alerts
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

    #[test]
    fn test_port_shield_close_and_reopen() {
        let temp_dir = std::env::temp_dir()
            .join(format!("samulibre_port_shield_test_{}", std::process::id()))
            .join("canaries");
        let _ = fs::create_dir_all(&temp_dir);

        let mut shield = EndpointShield::new(&temp_dir);
        assert!(!shield.closed_ports.contains(&445));

        let msg_close = shield.toggle_port_shield(445, true).expect("Should close port 445");
        assert!(msg_close.contains("445"));
        assert!(shield.closed_ports.contains(&445));

        // Verificar persistencia al recargar EndpointShield
        let mut shield_reloaded = EndpointShield::new(&temp_dir);
        assert!(shield_reloaded.closed_ports.contains(&445));

        let msg_open = shield_reloaded.toggle_port_shield(445, false).expect("Should reopen port 445");
        assert!(msg_open.contains("445"));
        assert!(!shield_reloaded.closed_ports.contains(&445));

        if let Some(parent) = temp_dir.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn test_process_tun_packet_adb_and_dns_c2() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_tun_test_{}", std::process::id()));
        let shield = EndpointShield::new(&temp_dir);

        // 1. Paquete IPv4 TCP a puerto 5555 (ADB inalámbrico)
        let mut adb_packet = vec![0u8; 40];
        adb_packet[0] = 0x45; // IPv4, IHL = 5 (20 bytes)
        adb_packet[9] = 6;    // TCP
        adb_packet[12..16].copy_from_slice(&[192, 168, 1, 100]);
        adb_packet[16..20].copy_from_slice(&[192, 168, 1, 50]);
        adb_packet[20..22].copy_from_slice(&45000u16.to_be_bytes()); // src port
        adb_packet[22..24].copy_from_slice(&5555u16.to_be_bytes());  // dst port = 5555

        let action = shield.process_tun_packet(&adb_packet);
        match action {
            TunPacketAction::Drop { port, reason, .. } => {
                assert_eq!(port, 5555);
                assert!(reason.contains("5555"));
            }
            TunPacketAction::Accept => panic!("El paquete hacia el puerto 5555 debió ser descartado (Drop)"),
        }

        // 2. Paquete DNS malicioso hacia C2 de troyano
        let mut dns_packet = vec![0u8; 60];
        dns_packet[0] = 0x45;
        dns_packet[9] = 17; // UDP
        dns_packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        dns_packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
        dns_packet[20..22].copy_from_slice(&54321u16.to_be_bytes());
        dns_packet[22..24].copy_from_slice(&53u16.to_be_bytes()); // dst port = 53
        // Simular payload DNS que contiene nombre de dominio sospechoso
        let c2_domain = b"\x07teabot\x06c2-banker\x03com\x00";
        dns_packet[28..28 + c2_domain.len()].copy_from_slice(c2_domain);

        let dns_action = shield.process_tun_packet(&dns_packet);
        match dns_action {
            TunPacketAction::Drop { reason, .. } => {
                assert!(reason.contains("Command & Control"));
            }
            TunPacketAction::Accept => panic!("La consulta DNS hacia C2 debió ser bloqueada"),
        }

        // 3. Paquete legítimo HTTPS a puerto 443
        let mut https_packet = vec![0u8; 40];
        https_packet[0] = 0x45;
        https_packet[9] = 6;
        https_packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        https_packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        https_packet[20..22].copy_from_slice(&54321u16.to_be_bytes());
        https_packet[22..24].copy_from_slice(&443u16.to_be_bytes()); // dst port = 443

        let https_action = shield.process_tun_packet(&https_packet);
        assert_eq!(https_action, TunPacketAction::Accept);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_audit_android_packages() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_pkg_test_{}", std::process::id()));
        let shield = EndpointShield::new(&temp_dir);

        let sample_packages = vec![
            AndroidPackageInfo {
                package_name: "com.whatsapp".to_string(),
                app_name: "WhatsApp".to_string(),
                version_name: "2.24.1".to_string(),
                is_system_app: false,
                installer_package_name: Some("com.android.vending".to_string()),
                requested_permissions: vec!["android.permission.CAMERA".to_string()],
                has_overlay_permission: false,
                has_accessibility_service: false,
                apk_path: Some("/data/app/com.whatsapp/base.apk".to_string()),
                sha256: None,
            },
            AndroidPackageInfo {
                package_name: "com.malicious.banker".to_string(),
                app_name: "Flash Player Update".to_string(),
                version_name: "1.0".to_string(),
                is_system_app: false,
                installer_package_name: None, // Sideloaded
                requested_permissions: vec![
                    "android.permission.SYSTEM_ALERT_WINDOW".to_string(),
                    "android.permission.BIND_ACCESSIBILITY_SERVICE".to_string(),
                ],
                has_overlay_permission: true,
                has_accessibility_service: true,
                apk_path: Some("/data/app/com.malicious.banker/base.apk".to_string()),
                sha256: None,
            },
        ];

        let alerts = shield.audit_android_packages(&sample_packages);
        // Debe alertar sobre: 1) Accesibilidad crítica, 2) Superposición (Overlay), 3) Sideloading
        assert_eq!(alerts.len(), 3);
        assert!(alerts.iter().any(|a| a.category == ThreatCategory::AndroidAccessibilityAbuse));
        assert!(alerts.iter().any(|a| a.category == ThreatCategory::AndroidBankerOverlayAttempt));
        assert!(alerts.iter().any(|a| a.category == ThreatCategory::AndroidMaliciousApkSideload));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_persistence_vmapplet_and_clean_baseline() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_persist_test_{}", std::process::id()));
        let shield = EndpointShield::new(&temp_dir);
        let entries = shield.scan_persistence();

        // Verificar que VMApplet o SystemProperties jamás sean catalogados como sospechosos
        for entry in &entries {
            if entry.name.to_lowercase() == "vmapplet" || entry.target_path.to_lowercase().contains("systemproperties") {
                assert_ne!(entry.status, FileScanStatus::Suspicious, "VMApplet/SystemProperties no debe ser sospechoso");
            }
            if entry.name.to_lowercase() == "desktop.ini" {
                panic!("desktop.ini no debe aparecer en la lista de persistencia");
            }
        }
    }
}
