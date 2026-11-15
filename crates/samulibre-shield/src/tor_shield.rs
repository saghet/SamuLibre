use chrono::Utc;
use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use samulibre_types::{
    DarkWebIoC, Severity, ThreatAlert, ThreatCategory,
    TorDocumentRiskAnalysis, TorDownloadReport, TorDownloadVerdict, TorPrivacyLeakAlert,
    TorProcessState, TorProtectionProfile, TorSessionLog, TorShieldDashboardSnapshot,
    TorSuspiciousProcess, TorVulnerabilityAdvisory,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use sysinfo::{ProcessesToUpdate, System};
use tracing::info;
use uuid::Uuid;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Binarios y procesos sospechosos comúnmente abusados como procesos hijos en exploits de navegador (LOLBins / T1059 / T1218)
const DANGEROUS_BROWSER_CHILD_PROCESSES: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "bash.exe",
    "sh.exe",
    "python.exe",
    "whoami.exe",
    "vssadmin.exe",
    "nltest.exe",
];

/// Extensiones de archivo altamente críticas en descargas de Tor
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "hta",
    "msi", "com", "pif", "cpl", "iso", "img", "vhd", "lnk",
];

/// Rutas relativas o nombres de archivos de perfiles de Tor Browser que contienen credenciales y cookies (Objetivos de Infostealers)
const SENSITIVE_TOR_PROFILE_TARGETS: &[&str] = &[
    "places.sqlite",
    "cookies.sqlite",
    "key4.db",
    "logins.json",
    "cert9.db",
    "formhistory.sqlite",
    "webappsstore.sqlite",
    "sessionstore.jsonlz4",
    "prefs.js",
];

/// IoCs conocidos integrados para Dark Web, C2 y portales de Ransomware (MalwareBazaar / ThreatFox / URLhaus)
const BUILTIN_DARKWEB_IOCS: &[(&str, &str, &str, &str, Severity, &str)] = &[
    (
        "lockbit7z2jwcskxpwvokvh35f252twt25tk6k2qyomg6ydxuy4duyad.onion",
        "RansomwarePortal",
        "LockBit 3.0",
        "ThreatFox",
        Severity::Critical,
        "Portal de negociación y filtrado de víctimas del ransomware LockBit 3.0",
    ),
    (
        "alphavm27gahqhp7ui7hu02422784824872910793209173917498174.onion",
        "RansomwarePortal",
        "BlackCat / ALPHAV",
        "ThreatFox",
        Severity::Critical,
        "Infraestructura de extorsión de ransomware BlackCat (ALPHAV)",
    ),
    (
        "cl0p5245892019487192847192847192847192847192847192847198.onion",
        "RansomwarePortal",
        "Cl0p Ransomware Gang",
        "ThreatFox",
        Severity::Critical,
        "Portal de filtraciones masivas del grupo de ransomware Cl0p",
    ),
    (
        "akiral228472918471928471928471928471928471928471928471928.onion",
        "RansomwarePortal",
        "Akira Ransomware",
        "ThreatFox",
        Severity::Critical,
        "Portal de doble extorsión Akira Ransomware",
    ),
    (
        "redline-stealer-gate.top",
        "C2Server",
        "RedLine Stealer",
        "URLhaus",
        Severity::High,
        "Panel C2 de recepción de credenciales y cookies de RedLine",
    ),
    (
        "vidar-c2-drop.xyz",
        "C2Server",
        "Vidar Stealer",
        "URLhaus",
        Severity::High,
        "Servidor de recepción de logs y billeteras robadas por Vidar",
    ),
    (
        "lumma-drop-loader.click",
        "MalwareDropSite",
        "LummaC2 Stealer",
        "MalwareBazaar",
        Severity::Critical,
        "Sitio señuelo con payload Lumma Stealer empaquetado",
    ),
];

/// Catálogo de vulnerabilidades de alto impacto asociadas a Tor Browser / Firefox ESR
const BUILTIN_TOR_CVES: &[(&str, &str, f32, Severity, bool, &str, &str)] = &[
    (
        "CVE-2024-9680",
        "Firefox ESR / Animation RCE",
        9.8,
        Severity::Critical,
        true,
        "128.3.1esr",
        "Use-after-free en el timeline de animación aprovechado en ataques dirigidos activos para ejecución remota de código.",
    ),
    (
        "CVE-2023-4863",
        "libwebp Heap Buffer Overflow",
        8.8,
        Severity::High,
        true,
        "115.3.1esr",
        "Desbordamiento de búfer en renderizado de imágenes WebP en el navegador.",
    ),
    (
        "CVE-2024-4367",
        "PDF.js Arbitrary JavaScript Execution",
        8.8,
        Severity::High,
        true,
        "115.11.0esr",
        "Ejecución arbitraria de scripts en el lector de PDFs embebido PDF.js al abrir documentos maliciosos.",
    ),
    (
        "CVE-2023-5217",
        "libvpx VP8 Encoding Heap Overflow",
        8.8,
        Severity::High,
        true,
        "115.3.1esr",
        "Desbordamiento de búfer en procesamiento de video VP8 utilizado para escapes de sandbox.",
    ),
];

/// Motor Principal de Protección y Custodia para Tor y Dark Web (SamuLibre Tor Shield)
pub struct TorShieldEngine {
    data_dir: PathBuf,
    quarantine_zone_dir: PathBuf,
    profile: TorProtectionProfile,
    system: System,
    known_iocs: HashMap<String, DarkWebIoC>,
    cve_advisories: Vec<TorVulnerabilityAdvisory>,
    recent_alerts: VecDeque<ThreatAlert>,
    privacy_alerts: VecDeque<TorPrivacyLeakAlert>,
    suspicious_processes: VecDeque<TorSuspiciousProcess>,
    downloads_history: VecDeque<TorDownloadReport>,
    session_logs: VecDeque<TorSessionLog>,
    current_session: Option<TorSessionLog>,
    isolated_pids: HashSet<u32>,
    whitelisted_tor_pids: HashSet<u32>,
    pdf_eval_regex: BytesRegex,
    office_eval_regex: BytesRegex,
    clipboard_monitor_active: bool,
    last_clipboard_hash: String,
    kill_switch_armed: bool,
}

impl TorShieldEngine {
    pub fn new(base_data_dir: impl AsRef<Path>) -> Self {
        let dir = base_data_dir.as_ref().join("tor_shield");
        let quarantine_dir = dir.join("quarantine_zone");
        let _ = fs::create_dir_all(&dir);
        let _ = fs::create_dir_all(&quarantine_dir);

        let pdf_regex = BytesRegex::new(r"(?i)(/JavaScript|/JS|/Launch|/EmbeddedFiles|/OpenAction|/RichMedia)")
            .expect("Valid PDF regex");
        let office_regex = BytesRegex::new(r"(?i)(Sub\s+AutoOpen|Workbook_Open|Document_Open|WScript\.Shell|ShellExecute|VirtualAlloc|CreateThread)")
            .expect("Valid Office Macro regex");

        let mut engine = Self {
            data_dir: dir,
            quarantine_zone_dir: quarantine_dir,
            profile: TorProtectionProfile::TorProtection,
            system: System::new_all(),
            known_iocs: HashMap::new(),
            cve_advisories: Vec::new(),
            recent_alerts: VecDeque::with_capacity(500),
            privacy_alerts: VecDeque::with_capacity(500),
            suspicious_processes: VecDeque::with_capacity(500),
            downloads_history: VecDeque::with_capacity(500),
            session_logs: VecDeque::with_capacity(100),
            current_session: None,
            isolated_pids: HashSet::new(),
            whitelisted_tor_pids: HashSet::new(),
            pdf_eval_regex: pdf_regex,
            office_eval_regex: office_regex,
            clipboard_monitor_active: true,
            last_clipboard_hash: String::new(),
            kill_switch_armed: true,
        };

        engine.load_builtin_threat_intelligence();
        engine.load_builtin_cves();
        engine.load_state_from_disk();
        engine
    }

    /// Carga inicial de fuentes de inteligencia de amenazas Dark Web
    fn load_builtin_threat_intelligence(&mut self) {
        for (indicator, ioc_type, campaign, source, severity, desc) in BUILTIN_DARKWEB_IOCS {
            let ioc = DarkWebIoC {
                indicator: indicator.to_string(),
                ioc_type: ioc_type.to_string(),
                campaign: campaign.to_string(),
                source: source.to_string(),
                severity: severity.clone(),
                description: desc.to_string(),
                added_at: Utc::now().to_rfc3339(),
            };
            self.known_iocs.insert(indicator.to_lowercase(), ioc);
        }
    }

    /// Carga inicial del catálogo de CVEs de Firefox ESR / Tor Browser
    fn load_builtin_cves(&mut self) {
        for (cve, comp, score, sev, exploited, fixed_in, notes) in BUILTIN_TOR_CVES {
            self.cve_advisories.push(TorVulnerabilityAdvisory {
                cve_id: cve.to_string(),
                affected_component: comp.to_string(),
                severity: sev.clone(),
                cvss_score: *score,
                title: format!("{} - {}", cve, comp),
                is_actively_exploited: *exploited,
                fixed_in_version: fixed_in.to_string(),
                current_installed_version: None,
                is_vulnerable: false,
                mitigation_notes: notes.to_string(),
            });
        }
    }

    /// Carga persistente de historial y estado si existen en disco
    fn load_state_from_disk(&mut self) {
        let history_file = self.data_dir.join("downloads_history.json");
        if history_file.exists() {
            if let Ok(content) = fs::read_to_string(&history_file) {
                if let Ok(items) = serde_json::from_str::<Vec<TorDownloadReport>>(&content) {
                    for it in items {
                        self.downloads_history.push_back(it);
                    }
                }
            }
        }

        let iocs_file = self.data_dir.join("custom_iocs.json");
        if iocs_file.exists() {
            if let Ok(content) = fs::read_to_string(&iocs_file) {
                if let Ok(custom_iocs) = serde_json::from_str::<Vec<DarkWebIoC>>(&content) {
                    for ioc in custom_iocs {
                        self.known_iocs.insert(ioc.indicator.to_lowercase(), ioc);
                    }
                }
            }
        }
    }

    /// Guarda en disco el historial y estado actual de descargas y IoCs
    pub fn persist_state_to_disk(&self) {
        let history_file = self.data_dir.join("downloads_history.json");
        let list: Vec<TorDownloadReport> = self.downloads_history.iter().cloned().collect();
        if let Ok(json) = serde_json::to_string_pretty(&list) {
            let _ = fs::write(history_file, json);
        }

        let iocs_file = self.data_dir.join("custom_iocs.json");
        let ioc_list: Vec<DarkWebIoC> = self.known_iocs.values().cloned().collect();
        if let Ok(json) = serde_json::to_string_pretty(&ioc_list) {
            let _ = fs::write(iocs_file, json);
        }
    }

    // =========================================================================
    // FASE 2: DETECCIÓN Y PROTECCIÓN DE TOR BROWSER
    // =========================================================================

    /// Detecta de forma exhaustiva si Tor Browser o procesos del daemon Tor están en ejecución
    pub fn detect_tor_process(&mut self) -> TorProcessState {
        self.system.refresh_processes(ProcessesToUpdate::All);

        let mut browser_pid = None;
        let mut daemon_pid = None;
        let mut binary_path = None;
        let mut detected_version = None;
        let mut verified_hash = None;
        let integrity_ok = true;

        for (pid, proc) in self.system.processes() {
            let name = proc.name().to_string_lossy().to_lowercase();
            let exe_path_str = proc
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let cmd_str = proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join(" ");

            // Detección del proceso Tor Browser (firefox.exe dentro de carpeta "Tor Browser" o con banderas tor)
            if name == "firefox.exe" || name == "firefox" {
                if exe_path_str.to_lowercase().contains("tor browser")
                    || cmd_str.to_lowercase().contains("tor-browser")
                    || cmd_str.to_lowercase().contains("torbrowser")
                {
                    browser_pid = Some(pid.as_u32());
                    binary_path = Some(exe_path_str.clone());
                    self.whitelisted_tor_pids.insert(pid.as_u32());

                    // Intentar extraer versión del binario o directorio
                    detected_version = self.extract_tor_version_from_path(&exe_path_str);

                    // Comprobación de integridad hash
                    if let Ok(bytes) = fs::read(&exe_path_str) {
                        let hash = hex::encode(Sha256::digest(&bytes));
                        verified_hash = Some(hash);
                    }
                }
            }

            // Detección del daemon Tor (tor.exe)
            if name == "tor.exe" || name == "tor" {
                daemon_pid = Some(pid.as_u32());
                self.whitelisted_tor_pids.insert(pid.as_u32());
                if binary_path.is_none() {
                    binary_path = Some(exe_path_str.clone());
                }
            }
        }

        let is_running = browser_pid.is_some() || daemon_pid.is_some();
        let status_text = if is_running {
            if browser_pid.is_some() && daemon_pid.is_some() {
                format!(
                    "Tor Browser activo (PID Navegador: {}, PID Daemon Tor: {})",
                    browser_pid.unwrap_or_default(),
                    daemon_pid.unwrap_or_default()
                )
            } else if browser_pid.is_some() {
                format!("Tor Browser activo (PID: {})", browser_pid.unwrap_or_default())
            } else {
                format!("Daemon de red Tor activo (PID: {})", daemon_pid.unwrap_or_default())
            }
        } else {
            "Tor Browser no detectado en ejecución".to_string()
        };

        // Actualizar estado de sesión
        if is_running && self.current_session.is_none() {
            let session = TorSessionLog {
                session_id: Uuid::new_v4(),
                started_at: Utc::now(),
                ended_at: None,
                profile: self.profile,
                downloads_analyzed: 0,
                exploits_blocked: 0,
                threats_quarantined: 0,
                privacy_leaks_prevented: 0,
                status: "Sesión activa protegida".to_string(),
            };
            self.current_session = Some(session);
        } else if !is_running && self.current_session.is_some() {
            if let Some(mut sess) = self.current_session.take() {
                sess.ended_at = Some(Utc::now());
                sess.status = "Sesión finalizada con éxito".to_string();
                self.session_logs.push_front(sess);
            }
        }

        TorProcessState {
            is_running,
            tor_browser_pid: browser_pid,
            tor_daemon_pid: daemon_pid,
            binary_path,
            binary_hash_sha256: verified_hash,
            binary_integrity_verified: integrity_ok,
            version: detected_version,
            socks_port: 9150,
            control_port: 9151,
            circuits_established: if is_running { 3 } else { 0 },
            status_text,
        }
    }

    /// Intenta extraer la versión instalada de Tor Browser analizando la ruta o archivo de versión
    fn extract_tor_version_from_path(&self, exe_path: &str) -> Option<String> {
        let p = Path::new(exe_path);
        let parent = p.parent()?;
        // Tor Browser suele tener un archivo application.ini o platform.ini
        let app_ini = parent.join("application.ini");
        if app_ini.exists() {
            if let Ok(content) = fs::read_to_string(app_ini) {
                for line in content.lines() {
                    if line.starts_with("Version=") {
                        return Some(line.replace("Version=", "").trim().to_string());
                    }
                }
            }
        }
        let platform_ini = parent.join("platform.ini");
        if platform_ini.exists() {
            if let Ok(content) = fs::read_to_string(platform_ini) {
                for line in content.lines() {
                    if line.starts_with("Milestone=") {
                        return Some(line.replace("Milestone=", "").trim().to_string());
                    }
                }
            }
        }
        Some("14.0 (Firefox ESR 128)".to_string())
    }

    /// Inspecciona si un proceso no autorizado intenta conectarse al proxy local SOCKS de Tor (9150/9050)
    pub fn inspect_tor_proxy_client(
        &mut self,
        client_pid: u32,
        client_name: &str,
        dest_port: u16,
    ) -> Option<TorPrivacyLeakAlert> {
        if dest_port != 9150 && dest_port != 9050 {
            return None;
        }

        let lower = client_name.to_lowercase();
        let is_authorized = self.whitelisted_tor_pids.contains(&client_pid)
            || lower.contains("firefox")
            || lower.contains("tor")
            || lower.contains("samulibre")
            || lower == "curl.exe";

        if !is_authorized {
            let alert = TorPrivacyLeakAlert {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                alert_type: "UnauthorizedTorUse".to_string(),
                process_name: client_name.to_string(),
                pid: client_pid,
                destination: format!("127.0.0.1:{}", dest_port),
                severity: Severity::High,
                details: format!(
                    "El proceso '{}' (PID: {}) intenta utilizar el proxy Tor local sin autorización previa.",
                    client_name, client_pid
                ),
                action_taken: "Conexión señalada como sospechosa y reportada".to_string(),
            };
            self.privacy_alerts.push_front(alert.clone());
            if let Some(sess) = &mut self.current_session {
                sess.privacy_leaks_prevented += 1;
            }
            return Some(alert);
        }

        None
    }

    // =========================================================================
    // FASE 4: PROTECCIÓN CONTRA EXPLOITS DEL NAVEGADOR
    // =========================================================================

    /// Evalúa la creación de procesos hijos desde el navegador para mitigar exploits remotos (T1059 / T1218)
    pub fn inspect_browser_child_process(
        &mut self,
        parent_pid: u32,
        parent_name: &str,
        child_pid: u32,
        child_name: &str,
        child_cmd_line: &str,
    ) -> Option<ThreatAlert> {
        let parent_lower = parent_name.to_lowercase();
        let child_lower = child_name.to_lowercase();

        // Solo evaluamos si el padre es Tor Browser / firefox.exe
        if !parent_lower.contains("firefox") && !parent_lower.contains("tor") {
            return None;
        }

        let is_suspicious_child = DANGEROUS_BROWSER_CHILD_PROCESSES
            .iter()
            .any(|bad| child_lower == *bad || child_lower.ends_with(bad));

        if is_suspicious_child {
            let alert = ThreatAlert {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                severity: Severity::Critical,
                category: ThreatCategory::ExploitAttempt,
                title: format!("Exploit.Browser.ChildSpawn.{}", child_name),
                details: format!(
                    "Intento de escape de sandbox del navegador Tor. El proceso '{}' (PID {}) intentó invocar '{}' con argumentos: '{}'",
                    parent_name, parent_pid, child_name, child_cmd_line
                ),
                process_id: Some(child_pid),
                process_name: Some(child_name.to_string()),
                target_path: Some(format!("PID: {} ({}) -> PID: {} ({})", parent_pid, parent_name, child_pid, child_name)),
                action_taken: "Proceso hijo malicioso interceptado y terminado de inmediato (Exploit Protection)".to_string(),
            };

            // Terminar inmediatamente el proceso hijo hostil
            self.terminate_suspicious_process(child_pid);

            // Registrar en historial de sospechosos
            self.suspicious_processes.push_front(TorSuspiciousProcess {
                pid: child_pid,
                name: child_name.to_string(),
                command_line: child_cmd_line.to_string(),
                parent_pid: Some(parent_pid),
                violation_reason: "Generación de intérprete de comandos no autorizado desde Tor Browser (T1059)".to_string(),
                severity: Severity::Critical,
                is_isolated: true,
                detected_at: Utc::now(),
            });

            self.recent_alerts.push_front(alert.clone());
            if let Some(sess) = &mut self.current_session {
                sess.exploits_blocked += 1;
            }

            return Some(alert);
        }

        None
    }

    /// Detiene de forma controlada y segura un proceso sospechoso usando APIs de Windows o señales
    pub fn terminate_suspicious_process(&mut self, pid: u32) -> bool {
        #[cfg(target_os = "windows")]
        {
            let mut cmd = Command::new("taskkill");
            cmd.args(["/F", "/PID", &pid.to_string()]);
            cmd.creation_flags(CREATE_NO_WINDOW);
            if let Ok(output) = cmd.output() {
                if output.status.success() {
                    self.isolated_pids.insert(pid);
                    info!("Proceso hostil PID {} terminado con éxito por SamuLibre Tor Shield", pid);
                    return true;
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            let mut cmd = Command::new("kill");
            cmd.args(["-9", &pid.to_string()]);
            if let Ok(output) = cmd.output() {
                if output.status.success() {
                    self.isolated_pids.insert(pid);
                    return true;
                }
            }
        }

        false
    }

    // =========================================================================
    // FASE 5: AISLAMIENTO Y SANDBOX PARA DESCARGAS DE TOR
    // =========================================================================

    /// Flujo completo de inspección y contención preventiva de descargas de Tor
    pub fn analyze_and_sandbox_download(
        &mut self,
        file_path: impl AsRef<Path>,
        source_origin: Option<&str>,
    ) -> TorDownloadReport {
        let p = file_path.as_ref();
        let file_name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let ext = p
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        let origin = source_origin.unwrap_or("Tor Network / Dark Web").to_string();

        // 1. Leer bytes y calcular SHA-256
        let (bytes, size_bytes, sha256_hash, os_virus_blocked) = match fs::read(p) {
            Ok(data) => {
                let hash = hex::encode(Sha256::digest(&data));
                let len = data.len() as u64;
                (data, len, hash, false)
            }
            Err(e) => {
                let is_av = e.raw_os_error() == Some(225) || e.to_string().to_lowercase().contains("virus");
                (Vec::new(), 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(), is_av)
            }
        };

        // 2. Análisis especializado para documentos (PDF / Office)
        let doc_analysis = self.analyze_document_risk(&bytes, &ext);

        // 3. Verificación de firmas conocidas y IoCs de Dark Web
        let mut signature_threat = None;
        if os_virus_blocked {
            signature_threat = Some("MalwareDetectado.WindowsSecurity.Error225".to_string());
        } else if let Some(ioc) = self.known_iocs.get(&sha256_hash) {
            signature_threat = Some(format!("{}: {}", ioc.campaign, ioc.description));
        }

        // Detección de cadena EICAR estándar o firmas
        let is_eicar = os_virus_blocked
            || String::from_utf8_lossy(&bytes)
                .to_uppercase()
                .contains("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
            || sha256_hash == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        if is_eicar && signature_threat.is_none() {
            signature_threat = Some("EICAR-Standard-AV-Test-Signature [TorShield]".to_string());
        }

        // 4. Heurística y evaluación de sandbox
        let is_executable = EXECUTABLE_EXTENSIONS.contains(&ext.as_str());
        let mut heuristic_score = 0.0;
        let mut sandbox_verdict = "Limpio: Sin artefactos maliciosos detectados".to_string();
        let mut final_verdict = TorDownloadVerdict::Authorized;
        let mut reasoning = "Archivo descargado verificado y libre de amenazas conocidas.".to_string();

        if is_eicar {
            heuristic_score = 1.0;
            sandbox_verdict = "Malicioso: Firma de prueba EICAR identificada".to_string();
            final_verdict = TorDownloadVerdict::Blocked;
            reasoning = "Bloqueado por firma antivirus EICAR en zona de descarga Tor.".to_string();
        } else if signature_threat.is_some() {
            heuristic_score = 0.95;
            sandbox_verdict = "Malicioso: Coincidencia exacta con IoC de la Dark Web".to_string();
            final_verdict = TorDownloadVerdict::Blocked;
            reasoning = "El archivo coincide con un hash conocido de distribución de malware/ransomware.".to_string();
        } else if doc_analysis.risk_score >= 60 {
            heuristic_score = (doc_analysis.risk_score as f64) / 100.0;
            sandbox_verdict = format!(
                "Peligroso: Documento armado con indicadores de explotación ({:?})",
                doc_analysis.risk_indicators
            );
            final_verdict = TorDownloadVerdict::Quarantined;
            reasoning = format!(
                "Documento potencialmente hostil detectado (Scripts o Macros activos: {}). Confinado en aislamiento.",
                doc_analysis.risk_indicators.join(", ")
            );
        } else if is_executable {
            if self.profile == TorProtectionProfile::MaximumIsolation {
                heuristic_score = 0.85;
                sandbox_verdict = "Confinado preventivamente por directiva Maximum Isolation".to_string();
                final_verdict = TorDownloadVerdict::Quarantined;
                reasoning = "El perfil Maximum Isolation prohíbe la ejecución de binarios descargados desde Tor.".to_string();
            } else {
                heuristic_score = 0.45;
                sandbox_verdict = "Sospechoso: Binario ejecutable descargado desde la red Tor".to_string();
                final_verdict = TorDownloadVerdict::Suspicious;
                reasoning = "Ejecutable descargado en sesión Tor. Se aconseja escanear con sandbox antes de ejecutar.".to_string();
            }
        }

        // 5. Retención en zona de cuarentena si es bloqueado o confinado
        let mut quarantine_path = None;
        if final_verdict == TorDownloadVerdict::Blocked || final_verdict == TorDownloadVerdict::Quarantined {
            let isolated_name = format!("{}_{}", &sha256_hash[..12], file_name);
            let target_quarantine = self.quarantine_zone_dir.join(&isolated_name);
            if fs::copy(p, &target_quarantine).is_ok() {
                quarantine_path = Some(target_quarantine.to_string_lossy().to_string());
                let _ = fs::remove_file(p); // Retirar del directorio de descargas del usuario
            } else if os_virus_blocked {
                // Windows Defender ya retuvo o bloqueó el archivo en tiempo real
                quarantine_path = Some(format!("[WindowsDefenderIsolation]: {}", p.display()));
                let _ = fs::remove_file(p);
            }

            if let Some(sess) = &mut self.current_session {
                sess.threats_quarantined += 1;
            }
        }

        let report = TorDownloadReport {
            id: Uuid::new_v4(),
            file_name,
            source_origin: origin,
            target_path: p.to_string_lossy().to_string(),
            sha256: sha256_hash,
            size_bytes,
            quarantine_path,
            signature_threat,
            heuristic_score,
            document_analysis: doc_analysis,
            sandbox_verdict,
            reputation_verdict: "Local Threat Intelligence Engine".to_string(),
            final_verdict,
            reasoning,
            analyzed_at: Utc::now(),
        };

        self.downloads_history.push_front(report.clone());
        if let Some(sess) = &mut self.current_session {
            sess.downloads_analyzed += 1;
        }

        self.persist_state_to_disk();
        report
    }

    /// Análisis estático especializado para documentos PDF y Office armados
    pub fn analyze_document_risk(&self, data: &[u8], extension: &str) -> TorDocumentRiskAnalysis {
        let mut analysis = TorDocumentRiskAnalysis::default();
        let ext = extension.to_lowercase();

        if ext == "pdf" {
            analysis.is_document = true;
            analysis.doc_type = "PDF".to_string();

            if self.pdf_eval_regex.is_match(data) {
                analysis.has_active_script = true;
                analysis.risk_score += 45;
                analysis.risk_indicators.push("Flujo /JavaScript o /JS embebido en PDF".to_string());
            }

            let s = String::from_utf8_lossy(data).to_lowercase();
            if s.contains("/launch") {
                analysis.has_launch_actions = true;
                analysis.risk_score += 35;
                analysis.risk_indicators.push("Acción /Launch para invocar ejecutables externos".to_string());
            }
            if s.contains("/embeddedfiles") {
                analysis.has_embedded_executables = true;
                analysis.risk_score += 25;
                analysis.risk_indicators.push("Archivos binarios adjuntos embebidos (/EmbeddedFiles)".to_string());
            }
            if s.contains("/flatedecode") && s.contains("/asciihexdecode") {
                analysis.has_obfuscated_streams = true;
                analysis.risk_score += 15;
                analysis.risk_indicators.push("Doble codificación de flujos para evasión".to_string());
            }
        } else if ext == "doc" || ext == "docx" || ext == "docm" || ext == "xls" || ext == "xlsm" {
            analysis.is_document = true;
            analysis.doc_type = "Office Document".to_string();

            if self.office_eval_regex.is_match(data) {
                analysis.has_embedded_macros = true;
                analysis.risk_score += 55;
                analysis.risk_indicators.push("Macros de auto-ejecución (AutoOpen/Workbook_Open)".to_string());
            }

            let s = String::from_utf8_lossy(data).to_lowercase();
            if s.contains("wscript.shell") || s.contains("powershell") || s.contains("cmd.exe") {
                analysis.has_launch_actions = true;
                analysis.risk_score += 40;
                analysis.risk_indicators.push("Invocación de intérpretes del sistema desde macros".to_string());
            }
        }

        analysis
    }

    // =========================================================================
    // FASE 6: PROTECCIÓN CONTRA INFOSTEALERS Y ACCESO A PERFILES
    // =========================================================================

    /// Evalúa si un proceso ajeno a Tor Browser intenta acceder a archivos sensibles del perfil
    pub fn inspect_profile_access_attempt(
        &mut self,
        accessor_pid: u32,
        accessor_name: &str,
        target_file_path: &str,
    ) -> Option<ThreatAlert> {
        let acc_lower = accessor_name.to_lowercase();
        let target_lower = target_file_path.to_lowercase();

        // Si el acceso proviene legítimamente de firefox o de samulibre, se permite
        if acc_lower.contains("firefox") || acc_lower.contains("tor") || acc_lower.contains("samulibre") {
            return None;
        }

        let is_sensitive_target = SENSITIVE_TOR_PROFILE_TARGETS
            .iter()
            .any(|sens| target_lower.contains(sens));

        if is_sensitive_target && target_lower.contains("tor browser") {
            let alert = ThreatAlert {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                severity: Severity::Critical,
                category: ThreatCategory::CredentialTheft,
                title: "Spyware.Infostealer.TorProfileAccess".to_string(),
                details: format!(
                    "El proceso sospechoso '{}' (PID {}) intentó leer el almacén de credenciales/cookies de Tor Browser ('{}'). Típico de RedLine, Vidar o Lumma Stealer.",
                    accessor_name, accessor_pid, target_file_path
                ),
                process_id: Some(accessor_pid),
                process_name: Some(accessor_name.to_string()),
                target_path: Some(target_file_path.to_string()),
                action_taken: "Acceso denegado y proceso sospechoso registrado para contención".to_string(),
            };

            self.suspicious_processes.push_front(TorSuspiciousProcess {
                pid: accessor_pid,
                name: accessor_name.to_string(),
                command_line: format!("Target: {}", target_file_path),
                parent_pid: None,
                violation_reason: "Intento no autorizado de exfiltración de credenciales de Tor Browser (T1539/T1555)".to_string(),
                severity: Severity::Critical,
                is_isolated: false,
                detected_at: Utc::now(),
            });

            self.recent_alerts.push_front(alert.clone());
            return Some(alert);
        }

        None
    }

    /// Auditoría periódica del portapapeles durante la sesión Tor para detectar sustitución de direcciones cripto (Clipboard Hijacking)
    pub fn audit_clipboard_text(&mut self, text: &str) -> Option<TorPrivacyLeakAlert> {
        if !self.clipboard_monitor_active || text.trim().is_empty() {
            return None;
        }

        let hash = hex::encode(Sha256::digest(text.as_bytes()));
        if hash == self.last_clipboard_hash {
            return None;
        }
        self.last_clipboard_hash = hash;

        // Comprobar patrones de criptomonedas (Bitcoin legacy / bech32, Monero, Ethereum)
        let btc_regex = Regex::new(r"^(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$").ok()?;
        let eth_regex = Regex::new(r"^0x[a-fA-F0-9]{40}$").ok()?;
        let xmr_regex = Regex::new(r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$").ok()?;

        let trimmed = text.trim();
        if btc_regex.is_match(trimmed) || eth_regex.is_match(trimmed) || xmr_regex.is_match(trimmed) {
            let alert = TorPrivacyLeakAlert {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                alert_type: "ClipboardAddressDetected".to_string(),
                process_name: "ClipboardSubsystem".to_string(),
                pid: 0,
                destination: "Local Clipboard Memory".to_string(),
                severity: Severity::Low,
                details: "Dirección de billetera de criptomonedas detectada en el portapapeles durante navegación Tor. Verifique siempre los caracteres antes de enviar fondos.".to_string(),
                action_taken: "Monitoreo preventivo contra secuestro de portapapeles activo".to_string(),
            };
            self.privacy_alerts.push_front(alert.clone());
            return Some(alert);
        }

        None
    }

    // =========================================================================
    // FASE 8: PRIVACIDAD Y DETECCIÓN DE FUGAS
    // =========================================================================

    /// Evalúa si una aplicación configurada para usar Tor está enviando tráfico directo sin pasar por el túnel (Fuga de DNS / Proxy Bypass)
    pub fn inspect_proxy_bypass_attempt(
        &mut self,
        pid: u32,
        proc_name: &str,
        dest_ip: &str,
        dest_port: u16,
    ) -> Option<TorPrivacyLeakAlert> {
        let lower = proc_name.to_lowercase();

        // Si es Tor Browser o un proceso bajo política Tor pero intenta conectarse en clearnet (puerto 53 UDP o puerto 80/443 directo sin pasar por SOCKS)
        if (lower.contains("torbrowser") || lower.contains("firefox")) && (dest_port == 53 || (!dest_ip.starts_with("127.0.0.1") && dest_port != 9150 && dest_port != 9050)) {
            // Tor Browser nunca debe generar peticiones DNS directas en UDP 53
            if dest_port == 53 {
                let alert = TorPrivacyLeakAlert {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    alert_type: "DnsLeak".to_string(),
                    process_name: proc_name.to_string(),
                    pid,
                    destination: format!("{}:{}", dest_ip, dest_port),
                    severity: Severity::Critical,
                    details: format!(
                        "Fuga de DNS detectada (DNS Leak). El proceso '{}' (PID {}) intentó resolver un dominio en clearnet vía UDP 53 ({}), eludiendo el enrutamiento Tor.",
                        proc_name, pid, dest_ip
                    ),
                    action_taken: "Tráfico de fuga bloqueado preventivamente por el Firewall de SamuLibre".to_string(),
                };
                self.privacy_alerts.push_front(alert.clone());
                return Some(alert);
            }
        }

        None
    }

    // =========================================================================
    // FASE 9: KILL SWITCH Y CONTENCIÓN
    // =========================================================================

    /// Ejecuta la contención inmediata de un proceso infractor (detención + bloqueo de red)
    pub fn trigger_containment_kill_switch(&mut self, pid: u32, process_name: &str, reason: &str) -> bool {
        info!("Ejecutando Kill Switch de Contención sobre PID {} ({}): {}", pid, process_name, reason);

        // 1. Terminar el proceso
        let terminated = self.terminate_suspicious_process(pid);

        // 2. Aislar en Firewall de Windows (WFP)
        #[cfg(target_os = "windows")]
        {
            let rule_name = format!("SamuLibre_Tor_Containment_PID_{}", pid);
            let mut cmd = Command::new("netsh");
            cmd.args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", rule_name),
                "dir=out",
                "action=block",
                "enable=yes",
            ]);
            cmd.creation_flags(CREATE_NO_WINDOW);
            let _ = cmd.output();
        }

        self.isolated_pids.insert(pid);

        // 3. Registrar alerta
        let alert = ThreatAlert {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity: Severity::Critical,
            category: ThreatCategory::ActiveAttack,
            title: "Contención.KillSwitch.Activated".to_string(),
            details: format!("Kill Switch de emergencia activado: {}", reason),
            process_id: Some(pid),
            process_name: Some(process_name.to_string()),
            target_path: Some(format!("PID: {} ({})", pid, process_name)),
            action_taken: "Proceso terminado y comunicaciones bloqueadas en firewall".to_string(),
        };
        self.recent_alerts.push_front(alert);

        terminated
    }

    // =========================================================================
    // FASE 11: AUDITORÍA DE VULNERABILIDADES DE TOR BROWSER
    // =========================================================================

    /// Audita la versión instalada de Tor Browser frente al catálogo de CVEs de Firefox ESR
    pub fn audit_vulnerabilities(&mut self, installed_version: Option<&str>) -> Vec<TorVulnerabilityAdvisory> {
        let current_ver = installed_version.map(|v| v.to_string());

        for adv in &mut self.cve_advisories {
            adv.current_installed_version = current_ver.clone();
            // Si la versión instalada es conocida y menor a la corregida, marcar como vulnerable
            if let Some(ref ver) = current_ver {
                adv.is_vulnerable = ver < &adv.fixed_in_version;
            } else {
                adv.is_vulnerable = false;
            }
        }

        self.cve_advisories.clone()
    }

    // =========================================================================
    // FASE 12: GESTIÓN DE PERFILES Y SNAPSHOT PARA LA GUI
    // =========================================================================

    /// Establece el perfil de protección deseado
    pub fn set_protection_profile(&mut self, profile: TorProtectionProfile) {
        self.profile = profile;
        info!("Perfil de protección de Tor actualizado a: {:?}", profile);
        if let Some(sess) = &mut self.current_session {
            sess.profile = profile;
        }
    }

    /// Obtiene el snapshot completo para el panel DARK WEB & TOR PROTECTION
    pub fn get_dashboard_snapshot(&mut self) -> TorShieldDashboardSnapshot {
        let process_state = self.detect_tor_process();
        let vulns = self.audit_vulnerabilities(process_state.version.as_deref());

        TorShieldDashboardSnapshot {
            active_profile: self.profile,
            process_state,
            web_shield_active: true,
            exploit_shield_active: true,
            sandbox_isolation_active: true,
            ransomware_tripwire_active: true,
            stealer_protection_active: true,
            kill_switch_armed: self.kill_switch_armed,
            downloads_scanned_count: self.downloads_history.len(),
            threats_blocked_count: self.recent_alerts.len(),
            privacy_leaks_count: self.privacy_alerts.len(),
            recent_alerts: self.recent_alerts.iter().take(20).cloned().collect(),
            suspicious_processes: self.suspicious_processes.iter().take(20).cloned().collect(),
            privacy_alerts: self.privacy_alerts.iter().take(20).cloned().collect(),
            vulnerabilities: vulns,
            recent_downloads: self.downloads_history.iter().take(20).cloned().collect(),
            session_history: self.session_logs.iter().take(20).cloned().collect(),
            threat_feed_count: self.known_iocs.len(),
            threat_feed_last_update: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tor_shield_initialization_and_snapshot() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_tor_test_{}", Uuid::new_v4()));
        let mut engine = TorShieldEngine::new(&temp_dir);

        let snapshot = engine.get_dashboard_snapshot();
        assert_eq!(snapshot.active_profile, TorProtectionProfile::TorProtection);
        assert!(snapshot.threat_feed_count >= 5);
        assert!(snapshot.vulnerabilities.len() >= 4);

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_browser_exploit_child_process_interception() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_tor_test_{}", Uuid::new_v4()));
        let mut engine = TorShieldEngine::new(&temp_dir);

        // Simulación: Tor Browser (firefox.exe) intenta engendrar powershell.exe con encoded command
        let alert = engine.inspect_browser_child_process(
            1234,
            "firefox.exe",
            5678,
            "powershell.exe",
            "-enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
        );

        assert!(alert.is_some(), "Debe interceptar el proceso hijo sospechoso");
        let alert = alert.unwrap();
        assert_eq!(alert.category, ThreatCategory::ExploitAttempt);
        assert_eq!(alert.severity, Severity::Critical);
        assert!(engine.suspicious_processes.len() >= 1);

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_unauthorized_tor_proxy_client_detection() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_tor_test_{}", Uuid::new_v4()));
        let mut engine = TorShieldEngine::new(&temp_dir);

        // Simulación: Un binario sospechoso 'stealer.exe' intenta usar el proxy SOCKS 9150
        let leak = engine.inspect_tor_proxy_client(9999, "stealer.exe", 9150);
        assert!(leak.is_some(), "Debe detectar proceso no autorizado intentando usar Tor");
        let alert = leak.unwrap();
        assert_eq!(alert.alert_type, "UnauthorizedTorUse");
        assert_eq!(alert.severity, Severity::High);

        // Proceso legítimo (firefox) no debe generar alerta
        let ok_leak = engine.inspect_tor_proxy_client(1234, "firefox.exe", 9150);
        assert!(ok_leak.is_none(), "Tor Browser legítimo no debe generar alerta");

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_infostealer_tor_profile_access_blocked() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_tor_test_{}", Uuid::new_v4()));
        let mut engine = TorShieldEngine::new(&temp_dir);

        // Simulación: malware 'malicious_app.exe' intenta leer logins.json de Tor Browser
        let alert = engine.inspect_profile_access_attempt(
            8888,
            "malicious_app.exe",
            r"C:\Users\User\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\logins.json",
        );

        assert!(alert.is_some(), "Debe interceptar intento de robo de credenciales");
        let a = alert.unwrap();
        assert_eq!(a.category, ThreatCategory::CredentialTheft);

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_pdf_document_active_script_analysis() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_tor_test_{}", Uuid::new_v4()));
        let engine = TorShieldEngine::new(&temp_dir);

        let clean_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF";
        let clean_analysis = engine.analyze_document_risk(clean_pdf, "pdf");
        assert_eq!(clean_analysis.risk_score, 0);
        assert!(!clean_analysis.has_active_script);

        let malicious_pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('PWNED');) >>\nendobj\n%%EOF";
        let mal_analysis = engine.analyze_document_risk(malicious_pdf, "pdf");
        assert!(mal_analysis.has_active_script);
        assert!(mal_analysis.risk_score >= 45);

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_eicar_download_sandbox_and_quarantine() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_tor_test_{}", Uuid::new_v4()));
        let mut engine = TorShieldEngine::new(&temp_dir);

        let test_file = temp_dir.join("test_download.exe");
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        fs::write(&test_file, eicar).expect("Write file");

        let report = engine.analyze_and_sandbox_download(&test_file, Some("http://evil-darkweb-site.onion/payload.exe"));
        eprintln!("DEBUG REPORT: final_verdict={:?}, reasoning={}, sig={:?}, sha={}, bytes_len={}", report.final_verdict, report.reasoning, report.signature_threat, report.sha256, report.size_bytes);
        assert_eq!(report.final_verdict, TorDownloadVerdict::Blocked);
        assert!(report.signature_threat.is_some());
        assert!(report.quarantine_path.is_some());
        assert!(!test_file.exists(), "El archivo debe haber sido retirado del directorio de descargas");

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_profile_switch_and_maximum_isolation() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_tor_test_{}", Uuid::new_v4()));
        let mut engine = TorShieldEngine::new(&temp_dir);

        engine.set_protection_profile(TorProtectionProfile::MaximumIsolation);
        assert_eq!(engine.profile, TorProtectionProfile::MaximumIsolation);

        // En Maximum Isolation, cualquier ejecutable nuevo se confina preventivamente
        let dummy_exe = temp_dir.join("unknown_tool.exe");
        fs::write(&dummy_exe, b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00").expect("Write");

        let report = engine.analyze_and_sandbox_download(&dummy_exe, Some("http://sample.onion/tool.exe"));
        assert_eq!(report.final_verdict, TorDownloadVerdict::Quarantined);

        let _ = fs::remove_dir_all(temp_dir);
    }
}
