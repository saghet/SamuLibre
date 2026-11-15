#![windows_subsystem = "windows"]

use anyhow::Result;
use rayon::prelude::*;
use samulibre_core::SamuLibreCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tao::{
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
    window::WindowBuilder,
};
use tracing::info;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use walkdir::WalkDir;
use wry::WebViewBuilder;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

static IS_SCAN_CANCELLED: AtomicBool = AtomicBool::new(false);
static IS_SCAN_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "windows")]
mod win_eco {
    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetCurrentThread() -> isize;
        pub fn SetThreadPriority(hThread: isize, nPriority: i32) -> i32;
        pub fn GetCurrentProcess() -> isize;
    }

    #[link(name = "psapi")]
    extern "system" {
        pub fn EmptyWorkingSet(hProcess: isize) -> i32;
    }

    pub const THREAD_PRIORITY_BELOW_NORMAL: i32 = -1;

    pub fn set_current_thread_affinity_and_priority(_num_threads: usize) {
        unsafe {
            let thread = GetCurrentThread();
            // No restringir afinidad para usar todos los núcleos Ryzen/Intel y evitar estrangulamiento EcoQoS
            SetThreadPriority(thread, THREAD_PRIORITY_BELOW_NORMAL);
        }
    }

    pub fn set_current_thread_eco_qos() {
        unsafe {
            let thread = GetCurrentThread();
            SetThreadPriority(thread, THREAD_PRIORITY_BELOW_NORMAL);
        }
    }

    pub fn trim_process_working_set() {
        unsafe {
            let process = GetCurrentProcess();
            EmptyWorkingSet(process);
        }
    }
}

#[cfg(target_os = "linux")]
mod win_eco {
    extern "C" {
        fn setpriority(which: i32, who: u32, prio: i32) -> i32;
        fn malloc_trim(pad: usize) -> i32;
    }

    const PRIO_PROCESS: i32 = 0;

    pub fn set_current_thread_eco_qos() {
        unsafe {
            // Asigna la prioridad mÃ¡s baja (nice 19) en el planificador de Linux
            let _ = setpriority(PRIO_PROCESS, 0, 19);
        }
    }

    pub fn trim_process_working_set() {
        unsafe {
            // Devuelve la memoria heap no utilizada al kernel (glibc)
            let _ = malloc_trim(0);
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
mod win_eco {
    pub fn set_current_thread_eco_qos() {}
    pub fn trim_process_working_set() {}
}

#[cfg(target_os = "windows")]
mod win_util {
    #[link(name = "user32")]
    extern "system" {
        fn FindWindowW(lpClassName: *const u16, lpWindowName: *const u16) -> isize;
        fn ShowWindow(hWnd: isize, nCmdShow: i32) -> i32;
        fn SetForegroundWindow(hWnd: isize) -> i32;
    }
    const SW_RESTORE: i32 = 9;

    pub fn bring_existing_window_to_front() -> bool {
        let title: Vec<u16> = "SamuLibre - Suite de Seguridad Open Source\0"
            .encode_utf16()
            .collect();
        let hwnd = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
        if hwnd != 0 {
            unsafe {
                ShowWindow(hwnd, SW_RESTORE);
                SetForegroundWindow(hwnd);
            }
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
enum CustomUserEvent {
    ScanProgress {
        files_scanned: usize,
        total_files: usize,
        current_file: String,
        threats_found: usize,
        is_done: bool,
    },
    ScanCompleted {
        files_scanned: usize,
        threats_found: usize,
        elapsed_ms: u64,
        infected_files: Vec<samulibre_types::ThreatRecord>,
    },
    RealTimeAlert {
        title: String,
        details: String,
    },
    ShowWindow,
    TriggerScan,
    TriggerFullScan,
    TriggerUpdateSignatures,
    SignaturesUpdated {
        total: usize,
        new_added: usize,
        timestamp: String,
        feed: String,
    },
    UpdatePatchRules {
        rules: Vec<samulibre_types::VirtualPatchRule>,
        os_info: Option<samulibre_patcher::OsVersionInfo>,
        sentinel_status: Option<samulibre_patcher::SentinelStatusInfo>,
        kb_monitor_status: Option<samulibre_types::KbMonitorStatus>,
    },
    KbAnalysisResultLoaded {
        result: samulibre_types::AiPatchAnalysisResult,
    },
    VpnStateUpdated {
        state: samulibre_vpn::VpnConnectionState,
        countries: Vec<samulibre_vpn::VpnCountryInfo>,
    },
    VpnLatenciesUpdated {
        latencies: std::collections::HashMap<String, u32>,
        tunnel_ping: Option<u32>,
    },
    UpdateHistoryLoaded {
        entries: Vec<samulibre_scanner::UpdateHistoryEntry>,
    },
    SignaturesCatalogLoaded {
        catalog_json: String,
    },
    IntelKeysStatusLoaded {
        status_json: String,
    },
    IntelFeedsSyncCompleted {
        reports_json: String,
    },
    AuditReportLoaded {
        report: samulibre_core::SecurityAuditReport,
    },
    ShieldStatusUpdated {
        status: samulibre_shield::ShieldLiveStatus,
    },
    SingleScanResult {
        result: samulibre_types::ScanResult,
    },
    BatchScanResults {
        results: Vec<samulibre_types::ScanResult>,
    },
    QuarantineListLoaded {
        records: Vec<samulibre_watcher::QuarantineRecord>,
    },
    OnAccessLabCompleted {
        log: String,
        quarantined: Option<samulibre_watcher::QuarantineRecord>,
    },
    PersistenceListLoaded {
        entries: Vec<samulibre_types::PersistenceEntry>,
    },
    NetworkSocketsLoaded {
        sockets: Vec<samulibre_types::NetworkSocketInfo>,
    },
    CopilotAnswerLoaded {
        response: samulibre_types::CopilotResponse,
    },
    PcAdvancedStatusLoaded {
        status: samulibre_core::PcAdvancedFeaturesStatus,
    },
    FilelessScanResultsLoaded {
        threats: Vec<samulibre_shield::FilelessThreat>,
    },
    SandboxReportLoaded {
        report: samulibre_core::SandboxReport,
    },
    ReputationResultLoaded {
        indicators: Vec<samulibre_core::CommunityThreatIndicator>,
    },
    PhishingVerdictLoaded {
        verdict: samulibre_scanner::PhishingVerdict,
    },
    BrowserExtensionsLoaded {
        extensions: Vec<samulibre_shield::ExtensionAuditReport>,
    },
    #[allow(dead_code)]
    ThreatDetected {
        record: samulibre_types::ThreatRecord,
    },
    ThreatHistoryLoaded {
        history: Vec<samulibre_types::ThreatRecord>,
    },
    VtVerificationLoaded {
        report: samulibre_scanner::VtCorrelationReport,
    },
    VtStatusLoaded {
        has_api_key: bool,
        policy: samulibre_scanner::VtVerificationPolicy,
        quota: samulibre_scanner::VtQuotaState,
    },
    AutostartStatusLoaded {
        enabled: bool,
    },
    ScheduledScanConfigLoaded {
        config: samulibre_types::ScheduledScanConfig,
    },
    ScheduledScanCompleted {
        report: samulibre_core::ScheduledScanReport,
    },
    WatcherSettingsLoaded {
        settings: samulibre_types::WatcherSettings,
    },
    SecurityExceptionsLoaded {
        exceptions: Vec<samulibre_types::SecurityException>,
    },
    PathSelectedForException {
        path: String,
        name: String,
        is_dir: bool,
        sha256: Option<String>,
        size: Option<u64>,
    },
    RealtimeTelemetryLoaded {
        telemetry: samulibre_types::RealtimeTelemetry,
    },
    RealtimeDiagnosticReportLoaded {
        report: samulibre_types::RealtimeDiagnosticReport,
    },
    ProtectionHealthLoaded {
        snapshot: samulibre_types::ProtectionHealthSnapshot,
    },
    WindowsPatchSummaryLoaded {
        summary: samulibre_types::WindowsPatchIntelligenceSummary,
    },
    CveCorrelationsLoaded {
        correlations: Vec<samulibre_types::CveKbCorrelation>,
    },
    VpnDiagnosticsLoaded {
        result: samulibre_types::VpnDiagnosticResult,
    },
    VpnHistoryLoaded {
        history: Vec<samulibre_types::VpnHistoryEntry>,
    },
    VirtualPatchIncidentsLoaded {
        incidents: Vec<samulibre_types::VirtualPatchIncident>,
    },
    KbInstallCompleted {
        result_message: String,
    },
    SsemConfigLoaded {
        config: samulibre_types::SsemConfig,
        metrics: samulibre_core::SsemMetrics,
    },
    WdheSettingsLoaded {
        coexistence_mode: String,
        resource_profile: String,
        safe_exclusions_active: bool,
    },
    ShceSettingsLoaded {
        topology: samulibre_types::HardwareTopology,
        selection: samulibre_types::BackendSelection,
        gpu_preference: String,
        gpu_status: Option<samulibre_core::gpu_compute::GpuPoolStatus>,
    },
    AmtsoReportLoaded {
        report: samulibre_types::AmtsoSuiteReport,
    },
    TorShieldSnapshotLoaded {
        snapshot: samulibre_types::TorShieldDashboardSnapshot,
    },
    NetDefenseStateLoaded {
        payload_json: String,
    },
    PauseProtection {
        duration_secs: u64,
    },
    ResumeProtection,
    Quit,
}

#[derive(Debug, Deserialize)]
struct IpcMessage {
    action: String,
    payload: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
struct IpcResponse {
    success: bool,
    action: String,
    message: String,
    data: Option<serde_json::Value>,
}

fn get_netdefense_engine(
    data_dir: &Path,
) -> &'static Arc<Mutex<samulibre_netdefense::NetworkDefenseEngine>> {
    static ND_ENGINE: std::sync::OnceLock<
        Arc<Mutex<samulibre_netdefense::NetworkDefenseEngine>>,
    > = std::sync::OnceLock::new();
    ND_ENGINE.get_or_init(|| {
        Arc::new(Mutex::new(samulibre_netdefense::NetworkDefenseEngine::new(
            data_dir,
        )))
    })
}

fn build_netdefense_state_json(nd: &mut samulibre_netdefense::NetworkDefenseEngine) -> String {
    let connections = nd.refresh_live_connections();
    let snapshot = nd.get_dashboard_snapshot();
    let rules = nd.rules.clone();
    let app_policies: Vec<_> = nd.app_policies.values().cloned().collect();
    let dns_config = nd.dns_proxy.config.lock().unwrap().clone();
    let dns_logs: Vec<_> = nd.dns_proxy.query_logs.lock().unwrap().iter().take(100).cloned().collect();
    let feeds = nd
        .intel
        .lock()
        .map(|i| i.store.feeds.clone())
        .unwrap_or_default();
    let event_logs: Vec<_> = nd.event_logs.iter().take(150).cloned().collect();
    let correlation_events: Vec<_> = nd.correlation_events.iter().take(50).cloned().collect();
    let learned_apps: Vec<_> = nd.learning_engine.db.apps.values().cloned().collect();

    serde_json::json!({
        "snapshot": snapshot,
        "connections": connections,
        "rules": rules,
        "app_policies": app_policies,
        "learned_apps": learned_apps,
        "dns_config": dns_config,
        "dns_logs": dns_logs,
        "feeds": feeds,
        "event_logs": event_logs,
        "correlation_events": correlation_events,
    })
    .to_string()
}

fn forward_rule_to_elevated_service(rule: &samulibre_netdefense::FirewallRule) -> Result<String, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    let addr: SocketAddr = "127.0.0.1:49791".parse().map_err(|e| format!("{}", e))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(450))
        .map_err(|e| format!("Servicio elevado no accesible ({})", e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(450)));

    let req = serde_json::json!({
        "cmd": "add_rule",
        "rule": rule,
    });
    let line = format!("{}\n", req);
    stream.write_all(line.as_bytes()).map_err(|e| format!("Error IPC write: {}", e))?;
    let _ = stream.flush();

    let mut reader = BufReader::new(stream);
    let mut resp = String::new();
    let _ = reader.read_line(&mut resp);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp) {
        if v["ok"].as_bool() == Some(true) {
            return Ok("Regla aplicada por el servicio elevado SamuLibreWatcher (WFP + TCP reset).".to_string());
        }
        return Err(v["error"].as_str().unwrap_or("Error desconocido en servicio").to_string());
    }
    Ok("Regla enviada al servicio elevado.".to_string())
}

#[derive(Debug, Deserialize)]
struct ModifyExceptionPayload {
    id: String,
    scope: samulibre_types::ExceptionScope,
    expires_at: Option<String>,
    justification: String,
}

fn get_project_root() -> PathBuf {
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            if parent.ends_with("release") || parent.ends_with("debug") {
                if let Some(root) = parent.parent().and_then(|p| p.parent()) {
                    if root.join("data").exists() {
                        return root.to_path_buf();
                    }
                }
            }
            if parent.join("data").exists() {
                return parent.to_path_buf();
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let hardcoded = PathBuf::from(r"C:\Users\saghe\Documents\Antivitus-SamuLibre");
        if hardcoded.join("data").exists() {
            return hardcoded;
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let user_root = std::env::var("HOME")
            .ok()
            .map(|home| PathBuf::from(home).join(".local/share/samulibre"));
        if let Some(user_data) = &user_root {
            if user_data.join("data").exists() {
                return user_data.clone();
            }
        }
        // InstalaciÃ³n del sistema (solo lectura): sembrar una copia escribible en ~/.local/share/samulibre
        for sys_root in [
            PathBuf::from("/opt/samulibre"),
            PathBuf::from("/usr/share/samulibre"),
        ] {
            if sys_root.join("data").exists() {
                if let Some(user_data) = &user_root {
                    if copy_dir_recursive(&sys_root.join("data"), &user_data.join("data")).is_ok() {
                        return user_data.clone();
                    }
                }
                return sys_root;
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Copia recursivamente un directorio (usado para sembrar los datos de usuario en Linux)
#[cfg(not(target_os = "windows"))]
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else if !target.exists() {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn is_running_as_admin() -> bool {
    #[link(name = "shell32")]
    extern "system" {
        fn IsUserAnAdmin() -> i32;
    }
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(not(target_os = "windows"))]
pub fn is_running_as_admin() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "windows")]
pub fn request_uac_admin_confirmation(_action_description: &str) -> bool {
    is_running_as_admin()
}

#[cfg(not(target_os = "windows"))]
pub fn request_uac_admin_confirmation(_action_description: &str) -> bool {
    is_running_as_admin()
}

fn is_windows_autostart_enabled() -> bool {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("reg")
            .args(&[
                "query",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "/v",
                "SamuLibre",
            ])
            .creation_flags(0x08000000)
            .output();
        if let Ok(out) = output {
            return out.status.success();
        }
    }
    false
}

fn set_windows_autostart(enable: bool) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        if !is_running_as_admin() {
            let confirmed =
                request_uac_admin_confirmation("modificar las opciones de inicio con Windows");
            if !confirmed {
                return Err("Operación cancelada: Se requieren permisos de Administrador para modificar el arranque automático.".to_string());
            }
        }

        if enable {
            let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let exe_str = current_exe.to_string_lossy().to_string();
            let value = format!("\"{}\" --minimized", exe_str);
            let status = std::process::Command::new("reg")
                .args(&[
                    "add",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "/v",
                    "SamuLibre",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &value,
                    "/f",
                ])
                .creation_flags(0x08000000)
                .status()
                .map_err(|e| e.to_string())?;
            if status.success() {
                Ok(())
            } else {
                Err("Fallo al registrar inicio automático en el registro de Windows".to_string())
            }
        } else {
            let _ = std::process::Command::new("reg")
                .args(&[
                    "delete",
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "/v",
                    "SamuLibre",
                    "/f",
                ])
                .creation_flags(0x08000000)
                .status();
            Ok(())
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = enable;
        Ok(())
    }
}

fn get_threat_history_path() -> PathBuf {
    get_project_root().join("data").join("threat_history.json")
}

fn load_threat_history() -> Vec<samulibre_types::ThreatRecord> {
    let p = get_threat_history_path();
    if p.exists() {
        if let Ok(content) = fs::read_to_string(&p) {
            if let Ok(records) =
                serde_json::from_str::<Vec<samulibre_types::ThreatRecord>>(&content)
            {
                return records;
            }
        }
    }
    Vec::new()
}

fn save_threat_history(records: &[samulibre_types::ThreatRecord]) {
    let p = get_threat_history_path();
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(records) {
        let _ = fs::write(&p, json);
    }
}

/// Envía o verifica automáticamente en VirusTotal API v3 los ficheros infectados detectados,
/// respetando cuota gratuita (máx. 3 por lote), caché SHA-256 y privacidad obligatoria para Office/PDF.
fn trigger_vt_auto_verification_for_infected(
    records: Vec<samulibre_types::ThreatRecord>,
    proxy: tao::event_loop::EventLoopProxy<CustomUserEvent>,
) {
    let infected_only: Vec<samulibre_types::ThreatRecord> = records
        .into_iter()
        .filter(|r| {
            matches!(
                r.confidence_level,
                samulibre_types::ConfidenceLevel::Critico | samulibre_types::ConfidenceLevel::Alto
            )
        })
        .take(3)
        .collect();

    if infected_only.is_empty() {
        return;
    }

    std::thread::spawn(move || {
        let data_dir = get_project_root().join("data");
        if !samulibre_scanner::VtSecureKeyBackend::has_api_key(&data_dir) {
            return;
        }
        let policy = samulibre_scanner::VirusTotalVerifier::load_policy(&data_dir);
        let verifier = samulibre_scanner::VirusTotalVerifier::new(&data_dir, policy.clone());

        for rec in infected_only {
            let report = verifier.verify_threat_record(&rec, false);
            let _ = proxy.send_event(CustomUserEvent::VtVerificationLoaded { report });
        }

        let has_api_key = samulibre_scanner::VtSecureKeyBackend::has_api_key(&data_dir);
        let quota = samulibre_scanner::VtQuotaState::load(&data_dir.join("vt_quota.json"));
        let _ = proxy.send_event(CustomUserEvent::VtStatusLoaded {
            has_api_key,
            policy,
            quota,
        });
    });
}

fn log_step(msg: &str) {
    use std::io::Write;
    let root = get_project_root();
    let log_path = root.join("data").join("app_error.log");
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = writeln!(f, "[{}] {}", chrono::Local::now().format("%H:%M:%S"), msg);
    }
}

fn open_native_file_dialog() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let script = r#"
            Add-Type -AssemblyName System.Windows.Forms
            $d = New-Object System.Windows.Forms.OpenFileDialog
            $d.Multiselect = $true
            $d.Title = 'Seleccionar Archivos para Escanear - SamuLibre'
            $d.Filter = 'Todos los archivos (*.*)|*.*|Ejecutables y Scripts (*.exe;*.dll;*.ps1;*.bat;*.cmd)|*.exe;*.dll;*.ps1;*.bat;*.cmd|Documentos (*.docx;*.pdf;*.xlsx;*.txt)|*.docx;*.pdf;*.xlsx;*.txt'
            if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $d.FileNames -join "`n"
            }
        "#;
        let mut cmd = std::process::Command::new("powershell");
        cmd.args(["-WindowStyle", "Hidden", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]);
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000 | 0x00000008); // CREATE_NO_WINDOW | DETACHED_PROCESS
        if let Ok(output) = cmd.output() {
            let text = String::from_utf8_lossy(&output.stdout);
            text.lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .map(PathBuf::from)
                .filter(|p| p.exists())
                .collect()
        } else {
            Vec::new()
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // 1. Intentar con zenity (GNOME / Ubuntu / RHEL)
        if let Ok(output) = std::process::Command::new("zenity")
            .args([
                "--file-selection",
                "--multiple",
                "--separator=\n",
                "--title=Seleccionar Archivos para Escanear - SamuLibre",
            ])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let files: Vec<PathBuf> = text
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .map(PathBuf::from)
                    .filter(|p| p.exists())
                    .collect();
                if !files.is_empty() {
                    return files;
                }
            }
        }

        // 2. Intentar con kdialog (KDE Plasma 6 / Garuda Linux)
        if let Ok(output) = std::process::Command::new("kdialog")
            .args([
                "--getopenfilename",
                "--multiple",
                "--separate-output",
                ".",
                "Todos los archivos (*)",
            ])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let files: Vec<PathBuf> = text
                    .lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty())
                    .map(PathBuf::from)
                    .filter(|p| p.exists())
                    .collect();
                if !files.is_empty() {
                    return files;
                }
            }
        }

        Vec::new()
    }
}

fn open_native_folder_dialog() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let script = r#"
            Add-Type -AssemblyName System.Windows.Forms
            $d = New-Object System.Windows.Forms.FolderBrowserDialog
            $d.Description = 'Seleccionar Carpeta para Escaneo Exhaustivo - SamuLibre'
            if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $d.SelectedPath
            }
        "#;
        let mut cmd = std::process::Command::new("powershell");
        cmd.args(["-WindowStyle", "Hidden", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]);
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000 | 0x00000008); // CREATE_NO_WINDOW | DETACHED_PROCESS
        if let Ok(output) = cmd.output() {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !text.is_empty() {
                let p = PathBuf::from(text);
                if p.is_dir() {
                    return Some(p);
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "windows"))]
    {
        // 1. Intentar con zenity (GNOME / Ubuntu / RHEL)
        if let Ok(output) = std::process::Command::new("zenity")
            .args([
                "--file-selection",
                "--directory",
                "--title=Seleccionar Carpeta para Escaneo Exhaustivo - SamuLibre",
            ])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !text.is_empty() {
                    let p = PathBuf::from(text);
                    if p.is_dir() {
                        return Some(p);
                    }
                }
            }
        }

        // 2. Intentar con kdialog (KDE Plasma 6 / Garuda Linux)
        if let Ok(output) = std::process::Command::new("kdialog")
            .args(["--getexistingdirectory", "."])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !text.is_empty() {
                    let p = PathBuf::from(text);
                    if p.is_dir() {
                        return Some(p);
                    }
                }
            }
        }

        None
    }
}

fn main() {
    let app_root = get_project_root();
    let _ = std::env::set_current_dir(&app_root);
    let _ = fs::create_dir_all(app_root.join("data"));
    std::panic::set_hook(Box::new(|info| {
        let _ = samulibre_vpn::reset_system_network_proxy();
        log_step(&format!("PANIC: {}", info));
    }));

    // Startup Self-Healing: Si el proxy de Windows/Linux quedó activo por un corte o cierre anterior,
    // restaurar la conectividad normal de forma inmediata e incondicional.
    if samulibre_vpn::is_system_proxy_enabled() {
        log_step("Startup Self-Healing: Proxy del sistema huérfano detectado. Restaurando conexión normal...");
        let _ = samulibre_vpn::reset_system_network_proxy();
    }

    log_step(&format!("Iniciando SamuLibre GUI en raíz: {:?}", app_root));
    if let Err(e) = run_app(app_root) {
        log_step(&format!("Error fatal: {:?}", e));
    }
    log_step("Fin de main().");
}

fn run_app(app_root: PathBuf) -> Result<()> {
    log_step("run_app: Paso 1 - comprobando single instance");
    const SINGLE_INSTANCE_PORT: u16 = 49721;
    let single_instance_listener = match TcpListener::bind(("127.0.0.1", SINGLE_INSTANCE_PORT)) {
        Ok(l) => {
            log_step("run_app: Paso 1 OK - Listener enlazado a puerto");
            l
        }
        Err(e) => {
            log_step(&format!(
                "run_app: Listener no pudo enlazar: {:?}. Verificando ventana en escritorio...",
                e
            ));
            #[cfg(target_os = "windows")]
            {
                if win_util::bring_existing_window_to_front() {
                    log_step("run_app: Ventana activa encontrada y traída al frente. Saliendo.");
                    if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", SINGLE_INSTANCE_PORT)) {
                        let _ = stream.write_all(b"SHOW\n");
                    }
                    return Ok(());
                }
            }

            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", SINGLE_INSTANCE_PORT)) {
                log_step("run_app: Señal SHOW enviada a instancia existente. Esperando...");
                let _ = stream.write_all(b"SHOW\n");
                std::thread::sleep(std::time::Duration::from_millis(300));
            }

            #[cfg(target_os = "windows")]
            {
                if win_util::bring_existing_window_to_front() {
                    log_step("run_app: Ventana traída al frente tras señal SHOW. Saliendo.");
                    return Ok(());
                }
            }

            log_step("run_app: No hay ventana visible en el escritorio. Abriendo GUI interactiva en socket secundario para garantizar visualización...");
            TcpListener::bind(("127.0.0.1", SINGLE_INSTANCE_PORT + 1))
                .unwrap_or_else(|_| TcpListener::bind(("127.0.0.1", 0)).expect("No se pudo enlazar socket TCP"))
        }
    };

    log_step("run_app: Creando carpetas de datos...");
    let canary_dir = app_root.join("data").join("canaries");
    let vpn_dir = app_root.join("data").join("vpn");
    let quarantine_dir = app_root.join("data").join("quarantine");
    let signatures_dir = app_root.join("data").join("signatures");
    let _ = fs::create_dir_all(&canary_dir);
    let _ = fs::create_dir_all(&vpn_dir);
    let _ = fs::create_dir_all(&quarantine_dir);
    let _ = fs::create_dir_all(&signatures_dir);

    log_step("run_app: Creando Core...");
    let core = Arc::new(Mutex::new(SamuLibreCore::new(&canary_dir, &vpn_dir, true)));
    let _ = get_netdefense_engine(&app_root.join("data"));

    let core_for_ipc = Arc::clone(&core);
    let core_for_actions = Arc::clone(&core);

    log_step("run_app: Creando event_loop...");
    let event_loop = EventLoopBuilder::<CustomUserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    log_step("run_app: EventLoop creado OK");

    // Hilo receptor de seÃ±ales de Instancia Única
    let proxy_single_instance = proxy.clone();
    std::thread::spawn(move || {
        for stream in single_instance_listener.incoming() {
            if let Ok(mut s) = stream {
                let mut buf = [0u8; 16];
                let _ = s.read(&mut buf);
                let _ = proxy_single_instance.send_event(CustomUserEvent::ShowWindow);
            }
        }
    });

    log_step("run_app: Cargando icon.png y tray_icon.png...");
    let icon_bytes = include_bytes!("../../../assets/icon.png");
    let img = match image::load_from_memory(icon_bytes) {
        Ok(i) => i.into_rgba8(),
        Err(e) => {
            log_step(&format!("run_app: Error cargando icon_bytes: {:?}", e));
            return Err(e.into());
        }
    };
    let (icon_w, icon_h) = img.dimensions();
    log_step(&format!(
        "run_app: Icon decodificado: {}x{}",
        icon_w, icon_h
    ));

    let tray_bytes = include_bytes!("../../../assets/tray_icon.png");
    let tray_img = match image::load_from_memory(tray_bytes) {
        Ok(i) => i.into_rgba8(),
        Err(e) => {
            log_step(&format!("run_app: Error cargando tray_bytes: {:?}", e));
            img.clone()
        }
    };
    let (tray_w, tray_h) = tray_img.dimensions();
    let tray_icon_data = match Icon::from_rgba(tray_img.into_raw(), tray_w, tray_h) {
        Ok(t) => t,
        Err(e) => {
            log_step(&format!("run_app: Error en Icon::from_rgba: {:?}", e));
            return Err(anyhow::anyhow!("TrayIcon error: {:?}", e));
        }
    };
    log_step("run_app: tray_icon_data creado OK");

    let window_icon = tao::window::Icon::from_rgba(img.into_raw(), icon_w, icon_h).ok();

    let start_minimized = std::env::args().any(|arg| arg == "--minimized");
    let mut window_builder = WindowBuilder::new()
        .with_title("SamuLibre - Suite de Seguridad Open Source")
        .with_inner_size(tao::dpi::LogicalSize::new(1060.0, 690.0))
        .with_min_inner_size(tao::dpi::LogicalSize::new(840.0, 560.0))
        .with_visible(!start_minimized)
        .with_decorations(true);

    if let Some(w_icon) = window_icon {
        window_builder = window_builder.with_window_icon(Some(w_icon));
    }

    log_step("run_app: Creando ventana...");
    let window = window_builder.build(&event_loop)?;
    log_step("run_app: Ventana creada OK");

    // 2. Construcción del Menú Nativo de la Bandeja (System Tray) con Muda
    log_step("run_app: Configurando TrayIcon y Menu...");
    let tray_menu = Menu::new();
    let item_show = MenuItem::new("Mostrar SamuLibre", true, None);
    let item_scan = MenuItem::new("Escaneo Rápido", true, None);
    let item_scan_full = MenuItem::new("Escaneo Completo", true, None);
    let item_update = MenuItem::new("Actualizar Firmas", true, None);

    let sep_pause = PredefinedMenuItem::separator();
    let item_pause_30m = MenuItem::new("Pausar protección (30 min)", true, None);
    let item_pause_1h = MenuItem::new("Pausar protección (1 hora)", true, None);
    let item_pause_24h = MenuItem::new("Pausar protección (24 horas)", true, None);
    let item_resume = MenuItem::new("Reanudar protección", true, None);

    let sep = PredefinedMenuItem::separator();
    let item_quit = MenuItem::new("Salir de SamuLibre (Requiere Admin)", true, None);

    let _ = tray_menu.append_items(&[
        &item_show,
        &item_scan,
        &item_scan_full,
        &item_update,
        &sep_pause,
        &item_pause_30m,
        &item_pause_1h,
        &item_pause_24h,
        &item_resume,
        &sep,
        &item_quit,
    ]);

    let show_id = item_show.id().clone();
    let scan_id = item_scan.id().clone();
    let scan_full_id = item_scan_full.id().clone();
    let update_id = item_update.id().clone();
    let pause_30m_id = item_pause_30m.id().clone();
    let pause_1h_id = item_pause_1h.id().clone();
    let pause_24h_id = item_pause_24h.id().clone();
    let resume_id = item_resume.id().clone();
    let quit_id = item_quit.id().clone();

    // Registrar icono residente en la barra de tareas al lado del reloj
    let _tray_icon_handle = TrayIconBuilder::new()
        .with_menu(Box::new(tray_menu))
        .with_tooltip("SamuLibre - Suite de Seguridad Open Source")
        .with_icon(tray_icon_data)
        .build()?;
    log_step("run_app: TrayIcon registrado OK");

    log_step("run_app: Spawneando hilo de tray...");
    // Hilo de escucha de eventos de la Bandeja y Menú contextual
    let proxy_tray = proxy.clone();
    std::thread::spawn(move || {
        let menu_channel = MenuEvent::receiver();
        let tray_channel = TrayIconEvent::receiver();

        loop {
            // Eventos del Menú Contextual (Clic derecho)
            if let Ok(event) = menu_channel.try_recv() {
                if event.id == show_id {
                    let _ = proxy_tray.send_event(CustomUserEvent::ShowWindow);
                } else if event.id == scan_id {
                    let _ = proxy_tray.send_event(CustomUserEvent::TriggerScan);
                } else if event.id == scan_full_id {
                    let _ = proxy_tray.send_event(CustomUserEvent::TriggerFullScan);
                } else if event.id == update_id {
                    let _ = proxy_tray.send_event(CustomUserEvent::TriggerUpdateSignatures);
                } else if event.id == pause_30m_id {
                    let _ = proxy_tray.send_event(CustomUserEvent::PauseProtection { duration_secs: 1800 });
                } else if event.id == pause_1h_id {
                    let _ = proxy_tray.send_event(CustomUserEvent::PauseProtection { duration_secs: 3600 });
                } else if event.id == pause_24h_id {
                    let _ = proxy_tray.send_event(CustomUserEvent::PauseProtection { duration_secs: 86400 });
                } else if event.id == resume_id {
                    let _ = proxy_tray.send_event(CustomUserEvent::ResumeProtection);
                } else if event.id == quit_id {
                    let _ = proxy_tray.send_event(CustomUserEvent::Quit);
                }
            }

            // Eventos de interacción directa con el icono (Solo Clic Izquierdo abre ventana; Clic Derecho mantiene el menÃº abierto)
            if let Ok(event) = tray_channel.try_recv() {
                match event {
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                    | TrayIconEvent::DoubleClick {
                        button: MouseButton::Left,
                        ..
                    } => {
                        let _ = proxy_tray.send_event(CustomUserEvent::ShowWindow);
                    }
                    _ => (),
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(40));
        }
    });
    log_step("run_app: Hilo de tray spawneado OK");

    let raw_html = if let Ok(disk_html) = fs::read_to_string("data/ui/index.html") {
        log_step("run_app: Cargando data/ui/index.html desde disco local");
        disk_html
    } else {
        include_str!("../../../data/ui/index.html").to_string()
    };
    const TAILWIND_JS: &str = include_str!("../../../data/ui/tailwindcss.min.js");
    let html_content = raw_html
        .replace(
            r#"<script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>"#,
            &format!("<script>{}</script>", TAILWIND_JS),
        )
        .replace(
            r#"<script src="tailwindcss.min.js"></script>"#,
            &format!("<script>{}</script>", TAILWIND_JS),
        );
    log_step("run_app: HTML template y Tailwind CSS offline embebidos OK");

    log_step("run_app: Creando WebViewBuilder con pool IPC asíncrono...");
    let (ipc_tx, ipc_rx) = std::sync::mpsc::channel::<IpcMessage>();
    let ipc_rx_shared = Arc::new(Mutex::new(ipc_rx));
    for _ in 0..4 {
        let rx_w = Arc::clone(&ipc_rx_shared);
        let core_w = Arc::clone(&core_for_ipc);
        let proxy_w = proxy.clone();
        std::thread::spawn(move || {
            loop {
                let msg_opt = {
                    let guard = match rx_w.lock() {
                        Ok(g) => g,
                        Err(_) => break,
                    };
                    guard.recv().ok()
                };
                match msg_opt {
                    Some(msg) => dispatch_ipc_message(msg, &core_w, &proxy_w),
                    None => break,
                }
            }
        });
    }

    let builder = WebViewBuilder::new()
        .with_html(&html_content)
        .with_ipc_handler(move |request| {
            let body = request.body();
            if let Ok(msg) = serde_json::from_str::<IpcMessage>(body) {
                if msg.action == "cancel_scan" {
                    IS_SCAN_CANCELLED.store(true, Ordering::SeqCst);
                    return;
                }
                let _ = ipc_tx.send(msg);
            }
        });

    fn dispatch_ipc_message(
        msg: IpcMessage,
        core_for_ipc: &Arc<Mutex<SamuLibreCore>>,
        proxy_for_ipc: &tao::event_loop::EventLoopProxy<CustomUserEvent>,
    ) {
                match msg.action.as_str() {
                    "start_real_scan" => {
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::TriggerScan);
                    }

                    "start_full_scan" => {
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::TriggerFullScan);
                    }

                    "update_signatures" => {
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::TriggerUpdateSignatures);
                    }

                    "browse_and_scan_files" => {
                        let proxy_browse = proxy_for_ipc.clone();
                        let core_browse = Arc::clone(&core_for_ipc);
                        std::thread::spawn(move || {
                            let paths = open_native_file_dialog();
                            if !paths.is_empty() {
                                if let Ok(c) = core_browse.lock() {
                                    let mut results = Vec::new();
                                    for p in paths {
                                        if let Ok(r) = c.scan_file_path(&p) {
                                            results.push(r);
                                        }
                                    }
                                    if results.len() == 1 {
                                        let _ = proxy_browse.send_event(CustomUserEvent::SingleScanResult { result: results.remove(0) });
                                    } else if !results.is_empty() {
                                        let _ = proxy_browse.send_event(CustomUserEvent::BatchScanResults { results });
                                    }
                                }
                            }
                        });
                    }

                    "browse_and_scan_folder" => {
                        let proxy_browse_folder = proxy_for_ipc.clone();
                        let core_browse_folder = Arc::clone(&core_for_ipc);
                        IS_SCAN_CANCELLED.store(false, Ordering::SeqCst);
                        std::thread::spawn(move || {
                            if let Some(folder) = open_native_folder_dialog() {
                                let scanner_arc = if let Ok(c) = core_browse_folder.lock() {
                                    if let Ok(s) = c.scanner.lock() {
                                        Arc::new(s.clone())
                                    } else {
                                        return;
                                    }
                                } else {
                                    return;
                                };

                                let _ = proxy_browse_folder.send_event(CustomUserEvent::ScanProgress {
                                    files_scanned: 0,
                                    total_files: 0,
                                    current_file: format!("Preparando análisis de carpeta ({} núcleos CPU)...", rayon::current_num_threads()),
                                    threats_found: 0,
                                    is_done: false,
                                });

                                let mut candidate_paths = Vec::new();
                                for entry in WalkDir::new(&folder)
                                    .max_depth(30)
                                    .into_iter()
                                    .filter_entry(|e| {
                                        let name = e.file_name().to_string_lossy();
                                        let path_str = e.path().to_string_lossy();
                                        !name.starts_with('.')
                                            && name != "node_modules"
                                            && name != "target"
                                            && name != "$Recycle.Bin"
                                            && !path_str.contains("Antivitus-SamuLibre")
                                            && !path_str.contains("quarantine")
                                            && !path_str.contains("threat_history.json")
                                            && !path_str.contains("exclusions.json")
                                    })
                                    .filter_map(|e| e.ok())
                                {
                                    if IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
                                        break;
                                    }
                                    if entry.file_type().is_file() {
                                        let p_str = entry.path().to_string_lossy();
                                        if p_str.contains("Antivitus-SamuLibre") 
                                            || p_str.contains("quarantine") 
                                            || p_str.contains("threat_history.json") 
                                            || p_str.ends_with(".quarantine") {
                                            continue;
                                        }
                                        candidate_paths.push(entry.into_path());
                                    }
                                }

                                let scan_start = std::time::Instant::now();
                                let (total_scanned, threats_found, infected_files) = scan_paths_parallel(candidate_paths, scanner_arc, proxy_browse_folder.clone());
                                let elapsed_ms = scan_start.elapsed().as_millis() as u64;

                                if !infected_files.is_empty() {
                                    let mut history = load_threat_history();
                                    for threat in &infected_files {
                                        if !history.iter().any(|h| h.file_path == threat.file_path && h.sha256 == threat.sha256 && h.action_taken == "Pendiente") {
                                            history.insert(0, threat.clone());
                                        }
                                    }
                                    save_threat_history(&history);
                                    let _ = proxy_browse_folder.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                                    trigger_vt_auto_verification_for_infected(infected_files.clone(), proxy_browse_folder.clone());
                                }

                                let _ = proxy_browse_folder.send_event(CustomUserEvent::ScanCompleted {
                                    files_scanned: total_scanned,
                                    threats_found,
                                    elapsed_ms,
                                    infected_files,
                                });

                                let _ = proxy_browse_folder.send_event(CustomUserEvent::ScanProgress {
                                    files_scanned: total_scanned,
                                    total_files: total_scanned,
                                    current_file: format!("Carpeta analizada: {} archivos verificados en {:.2}s.", total_scanned, elapsed_ms as f64 / 1000.0),
                                    threats_found,
                                    is_done: true,
                                });
                            }
                        });
                    }

                    "scan_custom_path" => {
                        if let Some(payload_str) = msg.payload {
                            let proxy_paths = proxy_for_ipc.clone();
                            let core_paths = Arc::clone(&core_for_ipc);
                            IS_SCAN_CANCELLED.store(false, Ordering::SeqCst);
                            std::thread::spawn(move || {
                                let mut paths_to_scan = Vec::new();
                                if let Ok(arr) = serde_json::from_str::<Vec<String>>(&payload_str) {
                                    paths_to_scan = arr.into_iter().map(PathBuf::from).collect();
                                } else {
                                    paths_to_scan.push(PathBuf::from(payload_str));
                                }

                                let scanner_arc = if let Ok(c) = core_paths.lock() {
                                    if let Ok(s) = c.scanner.lock() {
                                        Arc::new(s.clone())
                                    } else {
                                        return;
                                    }
                                } else {
                                    return;
                                };

                                let mut candidate_paths = Vec::new();
                                for path in paths_to_scan {
                                    if path.is_file() {
                                        candidate_paths.push(path);
                                    } else if path.is_dir() {
                                        for entry in WalkDir::new(&path)
                                            .max_depth(30)
                                            .into_iter()
                                            .filter_entry(|e| {
                                                let name = e.file_name().to_string_lossy();
                                                let path_str = e.path().to_string_lossy();
                                                !name.starts_with('.')
                                                    && name != "node_modules"
                                                    && name != "target"
                                                    && name != "$Recycle.Bin"
                                                    && !path_str.contains("Antivitus-SamuLibre")
                                                    && !path_str.contains("quarantine")
                                                    && !path_str.contains("threat_history.json")
                                                    && !path_str.contains("exclusions.json")
                                            })
                                            .filter_map(|e| e.ok())
                                        {
                                            if IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
                                                break;
                                            }
                                            if entry.file_type().is_file() {
                                                let p_str = entry.path().to_string_lossy();
                                                if p_str.contains("Antivitus-SamuLibre") 
                                                    || p_str.contains("quarantine") 
                                                    || p_str.contains("threat_history.json") 
                                                    || p_str.ends_with(".quarantine") {
                                                    continue;
                                                }
                                                candidate_paths.push(entry.into_path());
                                            }
                                        }
                                    }
                                }

                                let scan_start = std::time::Instant::now();
                                let (total_scanned, threats_found, infected_files) = scan_paths_parallel(candidate_paths, scanner_arc, proxy_paths.clone());
                                let elapsed_ms = scan_start.elapsed().as_millis() as u64;

                                if !infected_files.is_empty() {
                                    let mut history = load_threat_history();
                                    for threat in &infected_files {
                                        if !history.iter().any(|h| h.file_path == threat.file_path && h.sha256 == threat.sha256 && h.action_taken == "Pendiente") {
                                            history.insert(0, threat.clone());
                                        }
                                    }
                                    save_threat_history(&history);
                                    let _ = proxy_paths.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                                    trigger_vt_auto_verification_for_infected(infected_files.clone(), proxy_paths.clone());
                                }

                                let _ = proxy_paths.send_event(CustomUserEvent::ScanCompleted {
                                    files_scanned: total_scanned,
                                    threats_found,
                                    elapsed_ms,
                                    infected_files,
                                });

                                let _ = proxy_paths.send_event(CustomUserEvent::ScanProgress {
                                    files_scanned: total_scanned,
                                    total_files: total_scanned,
                                    current_file: format!("Ruta analizada: {} archivos verificados en {:.2}s.", total_scanned, elapsed_ms as f64 / 1000.0),
                                    threats_found,
                                    is_done: true,
                                });
                            });
                        }
                    }

                    "cancel_scan" => {
                        IS_SCAN_CANCELLED.store(true, Ordering::SeqCst);
                        IS_SCAN_IN_PROGRESS.store(false, Ordering::SeqCst);
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::ScanProgress {
                            files_scanned: 0,
                            total_files: 0,
                            current_file: "Análisis detenido por el usuario.".to_string(),
                            threats_found: 0,
                            is_done: true,
                        });
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                            title: "Análisis Detenido".to_string(),
                            details: "Cancelación solicitada por el usuario. Escaneo detenido inmediatamente.".to_string(),
                        });
                    }

                    "get_autostart_status" => {
                        let enabled = is_windows_autostart_enabled();
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::AutostartStatusLoaded { enabled });
                    }

                    "set_autostart" => {
                        let enable = msg.payload.map(|s| s == "true" || s == "1").unwrap_or(true);
                        let res = set_windows_autostart(enable);
                        match res {
                            Ok(()) => {
                                let enabled = is_windows_autostart_enabled();
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::AutostartStatusLoaded { enabled });
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: if enabled { "✔ Inicio con Windows Activado".to_string() } else { "Inicio con Windows Desactivado".to_string() },
                                    details: if enabled { "SamuLibre se iniciará automáticamente minimizado en la bandeja al arrancar Windows.".to_string() } else { "Se eliminó SamuLibre del inicio automático de Windows.".to_string() },
                                });
                            }
                            Err(err_msg) => {
                                let enabled = is_windows_autostart_enabled();
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::AutostartStatusLoaded { enabled });
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Acceso Denegado (Requiere Administrador)".to_string(),
                                    details: err_msg,
                                });
                            }
                        }
                    }

                    "get_threat_history" => {
                        let history = load_threat_history();
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                    }

                    "clear_threat_history" => {
                        save_threat_history(&[]);
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history: Vec::new() });
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                            title: "Historial Vaciado".to_string(),
                            details: "Se ha eliminado todo el registro del historial de amenazas.".to_string(),
                        });
                    }

                    "quarantine_threat_item" => {
                        if let Some(payload_str) = msg.payload {
                            #[derive(Deserialize)]
                            struct ThreatActionPayload {
                                id: String,
                                file_path: String,
                            }
                            let (threat_id, path_str) = if let Ok(data) = serde_json::from_str::<ThreatActionPayload>(&payload_str) {
                                (data.id, data.file_path)
                            } else {
                                (payload_str.clone(), payload_str)
                            };
                            let p = PathBuf::from(&path_str);
                            if let Ok(c) = core_for_ipc.lock() {
                                let res = c.isolate_file_manually(&p);
                                let mut history = load_threat_history();
                                let mut q_id_str = None;
                                if let Ok(rec) = &res {
                                    q_id_str = Some(rec.id.to_string());
                                }
                                for item in history.iter_mut() {
                                    if item.id == threat_id || item.file_path == path_str {
                                        item.action_taken = "En Cuarentena".to_string();
                                        item.quarantine_id = q_id_str.clone();
                                    }
                                }
                                save_threat_history(&history);
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                                let records = c.get_quarantined_records();
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::QuarantineListLoaded { records });
                                match res {
                                    Ok(rec) => {
                                        let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "✔ Amenaza en Cuarentena".to_string(),
                                            details: format!("'{}' cifrado con clave XOR y custodiado en la bóveda.", rec.original_path),
                                        });
                                    }
                                    Err(e) => {
                                        let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "Aviso de Cuarentena".to_string(),
                                            details: format!("Archivo registrado en historial (aviso: {}).", e),
                                        });
                                    }
                                }
                            }
                        }
                    }

                    "confirm_threat_item" => {
                        if let Some(payload_str) = msg.payload {
                            #[derive(Deserialize)]
                            struct ThreatActionPayload {
                                id: String,
                                file_path: String,
                            }
                            if let Ok(data) = serde_json::from_str::<ThreatActionPayload>(&payload_str) {
                                let mut history = load_threat_history();
                                let ledger_path = get_project_root().join("data").join("audit").join("detection_ledger.jsonl");
                                for item in history.iter_mut() {
                                    if item.id == data.id || (!data.file_path.is_empty() && item.file_path == data.file_path) {
                                        item.validation_status = samulibre_types::ValidationStatus::Confirmada;
                                        item.action_taken = if item.quarantine_id.is_some() {
                                            "Confirmada / En Cuarentena".to_string()
                                        } else {
                                            "Amenaza Confirmada".to_string()
                                        };
                                        let _ = samulibre_scanner::DetectionAuditLedger::append_entry(
                                            &ledger_path,
                                            "CONFIRM_THREAT",
                                            &item.sha256,
                                            &item.file_path,
                                            &item.threat_name,
                                            item.confidence_level.as_str(),
                                            item.calibrated_score,
                                            "Analyst",
                                            "Amenaza confirmada manualmente desde Centro de Análisis",
                                        );
                                    }
                                }
                                save_threat_history(&history);
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "✔ Amenaza Confirmada".to_string(),
                                    details: format!("Detección '{}' confirmada y registrada en el ledger criptográfico.", data.file_path),
                                });
                            }
                        }
                    }

                    "mark_false_positive_item" => {
                        if let Some(payload_str) = msg.payload {
                            #[derive(Deserialize)]
                            struct FpPayload {
                                id: String,
                                file_path: String,
                                reason: Option<String>,
                            }
                            if let Ok(data) = serde_json::from_str::<FpPayload>(&payload_str) {
                                let mut history = load_threat_history();
                                let root = get_project_root();
                                let ledger_path = root.join("data").join("audit").join("detection_ledger.jsonl");
                                let fp_path = root.join("data").join("audit").join("fp_feedback.json");
                                let reason = data.reason.unwrap_or_else(|| "Marcado como falso positivo por el analista".to_string());
                                for item in history.iter_mut() {
                                    if item.id == data.id || (!data.file_path.is_empty() && item.file_path == data.file_path) {
                                        item.validation_status = samulibre_types::ValidationStatus::FalsoPositivo;
                                        item.action_taken = "Falso Positivo (Auditado)".to_string();
                                        let _ = samulibre_scanner::FalsePositiveRegistry::record_fp(
                                            &fp_path,
                                            &item.sha256,
                                            &item.file_path,
                                            &item.threat_name,
                                            &reason,
                                        );
                                        let _ = samulibre_scanner::DetectionAuditLedger::append_entry(
                                            &ledger_path,
                                            "MARK_FALSE_POSITIVE",
                                            &item.sha256,
                                            &item.file_path,
                                            &item.threat_name,
                                            item.confidence_level.as_str(),
                                            item.calibrated_score,
                                            "Analyst",
                                            &reason,
                                        );
                                    }
                                }
                                save_threat_history(&history);
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "✔ Falso Positivo Registrado".to_string(),
                                    details: "Feedback guardado para refinamiento controlado de reglas (sin mutar reglas globales automáticamente).".to_string(),
                                });
                            }
                        }
                    }

                    "analyze_threat_deep" => {
                        if let Some(payload_str) = msg.payload {
                            #[derive(Deserialize)]
                            struct DeepPayload {
                                id: String,
                                file_path: String,
                            }
                            if let Ok(data) = serde_json::from_str::<DeepPayload>(&payload_str) {
                                let p = PathBuf::from(&data.file_path);
                                let mut history = load_threat_history();
                                let mut summary_msg = String::new();
                                if p.exists() {
                                    if let Ok(c) = core_for_ipc.lock() {
                                        if let Ok(res) = c.scan_file_path(&p) {
                                            for item in history.iter_mut() {
                                                if item.id == data.id || item.file_path == data.file_path {
                                                    item.validation_status = samulibre_types::ValidationStatus::EnAnalisis;
                                                    item.confidence_level = res.confidence_level;
                                                    item.calibrated_score = res.calibrated_score;
                                                    item.evidences = res.evidences.clone();
                                                    item.classification = res.classification.clone();
                                                    item.authenticode = res.authenticode.clone();
                                                }
                                            }
                                            summary_msg = format!(
                                                "Re-análisis completado: {} (Score={}/100, Evidencias={}).",
                                                res.classification,
                                                res.calibrated_score,
                                                res.evidences.len()
                                            );
                                        }
                                    }
                                } else {
                                    summary_msg = "El archivo ya no está en disco (posiblemente en cuarentena). Revise las evidencias almacenadas.".to_string();
                                }
                                save_threat_history(&history);
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "🔍 Análisis Adicional Completado".to_string(),
                                    details: summary_msg,
                                });
                            }
                        }
                    }

                    "create_specific_exclusion" => {
                        if let Some(payload_str) = msg.payload {
                            #[derive(Deserialize)]
                            struct ExclPayload {
                                id: String,
                                file_path: String,
                                sha256: String,
                                reason: Option<String>,
                            }
                            if let Ok(data) = serde_json::from_str::<ExclPayload>(&payload_str) {
                                let reason = data.reason.unwrap_or_else(|| "Exclusión específica anclada por SHA-256 desde Centro de Análisis".to_string());
                                if let Ok(c) = core_for_ipc.lock() {
                                    let ex = samulibre_types::SecurityException {
                                        id: uuid::Uuid::new_v4().to_string(),
                                        name: format!("SHA256 Pinned: {}", data.file_path),
                                        target: data.file_path.clone(),
                                        exception_type: samulibre_types::ExceptionType::File {
                                            sha256_pinned: if data.sha256.is_empty() { None } else { Some(data.sha256.clone()) },
                                        },
                                        scope: samulibre_types::ExceptionScope::default(),
                                        reason_category: samulibre_types::ReasonCategory::InvestigatedFalsePositive,
                                        justification: reason.clone(),
                                        risk_level: samulibre_types::ExceptionRiskLevel::Low,
                                        created_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                                        expires_at: None,
                                        is_active: true,
                                        audit_history: vec![samulibre_types::ExceptionAuditEntry {
                                            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                                            action: "Creada".to_string(),
                                            details: format!("Exclusión granular SHA-256: {}", data.sha256),
                                        }],
                                    };
                                    let _ = c.add_security_exception(ex);
                                }
                                let mut history = load_threat_history();
                                let ledger_path = get_project_root().join("data").join("audit").join("detection_ledger.jsonl");
                                for item in history.iter_mut() {
                                    if item.id == data.id || (!data.sha256.is_empty() && item.sha256 == data.sha256) {
                                        item.action_taken = "Excluido (SHA-256)".to_string();
                                        let _ = samulibre_scanner::DetectionAuditLedger::append_entry(
                                            &ledger_path,
                                            "EXCLUSION",
                                            &item.sha256,
                                            &item.file_path,
                                            &item.threat_name,
                                            item.confidence_level.as_str(),
                                            item.calibrated_score,
                                            "Analyst",
                                            &reason,
                                        );
                                    }
                                }
                                save_threat_history(&history);
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "🔑 Exclusión Específica Creada".to_string(),
                                    details: format!("Exclusión anclada por SHA-256 creada para '{}'. No afecta otros archivos.", data.file_path),
                                });
                            }
                        }
                    }

                    "vt_get_status" => {
                        let data_dir = get_project_root().join("data");
                        let has_api_key = samulibre_scanner::VtSecureKeyBackend::has_api_key(&data_dir);
                        let policy = samulibre_scanner::VirusTotalVerifier::load_policy(&data_dir);
                        let quota = samulibre_scanner::VtQuotaState::load(&data_dir.join("vt_quota.json"));
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::VtStatusLoaded {
                            has_api_key,
                            policy,
                            quota,
                        });
                    }

                    "vt_set_api_key_backend" => {
                        if let Some(payload_str) = msg.payload {
                            #[derive(Deserialize)]
                            struct KeyPayload {
                                api_key: String,
                            }
                            if let Ok(data) = serde_json::from_str::<KeyPayload>(&payload_str) {
                                let data_dir = get_project_root().join("data");
                                let res = samulibre_scanner::VtSecureKeyBackend::save_backend_key(&data_dir, &data.api_key);
                                let has_api_key = samulibre_scanner::VtSecureKeyBackend::has_api_key(&data_dir);
                                let policy = samulibre_scanner::VirusTotalVerifier::load_policy(&data_dir);
                                let quota = samulibre_scanner::VtQuotaState::load(&data_dir.join("vt_quota.json"));
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::VtStatusLoaded {
                                    has_api_key,
                                    policy,
                                    quota,
                                });
                                let msg_txt = match res {
                                    Ok(_) => if has_api_key {
                                        "API Key guardada exclusivamente en el backend seguro (no expuesta al cliente JS)."
                                    } else {
                                        "API Key eliminada del backend seguro."
                                    },
                                    Err(_) => "No se pudo guardar la API Key en el backend seguro.",
                                };
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "🔐 Backend Seguro VirusTotal".to_string(),
                                    details: msg_txt.to_string(),
                                });
                            }
                        }
                    }

                    "vt_set_policy" => {
                        if let Some(payload_str) = msg.payload {
                            if let Ok(policy) = serde_json::from_str::<samulibre_scanner::VtVerificationPolicy>(&payload_str) {
                                let data_dir = get_project_root().join("data");
                                samulibre_scanner::VirusTotalVerifier::save_policy(&data_dir, &policy);
                                let has_api_key = samulibre_scanner::VtSecureKeyBackend::has_api_key(&data_dir);
                                let quota = samulibre_scanner::VtQuotaState::load(&data_dir.join("vt_quota.json"));
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::VtStatusLoaded {
                                    has_api_key,
                                    policy,
                                    quota,
                                });
                            }
                        }
                    }

                    "vt_verify_threat" => {
                        if let Some(payload_str) = msg.payload {
                            #[derive(Deserialize)]
                            struct VtVerifyPayload {
                                id: String,
                                file_path: String,
                                allow_upload: Option<bool>,
                            }
                            if let Ok(data) = serde_json::from_str::<VtVerifyPayload>(&payload_str) {
                                let proxy_vt = proxy_for_ipc.clone();
                                std::thread::spawn(move || {
                                    let history = load_threat_history();
                                    let found_rec = history
                                        .into_iter()
                                        .find(|h| (!data.id.is_empty() && h.id == data.id) || (!data.file_path.is_empty() && h.file_path == data.file_path));
                                    let rec = found_rec.unwrap_or_else(|| samulibre_types::ThreatRecord {
                                        id: data.id.clone(),
                                        file_path: data.file_path.clone(),
                                        threat_name: "Verificación Manual".to_string(),
                                        engine: "SamuLibre".to_string(),
                                        ..Default::default()
                                    });
                                    let data_dir = get_project_root().join("data");
                                    let policy = samulibre_scanner::VirusTotalVerifier::load_policy(&data_dir);
                                    let verifier = samulibre_scanner::VirusTotalVerifier::new(&data_dir, policy.clone());
                                    let report = verifier.verify_threat_record(&rec, data.allow_upload.unwrap_or(false));
                                    let _ = proxy_vt.send_event(CustomUserEvent::VtVerificationLoaded { report });
                                    let has_api_key = samulibre_scanner::VtSecureKeyBackend::has_api_key(&data_dir);
                                    let quota = samulibre_scanner::VtQuotaState::load(&data_dir.join("vt_quota.json"));
                                    let _ = proxy_vt.send_event(CustomUserEvent::VtStatusLoaded {
                                        has_api_key,
                                        policy,
                                        quota,
                                    });
                                });
                            }
                        }
                    }

                    "delete_threat_item" => {
                        if let Some(payload_str) = msg.payload {
                            #[derive(Deserialize)]
                            struct ThreatActionPayload {
                                id: String,
                                file_path: String,
                            }
                            let (threat_id, path_str) = if let Ok(data) = serde_json::from_str::<ThreatActionPayload>(&payload_str) {
                                (data.id, data.file_path)
                            } else {
                                (payload_str.clone(), payload_str)
                            };
                            let p = PathBuf::from(&path_str);
                            let del_res = if p.exists() {
                                fs::remove_file(&p)
                            } else {
                                Ok(())
                            };
                            let mut history = load_threat_history();
                            for item in history.iter_mut() {
                                if item.id == threat_id || item.file_path == path_str {
                                    item.action_taken = "Eliminado".to_string();
                                }
                            }
                            save_threat_history(&history);
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                            match del_res {
                                Ok(_) => {
                                    let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                        title: "✔ Amenaza Eliminada Permanentemente".to_string(),
                                        details: format!("'{}' destruido de forma segura del sistema.", path_str),
                                    });
                                }
                                Err(e) => {
                                    let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                        title: "Error al Eliminar Archivo".to_string(),
                                        details: format!("No se pudo eliminar '{}': {}", path_str, e),
                                    });
                                }
                            }
                        }
                    }

                    "quarantine_all_threats" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let mut history = load_threat_history();
                            let mut count = 0;
                            for item in history.iter_mut() {
                                if item.action_taken == "Pendiente" {
                                    let p = PathBuf::from(&item.file_path);
                                    if let Ok(rec) = c.isolate_file_manually(&p) {
                                        item.action_taken = "En Cuarentena".to_string();
                                        item.quarantine_id = Some(rec.id.to_string());
                                        count += 1;
                                    }
                                }
                            }
                            save_threat_history(&history);
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                            let records = c.get_quarantined_records();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::QuarantineListLoaded { records });
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                title: "✔ Amenazas Aisladas en Lote".to_string(),
                                details: format!("Se han movido {} archivo(s) infectados a la bóveda de cuarentena cifrada.", count),
                            });
                        }
                    }

                    "delete_all_threats" => {
                        let mut history = load_threat_history();
                        let mut count = 0;
                        for item in history.iter_mut() {
                            if item.action_taken == "Pendiente" {
                                let p = PathBuf::from(&item.file_path);
                                if p.exists() {
                                    let _ = fs::remove_file(&p);
                                }
                                item.action_taken = "Eliminado".to_string();
                                count += 1;
                            }
                        }
                        save_threat_history(&history);
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                            title: "✔ Amenazas Eliminadas en Lote".to_string(),
                            details: format!("Se han eliminado permanentemente {} archivo(s) maliciosos del sistema.", count),
                        });
                    }

                    "whitelist_threat_item" => {
                        if let Some(payload_str) = msg.payload {
                            #[derive(Deserialize)]
                            struct ThreatActionPayload {
                                id: String,
                                file_path: String,
                            }
                            let (threat_id, path_str) = if let Ok(data) = serde_json::from_str::<ThreatActionPayload>(&payload_str) {
                                (data.id, data.file_path)
                            } else {
                                (payload_str.clone(), payload_str)
                            };

                            // Añadir a lista de exclusiones ancladas por hash criptográfico SHA-256
                            let p = PathBuf::from(&path_str);
                            if let Ok(c) = core_for_ipc.lock() {
                                if let Ok(mut s) = c.scanner.lock() {
                                    s.add_pinned_exclusion(&p, "Excluido por usuario desde interfaz gráfica");
                                }
                            }

                            let mut history = load_threat_history();
                            for item in history.iter_mut() {
                                if item.id == threat_id || item.file_path == path_str {
                                    item.action_taken = "Excluido".to_string();
                                }
                            }
                            save_threat_history(&history);
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                title: "✔ Archivo Excluido con Anclaje SHA-256".to_string(),
                                details: format!("'{}' protegido y excluido por huella criptográfica SHA-256.", path_str),
                            });
                        }
                    }

                    "ignore_threat_item" => {
                        if let Some(threat_id) = msg.payload {
                            let mut history = load_threat_history();
                            for item in history.iter_mut() {
                                if item.id == threat_id {
                                    item.action_taken = "Ignorado".to_string();
                                }
                            }
                            save_threat_history(&history);
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                        }
                    }

                    "restore_quarantined_item" => {
                        if let Some(payload_str) = msg.payload {
                            #[derive(Deserialize)]
                            struct RestorePayload {
                                quarantine_id: String,
                                threat_id: Option<String>,
                            }
                            let (qid_str, threat_id_opt) = if let Ok(data) = serde_json::from_str::<RestorePayload>(&payload_str) {
                                (data.quarantine_id, data.threat_id)
                            } else {
                                (payload_str.clone(), None)
                            };
                            if let Ok(qid) = uuid::Uuid::parse_str(&qid_str) {
                                if let Ok(c) = core_for_ipc.lock() {
                                    match c.restore_quarantined_record(qid) {
                                        Ok(original_path) => {
                                            let mut history = load_threat_history();
                                            for item in history.iter_mut() {
                                                if item.quarantine_id.as_deref() == Some(&qid_str) || threat_id_opt.as_deref() == Some(&item.id) {
                                                    item.action_taken = "Restaurado".to_string();
                                                }
                                            }
                                            save_threat_history(&history);
                                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
                                            let records = c.get_quarantined_records();
                                            let _ = proxy_for_ipc.send_event(CustomUserEvent::QuarantineListLoaded { records });
                                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                                title: "✔ Archivo Restaurado".to_string(),
                                                details: format!("'{}' restaurado con éxito desde la cuarentena.", original_path),
                                            });
                                        }
                                        Err(e) => {
                                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                                title: "Error al Restaurar".to_string(),
                                                details: format!("No se pudo restaurar el archivo: {}", e),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }

                    "scan_sample_test" => {
                        let sample_type = msg.payload.unwrap_or_else(|| "EICAR".to_string());
                        if let Ok(c) = core_for_ipc.lock() {
                            let res = c.scan_sample_test(&sample_type);
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::SingleScanResult { result: res });
                        }
                    }

                    "get_quarantine_records" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let records = c.get_quarantined_records();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::QuarantineListLoaded { records });
                        }
                    }

                    "purge_quarantine_record" => {
                        if let Some(id_str) = msg.payload {
                            if let Ok(uuid) = uuid::Uuid::parse_str(&id_str) {
                                if let Ok(c) = core_for_ipc.lock() {
                                    let _ = c.purge_quarantined_record(uuid);
                                    let records = c.get_quarantined_records();
                                    let _ = proxy_for_ipc.send_event(CustomUserEvent::QuarantineListLoaded { records });
                                }
                            }
                        }
                    }

                    "isolate_file_manually" => {
                        if let Some(path_str) = msg.payload {
                            let p = PathBuf::from(&path_str);
                            if let Ok(c) = core_for_ipc.lock() {
                                match c.isolate_file_manually(&p) {
                                    Ok(rec) => {
                                        let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "✔ Amenaza Aislada en Cuarentena".to_string(),
                                            details: format!("'{}' cifrado con clave XOR y custodiado en la bóveda.", rec.original_path),
                                        });
                                        let records = c.get_quarantined_records();
                                        let _ = proxy_for_ipc.send_event(CustomUserEvent::QuarantineListLoaded { records });
                                    }
                                    Err(e) => {
                                        let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "Error de Aislamiento".to_string(),
                                            details: format!("No se pudo aislar el archivo: {}", e),
                                        });
                                    }
                                }
                            }
                        }
                    }

                    "generate_test_threat" | "trigger_on_access_lab" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            match c.execute_on_access_lab_test() {
                                Ok((log_msg, quarantined)) => {
                                    let _ = proxy_for_ipc.send_event(CustomUserEvent::OnAccessLabCompleted {
                                        log: log_msg,
                                        quarantined,
                                    });
                                    let records = c.get_quarantined_records();
                                    let _ = proxy_for_ipc.send_event(CustomUserEvent::QuarantineListLoaded { records });
                                }
                                Err(e) => {
                                    let _ = proxy_for_ipc.send_event(CustomUserEvent::OnAccessLabCompleted {
                                        log: format!("Error en laboratorio On-Access: {}", e),
                                        quarantined: None,
                                    });
                                }
                            }
                        }
                    }

                    "get_status" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let status = c.get_status();
                            info!("GUI solicitó estado: {:?}", status);
                        }
                    }

                    "get_patch_rules" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let rules = c.get_patch_rules();
                            let os_info = c.get_os_info();
                            let sentinel_status = Some(c.get_sentinel_status());
                            let kb_monitor_status = Some(c.get_kb_monitor_status());
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
                        }
                    }

                    "reaudit_so" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let _ = c.reaudit_vulnerabilities();
                            let rules = c.get_patch_rules();
                            let os_info = c.get_os_info();
                            let sentinel_status = Some(c.get_sentinel_status());
                            let kb_monitor_status = Some(c.get_kb_monitor_status());
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
                        }
                    }

                    "toggle_virtual_patch" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let (cve, enable) = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&payload_str) {
                            (
                                parsed["cve"].as_str().unwrap_or("").to_string(),
                                parsed["enable"].as_bool().unwrap_or(true),
                            )
                        } else if let Some((c, e)) = payload_str.split_once('|') {
                            (c.to_string(), e == "true" || e == "1")
                        } else {
                            (payload_str, true)
                        };

                        log_step(&format!("IPC: toggle_virtual_patch para {} (enable={})", cve, enable));
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let _ = c.toggle_virtual_patch(&cve, enable);
                                let rules = c.get_patch_rules();
                                let os_info = c.get_os_info();
                                let sentinel_status = Some(c.get_sentinel_status());
                                let kb_monitor_status = Some(c.get_kb_monitor_status());
                                let _ = proxy_cloned.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
                            }
                        });
                    }

                    "dismiss_patch_rule" => {
                        let cve = msg.payload.unwrap_or_default().trim().to_string();
                        log_step(&format!("IPC: dismiss_patch_rule para {}", cve));
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let _ = c.dismiss_patch_rule(&cve);
                                let rules = c.get_patch_rules();
                                let os_info = c.get_os_info();
                                let sentinel_status = Some(c.get_sentinel_status());
                                let kb_monitor_status = Some(c.get_kb_monitor_status());
                                let _ = proxy_cloned.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
                            }
                        });
                    }

                    "set_sentinel_auto_patch" => {
                        let enable = msg.payload.map(|p| p == "true" || p == "1").unwrap_or(true);
                        log_step(&format!("IPC: set_sentinel_auto_patch: {}", enable));
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                c.set_sentinel_auto_patch(enable);
                                let rules = c.get_patch_rules();
                                let os_info = c.get_os_info();
                                let sentinel_status = Some(c.get_sentinel_status());
                                let kb_monitor_status = Some(c.get_kb_monitor_status());
                                let _ = proxy_cloned.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
                            }
                        });
                    }

                    "simulate_kb" => {
                        let kb = msg.payload.unwrap_or_else(|| "KB5041585".to_string());
                        if let Ok(c) = core_for_ipc.lock() {
                            if let Ok(mut patcher) = c.patcher.lock() {
                                let mut kbs = patcher.get_installed_kbs();
                                kbs.insert(kb.clone());
                                let _ = patcher.check_and_deactivate_obsolete_patches(Some(kbs));
                                info!("GUI simuló instalaciÃ³n oficial de {}", kb);
                            }
                            let rules = c.get_patch_rules();
                            let os_info = c.get_os_info();
                            let sentinel_status = Some(c.get_sentinel_status());
                            let kb_monitor_status = Some(c.get_kb_monitor_status());
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
                        }
                    }

                    "get_kb_monitor_status" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let rules = c.get_patch_rules();
                            let os_info = c.get_os_info();
                            let sentinel_status = Some(c.get_sentinel_status());
                            let kb_monitor_status = Some(c.get_kb_monitor_status());
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
                        }
                    }

                    "run_daily_kb_check" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let (new_kbs, _) = c.run_daily_kb_verification();
                                let rules = c.get_patch_rules();
                                let os_info = c.get_os_info();
                                let sentinel_status = Some(c.get_sentinel_status());
                                let kb_monitor_status = Some(c.get_kb_monitor_status());
                                let _ = proxy_cloned.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
                                if new_kbs > 0 {
                                    let title = "??? Monitor Diario de KBs".to_string();
                                    let details = format!("Se detectaron {} nuevas actualizaciones de seguridad en el cat?logo.", new_kbs);
                                    let _ = proxy_cloned.send_event(CustomUserEvent::RealTimeAlert { title, details });
                                }
                            }
                        });
                    }

                    "run_ai_kb_audit" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let results = c.run_ai_kb_audit_cycle();
                                let rules = c.get_patch_rules();
                                let os_info = c.get_os_info();
                                let sentinel_status = Some(c.get_sentinel_status());
                                let kb_monitor_status = Some(c.get_kb_monitor_status());
                                let _ = proxy_cloned.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
                                if let Some(first) = results.first() {
                                    let _ = proxy_cloned.send_event(CustomUserEvent::KbAnalysisResultLoaded { result: first.clone() });
                                }
                            }
                        });
                    }

                    "analyze_raw_kb" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            #[derive(serde::Deserialize)]
                            struct RawKbReq {
                                kb_id: String,
                                title: Option<String>,
                                description: Option<String>,
                            }
                            if let Ok(req) = serde_json::from_str::<RawKbReq>(&payload_str) {
                                if let Ok(c) = core_cloned.lock() {
                                    let title = req.title.unwrap_or_else(|| format!("Actualización {}", req.kb_id));
                                    let desc = req.description.unwrap_or_else(|| "Análisis técnico de seguridad solicitado".to_string());
                                    if let Ok(res) = c.analyze_raw_kb(&req.kb_id, &title, &desc) {
                                        let _ = proxy_cloned.send_event(CustomUserEvent::KbAnalysisResultLoaded { result: res });
                                        let rules = c.get_patch_rules();
                                        let os_info = c.get_os_info();
                                        let sentinel_status = Some(c.get_sentinel_status());
                                        let kb_monitor_status = Some(c.get_kb_monitor_status());
                                        let _ = proxy_cloned.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
                                    }
                                }
                            }
                        });
                    }

                    "set_ai_autopilot" => {
                        let enable = msg.payload.map(|p| p == "true" || p == "1").unwrap_or(true);
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                c.set_ai_autopilot(enable);
                                let rules = c.get_patch_rules();
                                let os_info = c.get_os_info();
                                let sentinel_status = Some(c.get_sentinel_status());
                                let kb_monitor_status = Some(c.get_kb_monitor_status());
                                let _ = proxy_cloned.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
                            }
                        });
                    }

                    "deploy_canaries" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            if let Ok(mut shield) = c.shield.lock() {
                                let _ = shield.deploy_canaries();
                                info!("GUI desplegó canarios seÃ±uelo anti-ransomware");
                            }
                            let status = c.get_shield_status();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ShieldStatusUpdated { status });
                        }
                    }

                    "get_shield_status" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let status = c.get_shield_status();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ShieldStatusUpdated { status });
                        }
                    }

                    "toggle_lsass_protection" => {
                        let enabled = msg.payload.as_deref() == Some("true");
                        if let Ok(c) = core_for_ipc.lock() {
                            let _ = c.toggle_lsass_protection(enabled);
                            let status = c.get_shield_status();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ShieldStatusUpdated { status });
                        }
                    }

                    "toggle_cookie_shield" => {
                        let enabled = msg.payload.as_deref() == Some("true");
                        if let Ok(c) = core_for_ipc.lock() {
                            let _ = c.toggle_cookie_shield(enabled);
                            let status = c.get_shield_status();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ShieldStatusUpdated { status });
                        }
                    }

                    "get_vpn_info" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let state = c.get_vpn_state();
                            let countries = c.get_vpn_countries();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::VpnStateUpdated { state, countries });
                        }
                    }

                    "connect_vpn" => {
                        let (country_code, double_encryption) = if let Some(ref p) = msg.payload {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(p) {
                                let code = val.get("country_code").and_then(|v| v.as_str()).unwrap_or("CH").to_string();
                                let double_enc = val.get("double_encryption").and_then(|v| v.as_bool()).unwrap_or(false);
                                (code, double_enc)
                            } else if p.contains('|') {
                                let parts: Vec<&str> = p.split('|').collect();
                                (parts[0].to_string(), parts.get(1) == Some(&"double"))
                            } else {
                                (p.clone(), false)
                            }
                        } else {
                            ("CH".to_string(), false)
                        };
                        log_step(&format!("IPC: connect_vpn recibido para país: {} (Doble Cifrado: {})", country_code, double_encryption));
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                match c.connect_vpn_ext(&country_code, true, double_encryption) {
                                    Ok(res_state) => {
                                        log_step(&format!("connect_vpn completado OK. IP: {:?}", res_state.assigned_ip));
                                    }
                                    Err(e) => {
                                        log_step(&format!("connect_vpn FALLÓ: {:?}", e));
                                    }
                                }
                                let state = c.get_vpn_state();
                                let countries = c.get_vpn_countries();
                                let _ = proxy_cloned.send_event(CustomUserEvent::VpnStateUpdated { state, countries });
                            } else {
                                log_step("connect_vpn: No se pudo obtener lock de Core");
                            }
                        });
                    }

                    "disconnect_vpn" => {
                        log_step("IPC: disconnect_vpn recibido");
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                match c.disconnect_vpn() {
                                    Ok(_) => log_step("disconnect_vpn completado OK"),
                                    Err(e) => log_step(&format!("disconnect_vpn FALLÓ: {:?}", e)),
                                }
                                let state = c.get_vpn_state();
                                let countries = c.get_vpn_countries();
                                let _ = proxy_cloned.send_event(CustomUserEvent::VpnStateUpdated { state, countries });
                            } else {
                                log_step("disconnect_vpn: No se pudo obtener lock de Core");
                            }
                        });
                    }

                    "reset_network" => {
                        log_step("IPC: reset_network recibido");
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                match c.reset_vpn_network() {
                                    Ok(_) => log_step("reset_vpn_network completado OK"),
                                    Err(e) => log_step(&format!("reset_vpn_network FALLÓ: {:?}", e)),
                                }
                                let state = c.get_vpn_state();
                                let countries = c.get_vpn_countries();
                                let _ = proxy_cloned.send_event(CustomUserEvent::VpnStateUpdated { state, countries });
                            } else {
                                let _ = samulibre_vpn::reset_system_network_proxy();
                                log_step("reset_network: Reseteado proxy directamente");
                            }
                        });
                    }

                    "refresh_vpn_pings" => {
                        log_step("IPC: refresh_vpn_pings recibido");
                        let proxy_pings = proxy_for_ipc.clone();
                        let core_pings = Arc::clone(&core_for_ipc);
                        std::thread::spawn(move || {
                            if let Ok(c) = core_pings.lock() {
                                let latencies = c.refresh_vpn_latencies();
                                let tunnel_ping = c.get_active_vpn_tunnel_latency();
                                let _ = proxy_pings.send_event(CustomUserEvent::VpnLatenciesUpdated {
                                    latencies,
                                    tunnel_ping,
                                });
                            }
                        });
                    }

                    "get_update_history" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let entries = c.get_signature_update_history();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::UpdateHistoryLoaded { entries });
                        }
                    }

                    "get_signatures_catalog" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            let val: serde_json::Value = serde_json::from_str(&payload_str).unwrap_or_default();
                            let kind = val["kind"].as_str().unwrap_or("ALL");
                            let status_filter = val["status_filter"].as_str().unwrap_or("PRODUCCION");
                            let query = val["query"].as_str().unwrap_or("");
                            let page = val["page"].as_u64().unwrap_or(0) as usize;
                            let sig_dir = get_project_root().join("data").join("signatures");
                            let page_resp = samulibre_scanner::query_signatures_from_intel_db(
                                &sig_dir,
                                kind,
                                status_filter,
                                query,
                                page,
                                50,
                            )
                            .unwrap_or_else(|| {
                                let catalog = samulibre_scanner::load_signatures_catalog_from_disk(&sig_dir);
                                samulibre_scanner::query_signatures_catalog(&catalog, kind, query, page, 50)
                            });
                            log_step(&format!(
                                "IPC: get_signatures_catalog ok (sha256={}, yara={}, c2={}, filtered={})",
                                page_resp.summary.sha256_hashes,
                                page_resp.summary.yara_rules,
                                page_resp.summary.c2_ips,
                                page_resp.total_filtered
                            ));
                            let catalog_json = serde_json::to_string(&page_resp)
                                .unwrap_or_else(|_| "{}".to_string());
                            let _ = proxy_cloned.send_event(CustomUserEvent::SignaturesCatalogLoaded { catalog_json });
                        });
                    }

                    "get_intel_keys_status" => {
                        let key_file = get_project_root().join("data").join("secure").join("intel_keys.json");
                        let status = samulibre_intel::ThreatFeedConnectors::get_intel_keys_status(&key_file);
                        let status_json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::IntelKeysStatusLoaded { status_json });
                    }

                    "save_intel_keys" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            let val: serde_json::Value = serde_json::from_str(&payload_str).unwrap_or_default();
                            let abusech = val["abusech_auth_key"].as_str();
                            let otx = val["otx_api_key"].as_str();
                            let sync_now = val["sync_now"].as_bool().unwrap_or(true);
                            let root = get_project_root();
                            let key_file = root.join("data").join("secure").join("intel_keys.json");
                            match samulibre_intel::ThreatFeedConnectors::save_intel_keys(&key_file, abusech, otx) {
                                Ok(status) => {
                                    log_step(&format!(
                                        "IPC: save_intel_keys ok (abusech={}, otx={})",
                                        status.abusech_configured, status.otx_configured
                                    ));
                                    let status_json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
                                    let _ = proxy_cloned.send_event(CustomUserEvent::IntelKeysStatusLoaded { status_json });
                                    if sync_now {
                                        let db_path = root.join("data").join("intel").join("samulibre_intel.db");
                                        let reports = samulibre_intel::ThreatFeedConnectors::sync_all_feeds(&db_path, &key_file, true)
                                            .unwrap_or_default();
                                        let reports_json = serde_json::to_string(&reports).unwrap_or_else(|_| "[]".to_string());
                                        let _ = proxy_cloned.send_event(CustomUserEvent::IntelFeedsSyncCompleted { reports_json });
                                        let sig_dir = root.join("data").join("signatures");
                                        if let Some(page_resp) = samulibre_scanner::query_signatures_from_intel_db(
                                            &sig_dir, "ALL", "PRODUCCION", "", 0, 50,
                                        ) {
                                            let catalog_json = serde_json::to_string(&page_resp).unwrap_or_else(|_| "{}".to_string());
                                            let _ = proxy_cloned.send_event(CustomUserEvent::SignaturesCatalogLoaded { catalog_json });
                                        }
                                    }
                                }
                                Err(e) => {
                                    log_step(&format!("IPC: save_intel_keys error: {:?}", e));
                                    let err_json = serde_json::json!({ "error": e.to_string() }).to_string();
                                    let _ = proxy_cloned.send_event(CustomUserEvent::IntelKeysStatusLoaded { status_json: err_json });
                                }
                            }
                        });
                    }

                    "sync_intel_feeds" => {
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            let root = get_project_root();
                            let key_file = root.join("data").join("secure").join("intel_keys.json");
                            let db_path = root.join("data").join("intel").join("samulibre_intel.db");
                            let reports = samulibre_intel::ThreatFeedConnectors::sync_all_feeds(&db_path, &key_file, true)
                                .unwrap_or_default();
                            let reports_json = serde_json::to_string(&reports).unwrap_or_else(|_| "[]".to_string());
                            let _ = proxy_cloned.send_event(CustomUserEvent::IntelFeedsSyncCompleted { reports_json });
                            let sig_dir = root.join("data").join("signatures");
                            if let Some(page_resp) = samulibre_scanner::query_signatures_from_intel_db(
                                &sig_dir, "ALL", "PRODUCCION", "", 0, 50,
                            ) {
                                let catalog_json = serde_json::to_string(&page_resp).unwrap_or_else(|_| "{}".to_string());
                                let _ = proxy_cloned.send_event(CustomUserEvent::SignaturesCatalogLoaded { catalog_json });
                            }
                        });
                    }

                    "run_internal_audit" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let report = c.run_internal_security_audit();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::AuditReportLoaded { report });
                        }
                    }

                    "get_persistence_entries" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let entries = c.get_persistence_entries();
                                let _ = proxy_cloned.send_event(CustomUserEvent::PersistenceListLoaded { entries });
                            }
                        });
                    }

                    "toggle_persistence" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let (id, enable) = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&payload_str) {
                            (
                                parsed["id"].as_str().unwrap_or("").to_string(),
                                parsed["enable"].as_bool().unwrap_or(true),
                            )
                        } else if let Some((i, e)) = payload_str.split_once('|') {
                            (i.to_string(), e == "true" || e == "1")
                        } else {
                            (payload_str, true)
                        };

                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let _ = c.toggle_persistence_entry(&id, enable);
                                let entries = c.get_persistence_entries();
                                let _ = proxy_cloned.send_event(CustomUserEvent::PersistenceListLoaded { entries });
                            }
                        });
                    }

                    "get_network_sockets" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let sockets = c.get_network_sockets();
                                let _ = proxy_cloned.send_event(CustomUserEvent::NetworkSocketsLoaded { sockets });
                            }
                        });
                    }

                    "nd_get_state" => {
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            let nd_arc = get_netdefense_engine(&get_project_root().join("data"));
                            if let Ok(mut nd) = nd_arc.lock() {
                                let payload_json = build_netdefense_state_json(&mut nd);
                                let _ = proxy_cloned.send_event(CustomUserEvent::NetDefenseStateLoaded { payload_json });
                            }
                        });
                    }

                    "nd_connection_action" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&payload_str) {
                                let action_kind = val["action_kind"].as_str().unwrap_or("block");
                                let app_name = val["app_name"].as_str().unwrap_or("unknown").to_string();
                                let app_path = val["app_path"]
                                    .as_str()
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty());
                                let remote_ip = val["remote_ip"]
                                    .as_str()
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty());
                                let remote_port = val["remote_port"].as_u64().map(|p| p as u16);

                                let nd_arc = get_netdefense_engine(&get_project_root().join("data"));
                                if let Ok(mut nd) = nd_arc.lock() {
                                    let rule_action = if action_kind == "allow" {
                                        samulibre_netdefense::RuleAction::Allow
                                    } else {
                                        samulibre_netdefense::RuleAction::Block
                                    };
                                    let scope = if action_kind == "temporary" {
                                        samulibre_netdefense::RuleScope::Temporary
                                    } else {
                                        samulibre_netdefense::RuleScope::Permanent
                                    };
                                    let rule = samulibre_netdefense::FirewallRule {
                                        id: uuid::Uuid::new_v4(),
                                        name: format!("Monitor_{}_{}", action_kind, app_name),
                                        app_path: app_path.clone(),
                                        app_hash_sha256: None,
                                        remote_ip: remote_ip.filter(|ip| ip != "0.0.0.0" && ip != "::"),
                                        remote_port: remote_port.filter(|&p| p > 0),
                                        local_port: None,
                                        protocol: samulibre_netdefense::NetProtocol::Any,
                                        direction: samulibre_netdefense::TrafficDirection::Outbound,
                                        action: rule_action,
                                        scope,
                                        expires_at: if scope == samulibre_netdefense::RuleScope::Temporary {
                                            Some(chrono::Utc::now() + chrono::Duration::hours(1))
                                        } else {
                                            None
                                        },
                                        interface_alias: None,
                                        ipv4: true,
                                        ipv6: true,
                                        enabled: true,
                                        created_at: chrono::Utc::now(),
                                        hit_count: 0,
                                        wfp_filter_ids: Vec::new(),
                                        reason: format!("Acción desde Network Monitor ({})", action_kind),
                                    };
                                    let (action_ok, action_feedback) = match nd.add_rule(rule.clone()) {
                                        Ok(applied_rule) => {
                                            if action_kind == "block" {
                                                nd.blocked_connections_count += 1;
                                            }
                                            if let Some(ref path) = app_path {
                                                let trust = if action_kind == "allow" {
                                                    samulibre_netdefense::AppTrustState::Trusted
                                                } else {
                                                    samulibre_netdefense::AppTrustState::Blocked
                                                };
                                                let _ = nd.set_app_policy(&app_name, path, trust, "Actualizado desde Monitor");
                                            }
                                            if nd.wfp.status().initialized {
                                                (true, format!("✔ Regla '{}' aplicada en WFP y conexiones activas cerradas para {}.", action_kind, app_name))
                                            } else {
                                                match forward_rule_to_elevated_service(&applied_rule) {
                                                    Ok(msg_ok) => (true, format!("✔ {}: {}", app_name, msg_ok)),
                                                    Err(err_ipc) => (true, format!("⚠️ Regla guardada localmente para {}. Para bloqueo WFP en kernel ejecuta como Administrador o inicia el servicio SamuLibreWatcher ({}).", app_name, err_ipc)),
                                                }
                                            }
                                        }
                                        Err(e) => (false, format!("🛡️ Acción rechazada por seguridad: {}", e)),
                                    };

                                    let base_json = build_netdefense_state_json(&mut nd);
                                    let payload_json = if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&base_json) {
                                        v["action_feedback"] = serde_json::json!({
                                            "ok": action_ok,
                                            "message": action_feedback,
                                        });
                                        v.to_string()
                                    } else {
                                        base_json
                                    };
                                    let _ = proxy_cloned.send_event(CustomUserEvent::NetDefenseStateLoaded { payload_json });
                                }
                            }
                        });
                    }

                    "nd_remove_rule" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(uid) = uuid::Uuid::parse_str(payload_str.trim()) {
                                let nd_arc = get_netdefense_engine(&get_project_root().join("data"));
                                if let Ok(mut nd) = nd_arc.lock() {
                                    let _ = nd.remove_rule(uid);
                                    let payload_json = build_netdefense_state_json(&mut nd);
                                    let _ = proxy_cloned.send_event(CustomUserEvent::NetDefenseStateLoaded { payload_json });
                                }
                            }
                        });
                    }

                    "nd_update_dns" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&payload_str) {
                                let nd_arc = get_netdefense_engine(&get_project_root().join("data"));
                                if let Ok(mut nd) = nd_arc.lock() {
                                    if let Ok(mut cfg) = nd.dns_proxy.config.lock() {
                                        if let Some(en) = val["enabled"].as_bool() {
                                            cfg.enabled = en;
                                        }
                                        if let Some(tr) = val["transport"].as_str() {
                                            cfg.transport = if tr == "DoT" {
                                                samulibre_netdefense::DnsTransport::DoT
                                            } else {
                                                samulibre_netdefense::DnsTransport::DoH
                                            };
                                        }
                                        if let Some(prov) = val["provider"].as_str() {
                                            match prov {
                                                "Cloudflare" => {
                                                    cfg.provider = samulibre_netdefense::DnsProviderPreset::Cloudflare;
                                                    cfg.doh_url = "https://cloudflare-dns.com/dns-query".to_string();
                                                    cfg.dot_host = "1.1.1.1".to_string();
                                                }
                                                "Mullvad" => {
                                                    cfg.provider = samulibre_netdefense::DnsProviderPreset::Mullvad;
                                                    cfg.doh_url = "https://dns.mullvad.net/dns-query".to_string();
                                                    cfg.dot_host = "dns.mullvad.net".to_string();
                                                }
                                                _ => {
                                                    cfg.provider = samulibre_netdefense::DnsProviderPreset::Quad9;
                                                    cfg.doh_url = "https://dns.quad9.net/dns-query".to_string();
                                                    cfg.dot_host = "dns.quad9.net".to_string();
                                                }
                                            }
                                        }
                                        if let Some(v) = val["block_malware"].as_bool() { cfg.block_malware = v; }
                                        if let Some(v) = val["block_phishing"].as_bool() { cfg.block_phishing = v; }
                                        if let Some(v) = val["block_trackers"].as_bool() { cfg.block_trackers = v; }
                                        if let Some(v) = val["rebinding_protection"].as_bool() { cfg.rebinding_protection = v; }
                                    }
                                    let should_run = nd.dns_proxy.config.lock().map(|c| c.enabled).unwrap_or(false);
                                    if should_run {
                                        let _ = nd.dns_proxy.start();
                                    } else {
                                        nd.dns_proxy.stop();
                                    }
                                    let _ = nd.save_state();
                                    let payload_json = build_netdefense_state_json(&mut nd);
                                    let _ = proxy_cloned.send_event(CustomUserEvent::NetDefenseStateLoaded { payload_json });
                                }
                            }
                        });
                    }

                    "nd_update_tor" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&payload_str) {
                                let nd_arc = get_netdefense_engine(&get_project_root().join("data"));
                                if let Ok(mut nd) = nd_arc.lock() {
                                    let mut cfg = nd.tor_manager.config.clone();
                                    if let Some(en) = val["enabled"].as_bool() { cfg.enabled = en; }
                                    if let Some(ks) = val["kill_switch_fail_closed"].as_bool() { cfg.kill_switch_fail_closed = ks; }
                                    if let Some(v6) = val["block_ipv6_for_protected_apps"].as_bool() { cfg.block_ipv6_for_protected_apps = v6; }
                                    if let Some(sp) = val["socks_port"].as_u64() { cfg.socks_port = sp as u16; }
                                    if let Some(path) = val["add_app_path"].as_str() {
                                        let trimmed = path.trim();
                                        if !trimmed.is_empty() && !cfg.protected_app_paths.contains(&trimmed.to_string()) {
                                            cfg.protected_app_paths.push(trimmed.to_string());
                                        }
                                    }
                                    let _ = nd.set_tor_secure_mode(cfg);
                                    let payload_json = build_netdefense_state_json(&mut nd);
                                    let _ = proxy_cloned.send_event(CustomUserEvent::NetDefenseStateLoaded { payload_json });
                                }
                            }
                        });
                    }

                    "nd_update_intel" => {
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            let nd_arc = get_netdefense_engine(&get_project_root().join("data"));
                            if let Ok(mut nd) = nd_arc.lock() {
                                if let Ok(mut intel) = nd.intel.lock() {
                                    let _ = intel.update_enabled_feeds();
                                }
                                nd.log_event("ThreatIntel", "INFO", "FeedsUpdated", "Actualización de feeds de amenazas ejecutada", "");
                                let payload_json = build_netdefense_state_json(&mut nd);
                                let _ = proxy_cloned.send_event(CustomUserEvent::NetDefenseStateLoaded { payload_json });
                            }
                        });
                    }

                    "nd_emergency_cleanup" => {
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            let nd_arc = get_netdefense_engine(&get_project_root().join("data"));
                            if let Ok(mut nd) = nd_arc.lock() {
                                let _ = nd.emergency_cleanup();
                                let payload_json = build_netdefense_state_json(&mut nd);
                                let _ = proxy_cloned.send_event(CustomUserEvent::NetDefenseStateLoaded { payload_json });
                            }
                        });
                    }

                    "isolate_process_network" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let (pid, isolate) = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&payload_str) {
                            (
                                parsed["pid"].as_u64().unwrap_or(0) as u32,
                                parsed["isolate"].as_bool().unwrap_or(true),
                            )
                        } else if let Some((p, iso)) = payload_str.split_once('|') {
                            (p.parse::<u32>().unwrap_or(0), iso == "true" || iso == "1")
                        } else {
                            (payload_str.parse::<u32>().unwrap_or(0), true)
                        };

                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                match c.isolate_process_network(pid, isolate) {
                                    Ok(msg) => {
                                        let _ = proxy_cloned.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "Control de Red SamuLibre".to_string(),
                                            details: msg,
                                        });
                                    }
                                    Err(e) => {
                                        let _ = proxy_cloned.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "Error Aislamiento de Red".to_string(),
                                            details: format!("{}", e),
                                        });
                                    }
                                }
                                let sockets = c.get_network_sockets();
                                let _ = proxy_cloned.send_event(CustomUserEvent::NetworkSocketsLoaded { sockets });
                            }
                        });
                    }

                    "toggle_port_shield" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let (port, close) = if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&payload_str) {
                            (
                                parsed["port"].as_u64().unwrap_or(0) as u16,
                                parsed["close"].as_bool().unwrap_or(true),
                            )
                        } else if let Some((p, cl)) = payload_str.split_once('|') {
                            (p.parse::<u16>().unwrap_or(0), cl == "true" || cl == "1")
                        } else {
                            (payload_str.parse::<u16>().unwrap_or(0), true)
                        };

                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                match c.toggle_port_shield(port, close) {
                                    Ok(msg) => {
                                        let _ = proxy_cloned.send_event(CustomUserEvent::RealTimeAlert {
                                            title: if close { "Puerto Cerrado y Blindado".to_string() } else { "Puerto Reabierto".to_string() },
                                            details: msg,
                                        });
                                    }
                                    Err(e) => {
                                        let _ = proxy_cloned.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "Error Control de Puerto".to_string(),
                                            details: format!("{}", e),
                                        });
                                    }
                                }
                                let sockets = c.get_network_sockets();
                                let _ = proxy_cloned.send_event(CustomUserEvent::NetworkSocketsLoaded { sockets });
                            }
                        });
                    }

                    "close_all_risk_ports" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                match c.close_all_risk_ports() {
                                    Ok(msg) => {
                                        let _ = proxy_cloned.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "Blindaje de Puertos Vulnerables".to_string(),
                                            details: msg,
                                        });
                                    }
                                    Err(e) => {
                                        let _ = proxy_cloned.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "Error de Blindaje".to_string(),
                                            details: format!("{}", e),
                                        });
                                    }
                                }
                                let sockets = c.get_network_sockets();
                                let _ = proxy_cloned.send_event(CustomUserEvent::NetworkSocketsLoaded { sockets });
                            }
                        });
                    }

                    "ask_copilot" => {
                        let query = msg.payload.unwrap_or_default();
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let response = c.ask_copilot(&query);
                                let _ = proxy_cloned.send_event(CustomUserEvent::CopilotAnswerLoaded { response });
                            }
                        });
                    }

                    "get_pc_advanced_status" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let status = c.get_pc_advanced_features_status();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::PcAdvancedStatusLoaded { status });
                        }
                    }

                    "scan_fileless_memory" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let threats = c.scan_fileless_memory();
                                let _ = proxy_cloned.send_event(CustomUserEvent::FilelessScanResultsLoaded { threats });
                            }
                        });
                    }

                    "run_sandbox_analysis" => {
                        let path_str = msg.payload.unwrap_or_default();
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let report = c.run_sandbox_analysis(&path_str);
                                let _ = proxy_cloned.send_event(CustomUserEvent::SandboxReportLoaded { report });
                            }
                        });
                    }

                    "query_community_reputation" => {
                        let hash_or_prefix = msg.payload.unwrap_or_default();
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let indicators = c.query_community_reputation(&hash_or_prefix);
                                let _ = proxy_cloned.send_event(CustomUserEvent::ReputationResultLoaded { indicators });
                            }
                        });
                    }

                    "analyze_phishing_url" => {
                        let url = msg.payload.unwrap_or_default();
                        if let Ok(c) = core_for_ipc.lock() {
                            let verdict = c.analyze_phishing_url(&url);
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::PhishingVerdictLoaded { verdict });
                        }
                    }

                    "audit_browser_extensions" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let extensions = c.audit_browser_extensions();
                                let _ = proxy_cloned.send_event(CustomUserEvent::BrowserExtensionsLoaded { extensions });
                            }
                        });
                    }

                    "uninstall_browser_extension" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            #[derive(Deserialize)]
                            struct UninstallReq {
                                browser: String,
                                profile: String,
                                ext_id: String,
                            }
                            if let Ok(req) = serde_json::from_str::<UninstallReq>(&payload_str) {
                                if let Ok(c) = core_cloned.lock() {
                                    match c.uninstall_browser_extension(&req.browser, &req.profile, &req.ext_id) {
                                        Ok(msg) => {
                                            let _ = proxy_cloned.send_event(CustomUserEvent::RealTimeAlert {
                                                title: "Extensión Eliminada".to_string(),
                                                details: msg,
                                            });
                                        }
                                        Err(e) => {
                                            let _ = proxy_cloned.send_event(CustomUserEvent::RealTimeAlert {
                                                title: "Error al Eliminar Extensión".to_string(),
                                                details: format!("{}", e),
                                            });
                                        }
                                    }
                                    // Re-auditar para refrescar la lista de inmediato
                                    let extensions = c.audit_browser_extensions();
                                    let _ = proxy_cloned.send_event(CustomUserEvent::BrowserExtensionsLoaded { extensions });
                                }
                            }
                        });
                    }

                    "get_scheduled_scan_config" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let config = c.get_scheduled_scan_config();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ScheduledScanConfigLoaded { config });
                        }
                    }

                    "update_scheduled_scan_config" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        if let Ok(cfg) = serde_json::from_str::<samulibre_types::ScheduledScanConfig>(&payload_str) {
                            if let Ok(c) = core_for_ipc.lock() {
                                let _ = c.update_scheduled_scan_config(cfg);
                                let updated = c.get_scheduled_scan_config();
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::ScheduledScanConfigLoaded { config: updated });
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Planificador Actualizado".to_string(),
                                    details: "Se guardó la configuración de escaneos programados.".to_string(),
                                });
                            }
                        }
                    }

                    "trigger_scheduled_scan_now" => {
                        let core_sched = Arc::clone(&core_for_ipc);
                        let proxy_sched = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_sched.lock() {
                                match c.execute_scheduled_scan_now() {
                                    Ok(report) => {
                                        let threats = report.threats_found;
                                        let _ = proxy_sched.send_event(CustomUserEvent::ScheduledScanCompleted { report });
                                        let updated = c.get_scheduled_scan_config();
                                        let _ = proxy_sched.send_event(CustomUserEvent::ScheduledScanConfigLoaded { config: updated });
                                        let _ = proxy_sched.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "Escaneo Programado Ejecutado".to_string(),
                                            details: format!("Escaneo finalizado. Amenazas detectadas: {}", threats),
                                        });
                                    }
                                    Err(e) => {
                                        let _ = proxy_sched.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "Error en Escaneo".to_string(),
                                            details: format!("No se pudo ejecutar: {}", e),
                                        });
                                    }
                                }
                            }
                        });
                    }

                    "get_watcher_settings" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let settings = c.get_watcher_settings();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::WatcherSettingsLoaded { settings });
                        }
                    }

                    "add_watcher_dir" => {
                        let folder_opt = open_native_folder_dialog();
                        if let Some(folder) = folder_opt {
                            if let Ok(c) = core_for_ipc.lock() {
                                c.add_watcher_dir(&folder);
                                let settings = c.get_watcher_settings();
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::WatcherSettingsLoaded { settings });
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Carpeta en Vigilancia".to_string(),
                                    details: format!("Se añadió '{}' a la protección activa en tiempo real.", folder.display()),
                                });
                            }
                        }
                    }

                    "remove_watcher_dir" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let path_clean = payload_str.trim().trim_matches('"');
                        if let Ok(c) = core_for_ipc.lock() {
                            let _ = c.remove_watcher_dir(path_clean);
                            let settings = c.get_watcher_settings();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::WatcherSettingsLoaded { settings });
                        }
                    }

                    "get_security_exceptions" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let exceptions = c.list_security_exceptions();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::SecurityExceptionsLoaded { exceptions });
                        }
                    }

                    "add_security_exception" => {
                        if let Some(payload_str) = msg.payload {
                            if let Ok(ex) = serde_json::from_str::<samulibre_types::SecurityException>(&payload_str) {
                                if let Ok(c) = core_for_ipc.lock() {
                                    match c.add_security_exception(ex) {
                                        Ok(saved) => {
                                            let exceptions = c.list_security_exceptions();
                                            let _ = proxy_for_ipc.send_event(CustomUserEvent::SecurityExceptionsLoaded { exceptions });
                                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                                title: "🛡️ Excepción de Seguridad Registrada".to_string(),
                                                details: format!("Se aplicó regla de exclusión para '{}' con nivel de riesgo {:?}.", saved.target, saved.risk_level),
                                            });
                                        }
                                        Err(err_msg) => {
                                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                                title: "⚠️ Excepción Rechazada".to_string(),
                                                details: format!("No se pudo registrar la excepción: {}", err_msg),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }

                    "toggle_security_exception" => {
                        if let Some(id_str) = msg.payload {
                            let id_clean = id_str.trim().trim_matches('"');
                            if let Ok(c) = core_for_ipc.lock() {
                                let _ = c.toggle_security_exception(id_clean);
                                let exceptions = c.list_security_exceptions();
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::SecurityExceptionsLoaded { exceptions });
                            }
                        }
                    }

                    "remove_security_exception" => {
                        if let Some(id_str) = msg.payload {
                            let id_clean = id_str.trim().trim_matches('"');
                            if let Ok(c) = core_for_ipc.lock() {
                                let _ = c.remove_security_exception(id_clean);
                                let exceptions = c.list_security_exceptions();
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::SecurityExceptionsLoaded { exceptions });
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Excepción Eliminada".to_string(),
                                    details: "Se eliminó la regla de excepción y se restableció el análisis exhaustivo.".to_string(),
                                });
                            }
                        }
                    }

                    "modify_security_exception" => {
                        if let Some(payload_str) = msg.payload {
                            if let Ok(m) = serde_json::from_str::<ModifyExceptionPayload>(&payload_str) {
                                if let Ok(c) = core_for_ipc.lock() {
                                    let ok = c.modify_security_exception(&m.id, m.scope, m.expires_at, m.justification);
                                    if ok {
                                        let exceptions = c.list_security_exceptions();
                                        let _ = proxy_for_ipc.send_event(CustomUserEvent::SecurityExceptionsLoaded { exceptions });
                                        let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                            title: "Excepción Modificada".to_string(),
                                            details: "Los alcances y vigencia de la excepción fueron actualizados con éxito.".to_string(),
                                        });
                                    }
                                }
                            }
                        }
                    }

                    "browse_exception_file" => {
                        let proxy_browse = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            let files = open_native_file_dialog();
                            if let Some(first) = files.first() {
                                let name = first.file_name().and_then(|n| n.to_str()).unwrap_or("archivo").to_string();
                                let size = fs::metadata(first).ok().map(|m| m.len());
                                let sha256 = fs::read(first).ok().map(|bytes| {
                                    use sha2::{Digest, Sha256};
                                    let mut h = Sha256::new();
                                    h.update(&bytes);
                                    hex::encode(h.finalize())
                                });
                                let _ = proxy_browse.send_event(CustomUserEvent::PathSelectedForException {
                                    path: first.to_string_lossy().to_string(),
                                    name,
                                    is_dir: false,
                                    sha256,
                                    size,
                                });
                            }
                        });
                    }

                    "browse_exception_folder" => {
                        let proxy_browse = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Some(folder) = open_native_folder_dialog() {
                                let name = folder.file_name().and_then(|n| n.to_str()).unwrap_or("carpeta").to_string();
                                let _ = proxy_browse.send_event(CustomUserEvent::PathSelectedForException {
                                    path: folder.to_string_lossy().to_string(),
                                    name,
                                    is_dir: true,
                                    sha256: None,
                                    size: None,
                                });
                            }
                        });
                    }

                    "get_realtime_telemetry" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let telemetry = c.get_realtime_telemetry();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealtimeTelemetryLoaded { telemetry });
                            let snapshot = c.get_protection_health();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot });
                        }
                    }

                    "get_protection_health" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let snapshot = c.get_protection_health();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot });
                        }
                    }

                    "get_ssem_config" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let config = c.get_ssem_config();
                            let metrics = c.get_ssem_metrics();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::SsemConfigLoaded { config, metrics });
                        }
                    }

                    "update_ssem_config" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        if let Ok(cfg) = serde_json::from_str::<samulibre_types::SsemConfig>(&payload_str) {
                            if let Ok(c) = core_for_ipc.lock() {
                                c.set_ssem_config(cfg);
                                let updated = c.get_ssem_config();
                                let metrics = c.get_ssem_metrics();
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::SsemConfigLoaded { config: updated, metrics });
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Telemetría SIEM / Syslog Actualizada".to_string(),
                                    details: "Se guardaron los parámetros de exportación corporativa SSEM.".to_string(),
                                });
                            }
                        }
                    }

                    "test_ssem_connection" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let test_alert = samulibre_types::ThreatAlert {
                                id: uuid::Uuid::new_v4(),
                                timestamp: chrono::Utc::now(),
                                severity: samulibre_types::Severity::High,
                                category: samulibre_types::ThreatCategory::MalwareFile,
                                title: "AMTSO-SIEM-TestEvent.Generic".to_string(),
                                details: "Evento de prueba de verificación de enlace SIEM / Syslog (AMTSO / RFC 5424)".to_string(),
                                process_id: Some(std::process::id()),
                                process_name: Some("samulibre-gui.exe".to_string()),
                                target_path: Some("C:\\Windows\\System32\\drivers\\test_endpoint.sys".to_string()),
                                action_taken: "Logged".to_string(),
                            };
                            c.record_security_event(&test_alert);
                            let _ = c.flush_ssem_buffer();
                            let config = c.get_ssem_config();
                            let metrics = c.get_ssem_metrics();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::SsemConfigLoaded { config, metrics });
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                title: "Prueba SIEM Emitida".to_string(),
                                details: "Se transmitió un evento RFC 5424 de prueba hacia el colector configurado.".to_string(),
                            });
                        }
                    }

                    "get_wdhe_settings" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let mode = c.wdhe.engine.get_mode();
                            let profile = c.wdhe.governor.get_profile();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::WdheSettingsLoaded {
                                coexistence_mode: format!("{:?}", mode),
                                resource_profile: format!("{:?}", profile),
                                safe_exclusions_active: true,
                            });
                        }
                    }

                    "set_wdhe_mode" => {
                        let mode_str = msg.payload.unwrap_or_default();
                        let target_mode = match mode_str.as_str() {
                            "Development" => samulibre_types::WdheMode::Development,
                            "PrimaryAntivirus" => samulibre_types::WdheMode::PrimaryAntivirus,
                            _ => samulibre_types::WdheMode::Complementary,
                        };
                        if let Ok(c) = core_for_ipc.lock() {
                            let _ = c.wdhe.set_coexistence_mode(target_mode);
                            let mode = c.wdhe.engine.get_mode();
                            let profile = c.wdhe.governor.get_profile();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::WdheSettingsLoaded {
                                coexistence_mode: format!("{:?}", mode),
                                resource_profile: format!("{:?}", profile),
                                safe_exclusions_active: true,
                            });
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                title: "Modo de Coexistencia Actualizado".to_string(),
                                details: format!("Configurado modo de armonía con Microsoft Defender: {:?}", mode),
                            });
                        }
                    }

                    "get_shce_settings" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let topology = c.get_hardware_topology();
                            let selection = c.get_shce_selection();
                            let gpu_preference = c.get_shce_gpu_preference().as_key().to_string();
                            let gpu_status = c.get_shce_gpu_status();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ShceSettingsLoaded {
                                topology,
                                selection,
                                gpu_preference,
                                gpu_status,
                            });
                        }
                    }

                    "set_shce_gpu_limit" => {
                        let pct_val = msg.payload.unwrap_or_default().parse::<u8>().unwrap_or(70);
                        if let Ok(c) = core_for_ipc.lock() {
                            c.set_shce_gpu_utilization_limit(pct_val);
                            let topology = c.get_hardware_topology();
                            let selection = c.get_shce_selection();
                            let gpu_preference = c.get_shce_gpu_preference().as_key().to_string();
                            let gpu_status = c.get_shce_gpu_status();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ShceSettingsLoaded {
                                topology,
                                selection,
                                gpu_preference,
                                gpu_status,
                            });
                        }
                    }

                    "set_shce_gpu_preference" => {
                        let pref_str = msg.payload.unwrap_or_else(|| "auto".to_string());
                        if let Some(pref) = samulibre_core::gpu_compute::GpuPreference::from_str_loose(&pref_str) {
                            if let Ok(c) = core_for_ipc.lock() {
                                let _ = c.set_shce_gpu_preference(pref);
                                let topology = c.get_hardware_topology();
                                let selection = c.get_shce_selection();
                                let gpu_preference = c.get_shce_gpu_preference().as_key().to_string();
                                let gpu_status = c.get_shce_gpu_status();
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::ShceSettingsLoaded {
                                    topology,
                                    selection,
                                    gpu_preference,
                                    gpu_status,
                                });
                            }
                        }
                    }

                    "run_amtso_cert_test" => {
                        let core_amtso = Arc::clone(&core_for_ipc);
                        let proxy_amtso = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_amtso.lock() {
                                let report = c.run_amtso_certification_battery();
                                let _ = proxy_amtso.send_event(CustomUserEvent::AmtsoReportLoaded { report });
                            }
                        });
                    }

                    "run_realtime_autodiagnostic" => {
                        let proxy_diag = proxy_for_ipc.clone();
                        let core_diag = Arc::clone(&core_for_ipc);
                        std::thread::spawn(move || {
                            if let Ok(c) = core_diag.lock() {
                                let report = c.run_realtime_autodiagnostic();
                                let _ = proxy_diag.send_event(CustomUserEvent::RealtimeDiagnosticReportLoaded { report });
                                let snapshot = c.get_protection_health();
                                let _ = proxy_diag.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot });
                            }
                        });
                    }

                    "pause_realtime_protection" => {
                        let duration_secs = msg
                            .payload
                            .as_deref()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(1800);
                        if let Ok(c) = core_for_ipc.lock() {
                            c.pause_realtime_protection(duration_secs);
                            let telemetry = c.get_realtime_telemetry();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealtimeTelemetryLoaded { telemetry });
                            let snapshot = c.get_protection_health();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot });
                        }
                        let mins = duration_secs / 60;
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                            title: "Protección Temporalmente Pausada".to_string(),
                            details: format!(
                                "La protección en tiempo real ha sido suspendida por {} minutos. Se reanudará automáticamente.",
                                mins
                            ),
                        });
                    }

                    "resume_realtime_protection" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            c.resume_realtime_protection();
                            let telemetry = c.get_realtime_telemetry();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealtimeTelemetryLoaded { telemetry });
                            let snapshot = c.get_protection_health();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot });
                        }
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                            title: "Protección Reanudada".to_string(),
                            details: "La protección en tiempo real de SamuLibre está completamente activa y vigilante.".to_string(),
                        });
                    }

                    "start_realtime_service" => {
                        let res = samulibre_watcher::service::start_service();
                        if let Ok(c) = core_for_ipc.lock() {
                            let telemetry = c.get_realtime_telemetry();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealtimeTelemetryLoaded { telemetry });
                            let snapshot = c.get_protection_health();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot });
                        }
                        match res {
                            Ok(msg) => {
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Protección en Tiempo Real Activada".to_string(),
                                    details: msg,
                                });
                            }
                            Err(e) => {
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Error al Iniciar Servicio".to_string(),
                                    details: format!("No se pudo arrancar el servicio en segundo plano: {}", e),
                                });
                            }
                        }
                    }

                    "stop_realtime_service" => {
                        let res = samulibre_watcher::service::stop_service();
                        if let Ok(c) = core_for_ipc.lock() {
                            let telemetry = c.get_realtime_telemetry();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealtimeTelemetryLoaded { telemetry });
                            let snapshot = c.get_protection_health();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot });
                        }
                        match res {
                            Ok(msg) => {
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Protección en Tiempo Real Detenida".to_string(),
                                    details: msg,
                                });
                            }
                            Err(e) => {
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Aviso al Detener Servicio".to_string(),
                                    details: e.to_string(),
                                });
                            }
                        }
                    }

                    "install_realtime_service" => {
                        let app_root = get_project_root();
                        let exe = if app_root.join("samulibre.exe").exists() {
                            app_root.join("samulibre.exe")
                        } else if let Ok(e) = std::env::current_exe() {
                            e
                        } else {
                            app_root.join("samulibre-gui.exe")
                        };
                        let res = samulibre_watcher::service::install_windows_service_elevated(&exe);
                        if let Ok(c) = core_for_ipc.lock() {
                            let snapshot = c.get_protection_health();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot });
                            let telemetry = c.get_realtime_telemetry();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealtimeTelemetryLoaded { telemetry });
                        }
                        match res {
                            Ok(msg) => {
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Servicio Windows 24/7 Instalado".to_string(),
                                    details: msg,
                                });
                            }
                            Err(e) => {
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Instalación de Servicio Cancelada o Fallida".to_string(),
                                    details: format!("{}", e),
                                });
                            }
                        }
                    }

                    "uninstall_realtime_service" => {
                        let res = samulibre_watcher::service::uninstall_windows_service_elevated();
                        if let Ok(c) = core_for_ipc.lock() {
                            let snapshot = c.get_protection_health();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot });
                            let telemetry = c.get_realtime_telemetry();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::RealtimeTelemetryLoaded { telemetry });
                        }
                        match res {
                            Ok(msg) => {
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Servicio Windows Eliminado".to_string(),
                                    details: msg,
                                });
                            }
                            Err(e) => {
                                let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "Error al Desinstalar Servicio".to_string(),
                                    details: format!("{}", e),
                                });
                            }
                        }
                    }

                    "get_security_center_overview" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let patch_summary = c.get_windows_patch_summary(false);
                                let correlations = c.get_cve_correlations();
                                let vpn_state = c.get_vpn_state();
                                let vpn_countries = c.get_vpn_countries();
                                let shield = c.get_shield_status();
                                let history = c.get_signature_update_history();

                                let _ = proxy_cloned.send_event(CustomUserEvent::WindowsPatchSummaryLoaded { summary: patch_summary });
                                let _ = proxy_cloned.send_event(CustomUserEvent::CveCorrelationsLoaded { correlations });
                                let _ = proxy_cloned.send_event(CustomUserEvent::VpnStateUpdated { state: vpn_state, countries: vpn_countries });
                                let _ = proxy_cloned.send_event(CustomUserEvent::ShieldStatusUpdated { status: shield });
                                let _ = proxy_cloned.send_event(CustomUserEvent::UpdateHistoryLoaded { entries: history });
                            }
                        });
                    }

                    "get_windows_patch_summary" => {
                        let force = msg.payload.as_deref() == Some("true") || msg.payload.as_deref() == Some("force");
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let summary = c.get_windows_patch_summary(force);
                                let _ = proxy_cloned.send_event(CustomUserEvent::WindowsPatchSummaryLoaded { summary });
                            }
                        });
                    }

                    "get_cve_correlations" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let correlations = c.get_cve_correlations();
                                let _ = proxy_cloned.send_event(CustomUserEvent::CveCorrelationsLoaded { correlations });
                            }
                        });
                    }

                    "install_pending_kb" => {
                        let kb_target = msg.payload.unwrap_or_default();
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            let res_msg = if let Ok(c) = core_cloned.lock() {
                                match c.install_pending_kb(&kb_target, true) {
                                    Ok(res) => res,
                                    Err(e) => format!("Error instalando {}: {}", kb_target, e),
                                }
                            } else {
                                "Error adquiriendo lock de Core".to_string()
                            };

                            let _ = proxy_cloned.send_event(CustomUserEvent::KbInstallCompleted { result_message: res_msg });
                            if let Ok(c) = core_cloned.lock() {
                                let summary = c.get_windows_patch_summary(true);
                                let _ = proxy_cloned.send_event(CustomUserEvent::WindowsPatchSummaryLoaded { summary });
                            }
                        });
                    }

                    "run_vpn_diagnostics" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let diag = c.run_vpn_diagnostics();
                                let _ = proxy_cloned.send_event(CustomUserEvent::VpnDiagnosticsLoaded { result: diag });
                            }
                        });
                    }

                    "emergency_recover_vpn" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let _ = c.emergency_recover_vpn_network();
                                let state = c.get_vpn_state();
                                let countries = c.get_vpn_countries();
                                let _ = proxy_cloned.send_event(CustomUserEvent::VpnStateUpdated { state, countries });
                                let diag = c.run_vpn_diagnostics();
                                let _ = proxy_cloned.send_event(CustomUserEvent::VpnDiagnosticsLoaded { result: diag });
                            }
                        });
                    }

                    "toggle_vpn_ipv6_protection" => {
                        let enabled = msg.payload.as_deref() == Some("true");
                        if let Ok(c) = core_for_ipc.lock() {
                            let _ = c.toggle_vpn_ipv6_protection(enabled);
                            let state = c.get_vpn_state();
                            let countries = c.get_vpn_countries();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::VpnStateUpdated { state, countries });
                        }
                    }

                    "reconnect_vpn" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let _ = c.reconnect_vpn();
                                let state = c.get_vpn_state();
                                let countries = c.get_vpn_countries();
                                let _ = proxy_cloned.send_event(CustomUserEvent::VpnStateUpdated { state, countries });
                            }
                        });
                    }

                    "get_vpn_history" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let hist = c.get_vpn_history();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::VpnHistoryLoaded { history: hist });
                        }
                    }

                    "get_virtual_patch_incidents" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let incidents = c.get_virtual_patch_incidents();
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::VirtualPatchIncidentsLoaded { incidents });
                        }
                    }

                    "get_tor_shield_snapshot" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let snapshot = c.get_tor_shield_snapshot();
                                let _ = proxy_cloned.send_event(CustomUserEvent::TorShieldSnapshotLoaded { snapshot });
                            }
                        });
                    }

                    "set_tor_profile" => {
                        let profile_name = msg.payload.unwrap_or_else(|| "tor".to_string());
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let prof = match profile_name.to_lowercase().as_str() {
                                    "normal" => samulibre_types::TorProtectionProfile::Normal,
                                    "isolation" | "max" => samulibre_types::TorProtectionProfile::MaximumIsolation,
                                    _ => samulibre_types::TorProtectionProfile::TorProtection,
                                };
                                c.set_tor_protection_profile(prof);
                                let snapshot = c.get_tor_shield_snapshot();
                                let _ = proxy_cloned.send_event(CustomUserEvent::TorShieldSnapshotLoaded { snapshot });
                            }
                        });
                    }

                    "trigger_tor_kill_switch" => {
                        let payload_str = msg.payload.unwrap_or_default();
                        let pid = payload_str.parse::<u32>().unwrap_or(0);
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                if pid > 0 {
                                    let _ = c.trigger_tor_kill_switch(pid, "SuspiciousProcess", "Contención manual desde la GUI");
                                }
                                let snapshot = c.get_tor_shield_snapshot();
                                let _ = proxy_cloned.send_event(CustomUserEvent::TorShieldSnapshotLoaded { snapshot });
                            }
                        });
                    }

                    "scan_tor_download_file" => {
                        let proxy_scan = proxy_for_ipc.clone();
                        let core_scan = Arc::clone(&core_for_ipc);
                        std::thread::spawn(move || {
                            let paths = open_native_file_dialog();
                            if let Some(first_path) = paths.into_iter().next() {
                                if let Ok(c) = core_scan.lock() {
                                    let _ = c.analyze_tor_download(&first_path, Some("Tor Browser Downloads"));
                                    let snapshot = c.get_tor_shield_snapshot();
                                    let _ = proxy_scan.send_event(CustomUserEvent::TorShieldSnapshotLoaded { snapshot });
                                }
                            }
                        });
                    }

                    "audit_tor_vulnerabilities" => {
                        let core_cloned = Arc::clone(&core_for_ipc);
                        let proxy_cloned = proxy_for_ipc.clone();
                        std::thread::spawn(move || {
                            if let Ok(c) = core_cloned.lock() {
                                let _ = c.audit_tor_vulnerabilities(None);
                                let snapshot = c.get_tor_shield_snapshot();
                                let _ = proxy_cloned.send_event(CustomUserEvent::TorShieldSnapshotLoaded { snapshot });
                            }
                        });
                    }

                    _ => {
                        info!("Acción IPC no reconocida: {}", msg.action);
                    }
                }
    }

    log_step("run_app: Llamando a builder.build(&window)...");
    // En Linux, `build` solo funciona en X11; `build_gtk` soporta Wayland (Garuda KDE, Ubuntu GNOME) y X11
    #[cfg(target_os = "linux")]
    let build_result = {
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        match window.default_vbox() {
            Some(vbox) => builder.build_gtk(vbox),
            None => builder.build(&window),
        }
    };
    #[cfg(not(target_os = "linux"))]
    let build_result = builder.build(&window);
    let webview = match build_result {
        Ok(w) => {
            log_step("run_app: WebView creado con éxito");
            w
        }
        Err(e) => {
            log_step(&format!("run_app: Error en builder.build: {:?}", e));
            return Err(e.into());
        }
    };

    // Actualizador automático diario de Threat Intelligence (Abuse.ch + OTX + Feodo + ClamAV)
    let proxy_daily_intel = proxy.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(12));
        let root = get_project_root();
        let db_path = root.join("data").join("intel").join("samulibre_intel.db");
        let key_file = root.join("data").join("secure").join("intel_keys.json");
        let sig_dir = root.join("data").join("signatures");
        let stamp_path = root.join("data").join("intel").join("last_auto_sync.txt");

        loop {
            let needs_sync = match std::fs::read_to_string(&stamp_path) {
                Ok(raw) => match chrono::DateTime::parse_from_rfc3339(raw.trim()) {
                    Ok(dt) => {
                        let age_secs = (chrono::Utc::now() - dt.with_timezone(&chrono::Utc)).num_seconds();
                        age_secs >= 86400
                    }
                    Err(_) => true,
                },
                Err(_) => true,
            };

            if needs_sync {
                log_step("AutoSync diaria ThreatIntel: ejecutando conectores y repos de hashes...");
                if let Ok(db) = samulibre_intel::IntelDatabase::open(&db_path) {
                    let git_sync = samulibre_intel::GitSyncService::new(root.join("data").join("intel").join("repos"));
                    for repo in samulibre_intel::GitSyncService::phase2_repos() {
                        if repo.source_id == "neo23x0-signature-base" {
                            let _ = git_sync.sync_repo(&db, &repo, false);
                        }
                    }
                    for repo in samulibre_intel::GitSyncService::phase3_behavior_repos() {
                        if repo.source_id == "loldrivers" {
                            let _ = git_sync.sync_behavior_repo(&db, &repo, 5000);
                        }
                    }
                }
                if let Ok(reports) =
                    samulibre_intel::ThreatFeedConnectors::sync_all_feeds(&db_path, &key_file, false)
                {
                    let ok_count = reports.iter().filter(|r| r.success).count();
                    let accepted: usize = reports.iter().map(|r| r.accepted).sum();
                    log_step(&format!(
                        "AutoSync diaria ThreatIntel completada: {}/{} feeds OK, {} indicadores aceptados",
                        ok_count,
                        reports.len(),
                        accepted
                    ));
                    let _ = std::fs::write(&stamp_path, chrono::Utc::now().to_rfc3339());
                    if let Ok(reports_json) = serde_json::to_string(&reports) {
                        let _ = proxy_daily_intel
                            .send_event(CustomUserEvent::IntelFeedsSyncCompleted { reports_json });
                    }
                    if let Some(page_resp) = samulibre_scanner::query_signatures_from_intel_db(
                        &sig_dir,
                        "ALL",
                        "PRODUCCION",
                        "",
                        0,
                        50,
                    ) {
                        if let Ok(catalog_json) = serde_json::to_string(&page_resp) {
                            let _ = proxy_daily_intel
                                .send_event(CustomUserEvent::SignaturesCatalogLoaded { catalog_json });
                        }
                    }
                }
            }

            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    });

    // Hilo para sincronizar el estado inicial de parches, VPN, historial y auditoría con la UI
    let proxy_init = proxy.clone();
    let core_init = Arc::clone(&core);
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(350));
        if let Ok(c) = core_init.lock() {
            let _ = c.initialize();
            // Verificación inicial diaria de KBs para supersesión nativa y catálogo actualizado
            let _ = c.run_daily_kb_verification();
            let rules = c.get_patch_rules();
            let os_info = c.get_os_info();
            let sentinel_status = Some(c.get_sentinel_status());
            let kb_monitor_status = Some(c.get_kb_monitor_status());
            let _ = proxy_init.send_event(CustomUserEvent::UpdatePatchRules {
                rules,
                os_info,
                sentinel_status,
                kb_monitor_status,
            });

            let vpn_state = c.get_vpn_state();
            let vpn_countries = c.get_vpn_countries();
            let _ = proxy_init.send_event(CustomUserEvent::VpnStateUpdated {
                state: vpn_state,
                countries: vpn_countries,
            });

            let history = c.get_signature_update_history();
            let _ =
                proxy_init.send_event(CustomUserEvent::UpdateHistoryLoaded { entries: history });

            if let Ok(s) = c.scanner.lock() {
                let catalog = s.get_signatures_catalog();
                let page_resp = samulibre_scanner::query_signatures_catalog(&catalog, "ALL", "", 0, 50);
                if let Ok(catalog_json) = serde_json::to_string(&page_resp) {
                    let _ = proxy_init.send_event(CustomUserEvent::SignaturesCatalogLoaded { catalog_json });
                }
            }

            let audit = c.run_internal_security_audit();
            let _ = proxy_init.send_event(CustomUserEvent::AuditReportLoaded { report: audit });

            let shield_status = c.get_shield_status();
            let _ = proxy_init.send_event(CustomUserEvent::ShieldStatusUpdated {
                status: shield_status,
            });

            let quarantine = c.get_quarantined_records();
            let _ = proxy_init.send_event(CustomUserEvent::QuarantineListLoaded {
                records: quarantine,
            });

            let persistence = c.get_persistence_entries();
            let _ = proxy_init.send_event(CustomUserEvent::PersistenceListLoaded {
                entries: persistence,
            });

            let sockets = c.get_network_sockets();
            let _ = proxy_init.send_event(CustomUserEvent::NetworkSocketsLoaded { sockets });

            let autostart_enabled = is_windows_autostart_enabled();
            let _ = proxy_init.send_event(CustomUserEvent::AutostartStatusLoaded {
                enabled: autostart_enabled,
            });

            let history = load_threat_history();
            let _ = proxy_init.send_event(CustomUserEvent::ThreatHistoryLoaded { history });

            let pc_features = c.get_pc_advanced_features_status();
            let _ = proxy_init.send_event(CustomUserEvent::PcAdvancedStatusLoaded {
                status: pc_features,
            });

            let sched_cfg = c.get_scheduled_scan_config();
            let _ = proxy_init
                .send_event(CustomUserEvent::ScheduledScanConfigLoaded { config: sched_cfg });

            let watcher_settings = c.get_watcher_settings();
            let _ = proxy_init.send_event(CustomUserEvent::WatcherSettingsLoaded {
                settings: watcher_settings,
            });

            let exceptions = c.list_security_exceptions();
            let _ = proxy_init.send_event(CustomUserEvent::SecurityExceptionsLoaded { exceptions });

            let telemetry = c.get_realtime_telemetry();
            let _ = proxy_init.send_event(CustomUserEvent::RealtimeTelemetryLoaded { telemetry });

            let health = c.get_protection_health();
            let _ =
                proxy_init.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot: health });

            let patch_summary = c.get_windows_patch_summary(false);
            let _ = proxy_init.send_event(CustomUserEvent::WindowsPatchSummaryLoaded { summary: patch_summary });

            let correlations = c.get_cve_correlations();
            let _ = proxy_init.send_event(CustomUserEvent::CveCorrelationsLoaded { correlations });

            let vpn_history = c.get_vpn_history();
            let _ = proxy_init.send_event(CustomUserEvent::VpnHistoryLoaded { history: vpn_history });

            let incidents = c.get_virtual_patch_incidents();
            let _ = proxy_init.send_event(CustomUserEvent::VirtualPatchIncidentsLoaded { incidents });
        }
    });

    // Hilo Demonio Centinela de CVEs en segundo plano (EcoQoS - ciclo continuo cada 15 min)
    let proxy_sentinel = proxy.clone();
    let core_sentinel = Arc::clone(&core);
    std::thread::spawn(move || {
        win_eco::set_current_thread_eco_qos();
        let mut sentinel_cycles: u64 = 0;
        loop {
            // Dormir 15 minutos entre ciclos periódicos de auditoría
            std::thread::sleep(std::time::Duration::from_secs(900));
            sentinel_cycles += 1;
            if let Ok(c) = core_sentinel.lock() {
                // Cada 24 horas (96 ciclos de 15 min = 24h) ejecutar la verificaci?n diaria de nuevos KBs
                if sentinel_cycles % 96 == 0 {
                    let _ = c.run_daily_kb_verification();
                }
                let (_unmitigated, _active, _native, auto_patched) = c.run_sentinel_audit_cycle();
                let _ai_results = c.run_ai_kb_audit_cycle();
                if !auto_patched.is_empty() {
                    let title = "Centinela SamuLibre: Parche Virtual Aplicado".to_string();
                    let details =
                        format!("Se mitigaron automáticamente: {}", auto_patched.join(", "));
                    let _ = proxy_sentinel
                        .send_event(CustomUserEvent::RealTimeAlert { title, details });
                }
                let rules = c.get_patch_rules();
                let os_info = c.get_os_info();
                let sentinel_status = Some(c.get_sentinel_status());
                let kb_monitor_status = Some(c.get_kb_monitor_status());
                let _ = proxy_sentinel.send_event(CustomUserEvent::UpdatePatchRules {
                    rules,
                    os_info,
                    sentinel_status,
                    kb_monitor_status,
                });
            }
        }
    });

    // Hilo de monitoreo continuo del Escudo Endpoint con EcoQoS (5 segundos en reposo)
    let proxy_shield_loop = proxy.clone();
    let core_shield_loop = Arc::clone(&core);
    std::thread::spawn(move || {
        win_eco::set_current_thread_eco_qos();
        let mut cycle_counter = 0u64;

        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            cycle_counter += 1;

            if let Ok(c) = core_shield_loop.try_lock() {
                if let Some(report) = c.check_and_run_scheduled_scan_if_due() {
                    let cfg = c.get_scheduled_scan_config();
                    let _ = proxy_shield_loop
                        .send_event(CustomUserEvent::ScheduledScanConfigLoaded { config: cfg });
                    let _ = proxy_shield_loop.send_event(CustomUserEvent::ScheduledScanCompleted {
                        report: report.clone(),
                    });
                    let _ = proxy_shield_loop.send_event(CustomUserEvent::RealTimeAlert {
                        title: "Escaneo Programado Completado".to_string(),
                        details: format!(
                            "Se analizaron {} archivos. Amenazas: {}.",
                            report.files_scanned, report.threats_found
                        ),
                    });
                }
                let alerts = c.run_continuous_shield_check();
                for alert in alerts {
                    let _ = proxy_shield_loop.send_event(CustomUserEvent::RealTimeAlert {
                        title: alert.title,
                        details: alert.details,
                    });
                }
                let status = c.get_shield_status();
                let _ =
                    proxy_shield_loop.send_event(CustomUserEvent::ShieldStatusUpdated { status });

                let telemetry = c.get_realtime_telemetry();
                let _ = proxy_shield_loop
                    .send_event(CustomUserEvent::RealtimeTelemetryLoaded { telemetry });

                let health = c.get_protection_health();
                let _ = proxy_shield_loop
                    .send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot: health });

                let tor_snap = c.get_tor_shield_snapshot();
                let _ = proxy_shield_loop
                    .send_event(CustomUserEvent::TorShieldSnapshotLoaded { snapshot: tor_snap });
            }

            // Cada 36 ciclos (~3 minutos) en reposo, recortar working set sin provocar page faults en escaneos
            if cycle_counter % 36 == 0 && !IS_SCAN_IN_PROGRESS.load(Ordering::Relaxed) {
                win_eco::trim_process_working_set();
            }
        }
    });

    // Hilo de actualización horaria periÃ³dica (cada 1 hora = 3600 segundos) con EcoQoS
    let proxy_hourly = proxy.clone();
    let core_hourly = Arc::clone(&core);
    std::thread::spawn(move || {
        win_eco::set_current_thread_eco_qos();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
            let scanner_opt = if let Ok(c) = core_hourly.try_lock() {
                Some(Arc::clone(&c.scanner))
            } else {
                None
            };
            if let Some(scanner_arc) = scanner_opt {
                if let Ok(mut s) = scanner_arc.lock() {
                    if let Ok(report) = s.update_signatures() {
                        let _ = proxy_hourly.send_event(CustomUserEvent::SignaturesUpdated {
                            total: report.total_signatures,
                            new_added: report.new_added,
                            timestamp: report.timestamp,
                            feed: report.feed_source,
                        });
                    }
                }
            }
            if let Ok(c) = core_hourly.try_lock() {
                let entries = c.get_signature_update_history();
                let _ = proxy_hourly.send_event(CustomUserEvent::UpdateHistoryLoaded { entries });
            }
        }
    });

    // Hilo de sondeo periÃ³dico de latencias VPN en tiempo real (cada 45 segundos)
    let proxy_vpn_latencies = proxy.clone();
    let core_vpn_latencies = Arc::clone(&core);
    std::thread::spawn(move || {
        win_eco::set_current_thread_eco_qos();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(45));
            if let Ok(c) = core_vpn_latencies.try_lock() {
                let latencies = c.refresh_vpn_latencies();
                let tunnel_ping = c.get_active_vpn_tunnel_latency();
                let _ = proxy_vpn_latencies.send_event(CustomUserEvent::VpnLatenciesUpdated {
                    latencies,
                    tunnel_ping,
                });
            }
        }
    });

    // Hilo de telemetrÃ­a para el túnel activo (cada 5 segundos si está conectado)
    let proxy_tunnel_ping = proxy.clone();
    let core_tunnel_ping = Arc::clone(&core);
    std::thread::spawn(move || {
        win_eco::set_current_thread_eco_qos();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            if let Ok(c) = core_tunnel_ping.try_lock() {
                let state = c.get_vpn_state();
                if state.is_connected {
                    let tunnel_ping = c.get_active_vpn_tunnel_latency();
                    let mut dummy_map = std::collections::HashMap::new();
                    if let Some(ref cid) = state.country_id {
                        if let Some(tp) = tunnel_ping {
                            dummy_map.insert(cid.clone(), tp);
                        }
                    }
                    let _ = proxy_tunnel_ping.send_event(CustomUserEvent::VpnLatenciesUpdated {
                        latencies: dummy_map,
                        tunnel_ping,
                    });
                } else if samulibre_vpn::is_system_proxy_enabled() {
                    // Watchdog Fail-Safe: VPN inactiva pero el proxy del SO quedó encendido
                    let _ = samulibre_vpn::reset_system_network_proxy();
                    let countries = c.get_vpn_countries();
                    let _ = proxy_tunnel_ping
                        .send_event(CustomUserEvent::VpnStateUpdated { state, countries });
                }
            }
        }
    });

    let _keep_tray = _tray_icon_handle;

    log_step("run_app: Entrando a event_loop.run()...");
    // Bucle de Eventos Principal
    event_loop.run(move |event, _, control_flow| {
        let _ = &_keep_tray;
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {
                info!("SamuLibre Apple-Style GUI inicializado con éxito.");
                if !start_minimized {
                    window.set_visible(true);
                    window.set_minimized(false);
                    window.set_focus();
                    #[cfg(target_os = "windows")]
                    win_util::bring_existing_window_to_front();
                }
            }

            Event::UserEvent(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status }) => {
                let rules_json = serde_json::to_string(&rules).unwrap_or_else(|_| "[]".to_string());
                let os_json = serde_json::to_string(&os_info).unwrap_or_else(|_| "null".to_string());
                let sentinel_json = serde_json::to_string(&sentinel_status).unwrap_or_else(|_| "null".to_string());
                let kb_json = serde_json::to_string(&kb_monitor_status).unwrap_or_else(|_| "null".to_string());
                let script = format!(
                    "if (window.onPatchRulesUpdated) {{ window.onPatchRulesUpdated({}, {}, {}, {}); }}",
                    rules_json, os_json, sentinel_json, kb_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::KbAnalysisResultLoaded { result }) => {
                let res_json = serde_json::to_string(&result).unwrap_or_else(|_| "null".to_string());
                let script = format!(
                    "if (window.onKbAnalysisResult) {{ window.onKbAnalysisResult({}); }}",
                    res_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ShowWindow) => {
                window.set_visible(true);
                window.set_minimized(false);
                window.set_focus();
                #[cfg(target_os = "windows")]
                win_util::bring_existing_window_to_front();
            }

            Event::UserEvent(CustomUserEvent::TriggerScan) => {
                if IS_SCAN_IN_PROGRESS.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                    window.set_visible(true);
                    window.set_minimized(false);
                    window.set_focus();
                    let _ = webview.evaluate_script("if (window.showScanProgressUI) { window.showScanProgressUI(); }");
                    return;
                }

                IS_SCAN_CANCELLED.store(false, Ordering::SeqCst);
                window.set_visible(true);
                window.set_minimized(false);
                window.set_focus();
                let _ = webview.evaluate_script("if (window.showScanProgressUI) { window.showScanProgressUI(); }");

                let proxy_scan = proxy.clone();
                let scanner_arc = if let Ok(c) = core_for_actions.lock() {
                    Arc::clone(&c.scanner)
                } else {
                    IS_SCAN_IN_PROGRESS.store(false, Ordering::SeqCst);
                    return;
                };

                std::thread::spawn(move || {
                    execute_scan_loop(proxy_scan, scanner_arc);
                    IS_SCAN_IN_PROGRESS.store(false, Ordering::SeqCst);
                });
            }

            Event::UserEvent(CustomUserEvent::TriggerFullScan) => {
                if IS_SCAN_IN_PROGRESS.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                    window.set_visible(true);
                    window.set_minimized(false);
                    window.set_focus();
                    let _ = webview.evaluate_script("if (window.showScanProgressUI) { window.showScanProgressUI(); }");
                    return;
                }

                IS_SCAN_CANCELLED.store(false, Ordering::SeqCst);
                window.set_visible(true);
                window.set_minimized(false);
                window.set_focus();
                let _ = webview.evaluate_script("if (window.showScanProgressUI) { window.showScanProgressUI(); }");

                let proxy_scan = proxy.clone();
                let scanner_arc = if let Ok(c) = core_for_actions.lock() {
                    Arc::clone(&c.scanner)
                } else {
                    IS_SCAN_IN_PROGRESS.store(false, Ordering::SeqCst);
                    return;
                };

                std::thread::spawn(move || {
                    execute_full_scan_loop(proxy_scan, scanner_arc);
                    IS_SCAN_IN_PROGRESS.store(false, Ordering::SeqCst);
                });
            }

            Event::UserEvent(CustomUserEvent::TriggerUpdateSignatures) => {
                let proxy_update = proxy.clone();
                let core_update = Arc::clone(&core_for_actions);

                std::thread::spawn(move || {
                    if let Ok(c) = core_update.lock() {
                        let res = if let Ok(mut s) = c.scanner.lock() {
                            s.update_signatures()
                        } else {
                            Err(anyhow::anyhow!("El motor de escaneo está ocupado en otra operación."))
                        };

                        match res {
                            Ok(report) => {
                                let _ = proxy_update.send_event(CustomUserEvent::SignaturesUpdated {
                                    total: report.total_signatures,
                                    new_added: report.new_added,
                                    timestamp: report.timestamp,
                                    feed: report.feed_source,
                                });
                            }
                            Err(e) => {
                                let _ = proxy_update.send_event(CustomUserEvent::RealTimeAlert {
                                    title: "❌ Error de Actualización".to_string(),
                                    details: format!("No se pudieron descargar ni sincronizar las firmas: {}", e),
                                });
                            }
                        }

                        let history = c.get_signature_update_history();
                        let _ = proxy_update.send_event(CustomUserEvent::UpdateHistoryLoaded { entries: history });

                        let root = get_project_root();
                        let db_path = root.join("data").join("intel").join("samulibre_intel.db");
                        let key_file = root.join("data").join("secure").join("intel_keys.json");
                        if let Ok(reports) =
                            samulibre_intel::ThreatFeedConnectors::sync_all_feeds(&db_path, &key_file, true)
                        {
                            let _ = std::fs::write(
                                root.join("data").join("intel").join("last_auto_sync.txt"),
                                chrono::Utc::now().to_rfc3339(),
                            );
                            if let Ok(reports_json) = serde_json::to_string(&reports) {
                                let _ = proxy_update.send_event(CustomUserEvent::IntelFeedsSyncCompleted { reports_json });
                            }
                        }

                        let sig_dir = root.join("data").join("signatures");
                        if let Some(page_resp) = samulibre_scanner::query_signatures_from_intel_db(
                            &sig_dir,
                            "ALL",
                            "PRODUCCION",
                            "",
                            0,
                            50,
                        ) {
                            if let Ok(catalog_json) = serde_json::to_string(&page_resp) {
                                let _ = proxy_update.send_event(CustomUserEvent::SignaturesCatalogLoaded { catalog_json });
                            }
                        } else if let Ok(s) = c.scanner.lock() {
                            let catalog = s.get_signatures_catalog();
                            let page_resp = samulibre_scanner::query_signatures_catalog(&catalog, "ALL", "", 0, 50);
                            if let Ok(catalog_json) = serde_json::to_string(&page_resp) {
                                let _ = proxy_update.send_event(CustomUserEvent::SignaturesCatalogLoaded { catalog_json });
                            }
                        }
                    }
                });
            }

            Event::UserEvent(CustomUserEvent::VpnStateUpdated { state, countries }) => {
                let state_json = serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string());
                let countries_json = serde_json::to_string(&countries).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.onVpnStateUpdated) {{ window.onVpnStateUpdated({}, {}); }}",
                    state_json, countries_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::VpnLatenciesUpdated { latencies, tunnel_ping }) => {
                let latencies_json = serde_json::to_string(&latencies).unwrap_or_else(|_| "{}".to_string());
                let ping_json = serde_json::to_string(&tunnel_ping).unwrap_or_else(|_| "null".to_string());
                let script = format!(
                    "if (window.onVpnLatenciesUpdated) {{ window.onVpnLatenciesUpdated({}, {}); }}",
                    latencies_json, ping_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::UpdateHistoryLoaded { entries }) => {
                let entries_json = serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.onUpdateHistoryLoaded) {{ window.onUpdateHistoryLoaded({}); }}",
                    entries_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::SignaturesCatalogLoaded { catalog_json }) => {
                let script = format!(
                    "if (window.onSignaturesCatalogLoaded) {{ window.onSignaturesCatalogLoaded({}); }}",
                    catalog_json
                );
                if let Err(e) = webview.evaluate_script(&script) {
                    log_step(&format!("evaluate_script SignaturesCatalogLoaded error: {:?}", e));
                }
            }

            Event::UserEvent(CustomUserEvent::IntelKeysStatusLoaded { status_json }) => {
                let script = format!(
                    "if (window.onIntelKeysStatusLoaded) {{ window.onIntelKeysStatusLoaded({}); }}",
                    status_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::IntelFeedsSyncCompleted { reports_json }) => {
                let script = format!(
                    "if (window.onIntelFeedsSyncCompleted) {{ window.onIntelFeedsSyncCompleted({}); }}",
                    reports_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::AuditReportLoaded { report }) => {
                let report_json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onAuditReportLoaded) {{ window.onAuditReportLoaded({}); }}",
                    report_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ShieldStatusUpdated { status }) => {
                let status_json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onShieldStatusUpdated) {{ window.onShieldStatusUpdated({}); }}",
                    status_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::SingleScanResult { result }) => {
                let res_json = serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onSingleScanResult) {{ window.onSingleScanResult({}); }}",
                    res_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::BatchScanResults { results }) => {
                let res_json = serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.onBatchScanResults) {{ window.onBatchScanResults({}); }}",
                    res_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::QuarantineListLoaded { records }) => {
                let rec_json = serde_json::to_string(&records).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.onQuarantineListLoaded) {{ window.onQuarantineListLoaded({}); }}",
                    rec_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::OnAccessLabCompleted { log, quarantined }) => {
                let log_json = serde_json::to_string(&log).unwrap_or_default();
                let q_json = serde_json::to_string(&quarantined).unwrap_or_else(|_| "null".to_string());
                let script = format!(
                    "if (window.onAccessLabCompleted) {{ window.onAccessLabCompleted({}, {}); }}",
                    log_json, q_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::PersistenceListLoaded { entries }) => {
                let rec_json = serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.onPersistenceLoaded) {{ window.onPersistenceLoaded({}); }}",
                    rec_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::NetworkSocketsLoaded { sockets }) => {
                let rec_json = serde_json::to_string(&sockets).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.onNetworkSocketsLoaded) {{ window.onNetworkSocketsLoaded({}); }}",
                    rec_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::NetDefenseStateLoaded { payload_json }) => {
                let script = format!(
                    "if (window.onNetDefenseStateLoaded) {{ window.onNetDefenseStateLoaded({}); }}",
                    payload_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::CopilotAnswerLoaded { response }) => {
                let res_json = serde_json::to_string(&response).unwrap_or_else(|_| "null".to_string());
                let script = format!(
                    "if (window.onCopilotAnswerLoaded) {{ window.onCopilotAnswerLoaded({}); }}",
                    res_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::PcAdvancedStatusLoaded { status }) => {
                let status_json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onPcAdvancedStatusLoaded) {{ window.onPcAdvancedStatusLoaded({}); }}",
                    status_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::FilelessScanResultsLoaded { threats }) => {
                let threats_json = serde_json::to_string(&threats).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.onFilelessScanResultsLoaded) {{ window.onFilelessScanResultsLoaded({}); }}",
                    threats_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::SandboxReportLoaded { report }) => {
                let report_json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onSandboxReportLoaded) {{ window.onSandboxReportLoaded({}); }}",
                    report_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ReputationResultLoaded { indicators }) => {
                let ind_json = serde_json::to_string(&indicators).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.onReputationResultLoaded) {{ window.onReputationResultLoaded({}); }}",
                    ind_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::PhishingVerdictLoaded { verdict }) => {
                let verd_json = serde_json::to_string(&verdict).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onPhishingVerdictLoaded) {{ window.onPhishingVerdictLoaded({}); }}",
                    verd_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::BrowserExtensionsLoaded { extensions }) => {
                let ext_json = serde_json::to_string(&extensions).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.onBrowserExtensionsLoaded) {{ window.onBrowserExtensionsLoaded({}); }}",
                    ext_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::SignaturesUpdated { total, new_added, timestamp, feed }) => {
                let msg = format!("Se sincronizaron {} firmas activas (+{} nuevas) desde {}.", total, new_added, feed);
                let title = "✔ Base de Firmas Actualizada";
                let t_json = serde_json::to_string(&title).unwrap_or_default();
                let m_json = serde_json::to_string(&msg).unwrap_or_default();
                let script = format!(
                    "if (window.onSignaturesUpdated) {{ window.onSignaturesUpdated({}, {}, '{}'); }} if (window.showToast) {{ window.showToast({}, {}, false); }}",
                    total, new_added, timestamp, t_json, m_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ScanProgress {
                files_scanned,
                total_files,
                current_file,
                threats_found,
                is_done,
            }) => {
                let file_json = serde_json::to_string(&current_file).unwrap_or_else(|_| "\"\"".to_string());
                let script = format!(
                    "if (window.onScanProgressUpdate) {{ window.onScanProgressUpdate({}, {}, {}, {}, {}); }}",
                    files_scanned, file_json, threats_found, is_done, total_files
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ScanCompleted {
                files_scanned,
                threats_found,
                elapsed_ms,
                infected_files,
            }) => {
                let list_json = serde_json::to_string(&infected_files).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.onScanCompleted) {{ window.onScanCompleted({}, {}, {}, {}); }}",
                    files_scanned, threats_found, elapsed_ms, list_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::RealTimeAlert { title, details }) => {
                let title_json = serde_json::to_string(&title).unwrap_or_else(|_| "\"\"".to_string());
                let details_json = serde_json::to_string(&details).unwrap_or_else(|_| "\"\"".to_string());
                let script = format!(
                    "if (window.showToast) {{ window.showToast({}, {}, true); }}",
                    title_json, details_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ThreatDetected { record }) => {
                let rec_json = serde_json::to_string(&record).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onThreatDetected) {{ window.onThreatDetected({}); }}",
                    rec_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ThreatHistoryLoaded { history }) => {
                let hist_json = serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.onThreatHistoryLoaded) {{ window.onThreatHistoryLoaded({}); }}",
                    hist_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::VtVerificationLoaded { report }) => {
                let rep_json = serde_json::to_string(&report).unwrap_or_else(|_| "null".to_string());
                let script = format!(
                    "if (window.onVtVerificationLoaded) {{ window.onVtVerificationLoaded({}); }}",
                    rep_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::VtStatusLoaded { has_api_key, policy, quota }) => {
                let payload = serde_json::json!({
                    "has_api_key": has_api_key,
                    "policy": policy,
                    "quota": quota,
                });
                let script = format!(
                    "if (window.onVtStatusLoaded) {{ window.onVtStatusLoaded({}); }}",
                    payload
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::AutostartStatusLoaded { enabled }) => {
                let script = format!(
                    "if (window.onAutostartStatusLoaded) {{ window.onAutostartStatusLoaded({}); }}",
                    enabled
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ScheduledScanConfigLoaded { config }) => {
                let cfg_json = serde_json::to_string(&config).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onScheduledScanConfigLoaded) {{ window.onScheduledScanConfigLoaded({}); }}",
                    cfg_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ScheduledScanCompleted { report }) => {
                let rep_json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onScheduledScanCompleted) {{ window.onScheduledScanCompleted({}); }}",
                    rep_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::WatcherSettingsLoaded { settings }) => {
                let set_json = serde_json::to_string(&settings).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onWatcherSettingsLoaded) {{ window.onWatcherSettingsLoaded({}); }}",
                    set_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::SecurityExceptionsLoaded { exceptions }) => {
                let ex_json = serde_json::to_string(&exceptions).unwrap_or_else(|_| "[]".to_string());
                let script = format!(
                    "if (window.renderSecurityExceptions) {{ window.renderSecurityExceptions({}); }}",
                    ex_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::PathSelectedForException { path, name, is_dir, sha256, size }) => {
                let payload = serde_json::json!({
                    "path": path,
                    "name": name,
                    "is_dir": is_dir,
                    "sha256": sha256,
                    "size": size,
                });
                let script = format!(
                    "if (window.onExceptionPathSelected) {{ window.onExceptionPathSelected({}); }}",
                    serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::RealtimeTelemetryLoaded { telemetry }) => {
                let telem_json = serde_json::to_string(&telemetry).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onRealtimeTelemetryLoaded) {{ window.onRealtimeTelemetryLoaded({}); }}",
                    telem_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::RealtimeDiagnosticReportLoaded { report }) => {
                let rep_json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onRealtimeDiagnosticReportLoaded) {{ window.onRealtimeDiagnosticReportLoaded({}); }}",
                    rep_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ProtectionHealthLoaded { snapshot }) => {
                let snap_json = serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".to_string());
                let script = format!(
                    "if (window.onProtectionHealthLoaded) {{ window.onProtectionHealthLoaded({}); }}",
                    snap_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::WindowsPatchSummaryLoaded { summary }) => {
                let json = serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string());
                let script = format!("if (window.onWindowsPatchSummary) {{ window.onWindowsPatchSummary({}); }}", json);
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::CveCorrelationsLoaded { correlations }) => {
                let json = serde_json::to_string(&correlations).unwrap_or_else(|_| "[]".to_string());
                let script = format!("if (window.onCveCorrelations) {{ window.onCveCorrelations({}); }}", json);
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::VpnDiagnosticsLoaded { result }) => {
                let json = serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string());
                let script = format!("if (window.onVpnDiagnostics) {{ window.onVpnDiagnostics({}); }}", json);
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::VpnHistoryLoaded { history }) => {
                let json = serde_json::to_string(&history).unwrap_or_else(|_| "[]".to_string());
                let script = format!("if (window.onVpnHistoryLoaded) {{ window.onVpnHistoryLoaded({}); }}", json);
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::VirtualPatchIncidentsLoaded { incidents }) => {
                let json = serde_json::to_string(&incidents).unwrap_or_else(|_| "[]".to_string());
                let script = format!("if (window.onVirtualPatchIncidentsLoaded) {{ window.onVirtualPatchIncidentsLoaded({}); }}", json);
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::KbInstallCompleted { result_message }) => {
                let escaped = serde_json::to_string(&result_message).unwrap_or_else(|_| "\"\"".to_string());
                let script = format!("if (window.onKbInstallCompleted) {{ window.onKbInstallCompleted({}); }}", escaped);
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::SsemConfigLoaded { config, metrics }) => {
                let cfg_json = serde_json::to_string(&config).unwrap_or_else(|_| "{}".to_string());
                let met_json = serde_json::to_string(&metrics).unwrap_or_else(|_| "{}".to_string());
                let script = format!("if (window.onSsemConfigLoaded) {{ window.onSsemConfigLoaded({}, {}); }}", cfg_json, met_json);
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::WdheSettingsLoaded { coexistence_mode, resource_profile, safe_exclusions_active }) => {
                let payload = serde_json::json!({
                    "coexistence_mode": coexistence_mode,
                    "resource_profile": resource_profile,
                    "safe_exclusions_active": safe_exclusions_active
                });
                let script = format!("if (window.onWdheSettingsLoaded) {{ window.onWdheSettingsLoaded({}); }}", payload);
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ShceSettingsLoaded { topology, selection, gpu_preference, gpu_status }) => {
                let top_json = serde_json::to_string(&topology).unwrap_or_else(|_| "{}".to_string());
                let sel_json = serde_json::to_string(&selection).unwrap_or_else(|_| "{}".to_string());
                let pref_json = serde_json::to_string(&gpu_preference).unwrap_or_else(|_| "\"auto\"".to_string());
                let stat_json = serde_json::to_string(&gpu_status).unwrap_or_else(|_| "null".to_string());
                let script = format!("if (window.onShceSettingsLoaded) {{ window.onShceSettingsLoaded({}, {}, {}, {}); }}", top_json, sel_json, pref_json, stat_json);
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::AmtsoReportLoaded { report }) => {
                let rep_json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
                let script = format!("if (window.onAmtsoReportLoaded) {{ window.onAmtsoReportLoaded({}); }}", rep_json);
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::TorShieldSnapshotLoaded { snapshot }) => {
                let snap_json = serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".to_string());
                let script = format!("if (window.onTorShieldSnapshotLoaded) {{ window.onTorShieldSnapshotLoaded({}); }}", snap_json);
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::PauseProtection { duration_secs }) => {
                let proxy_pause = proxy.clone();
                let core_pause = Arc::clone(&core_for_actions);
                std::thread::spawn(move || {
                    if let Ok(c) = core_pause.lock() {
                        c.pause_realtime_protection(duration_secs);
                        let telemetry = c.get_realtime_telemetry();
                        let _ = proxy_pause.send_event(CustomUserEvent::RealtimeTelemetryLoaded { telemetry });
                        let snapshot = c.get_protection_health();
                        let _ = proxy_pause.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot });
                    }
                    let mins = duration_secs / 60;
                    let _ = proxy_pause.send_event(CustomUserEvent::RealTimeAlert {
                        title: "Protección Temporalmente Pausada".to_string(),
                        details: format!(
                            "La protección en tiempo real ha sido suspendida por {} minutos desde la bandeja del sistema.",
                            mins
                        ),
                    });
                });
            }

            Event::UserEvent(CustomUserEvent::ResumeProtection) => {
                let proxy_resume = proxy.clone();
                let core_resume = Arc::clone(&core_for_actions);
                std::thread::spawn(move || {
                    if let Ok(c) = core_resume.lock() {
                        c.resume_realtime_protection();
                        let telemetry = c.get_realtime_telemetry();
                        let _ = proxy_resume.send_event(CustomUserEvent::RealtimeTelemetryLoaded { telemetry });
                        let snapshot = c.get_protection_health();
                        let _ = proxy_resume.send_event(CustomUserEvent::ProtectionHealthLoaded { snapshot });
                    }
                    let _ = proxy_resume.send_event(CustomUserEvent::RealTimeAlert {
                        title: "Protección Reanudada".to_string(),
                        details: "La protección en tiempo real de SamuLibre ha sido reanudada exitosamente.".to_string(),
                    });
                });
            }

            Event::UserEvent(CustomUserEvent::Quit) => {
                #[cfg(target_os = "windows")]
                {
                    if !is_running_as_admin() {
                        let confirmed = request_uac_admin_confirmation("detener la protección de SamuLibre y salir");
                        if !confirmed {
                            log_step("Intento de salida bloqueado: Permisos de Administrador denegados por UAC.");
                            let _ = proxy.send_event(CustomUserEvent::RealTimeAlert {
                                title: "Protección contra ManipulaciÃ³n".to_string(),
                                details: "Se bloqueó el cierre de SamuLibre. Solo un Administrador del equipo puede detener la protección en tiempo real.".to_string(),
                            });
                            return;
                        }
                    }
                }

                if let Ok(c) = core_for_actions.lock() {
                    let _ = c.reset_vpn_network();
                }
                let _ = samulibre_vpn::reset_system_network_proxy();
                *control_flow = ControlFlow::Exit;
            }

            // Al hacer clic en la "X" (Cerrar), la ventana se oculta a la bandeja del sistema
            // sin detener la protección en segundo plano (comportamiento estándar de antivirus)
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                window.set_visible(false);
            }

            _ => (),
        }
    });
}

fn scan_paths_parallel(
    paths: Vec<PathBuf>,
    scanner_arc: Arc<samulibre_scanner::MultiEngineScanner>,
    proxy: EventLoopProxy<CustomUserEvent>,
) -> (usize, usize, Vec<samulibre_types::ThreatRecord>) {
    let total_files_count = paths.len();
    let scanned_count = Arc::new(AtomicUsize::new(0));
    let threats_count = Arc::new(AtomicUsize::new(0));
    let detected_threats = Arc::new(Mutex::new(Vec::<samulibre_types::ThreatRecord>::new()));

    let last_ui_update = Arc::new(Mutex::new(std::time::Instant::now()));
    let start_time = std::time::Instant::now();

    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    // Keep CPU cool and leave cores completely free:
    // On 16-core CPU (e.g. Ryzen 9 7940HS), use 5 threads (leaving 11 logical cores 100% idle at 0%).
    let scan_threads = if num_cpus > 8 {
        5
    } else if num_cpus > 4 {
        num_cpus - 2
    } else {
        1.max(num_cpus - 1)
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(scan_threads)
        .thread_name(|i| format!("samu-scan-{}", i))
        .start_handler(move |_idx| {
            #[cfg(target_os = "windows")]
            win_eco::set_current_thread_affinity_and_priority(scan_threads);
        })
        .build()
        .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());

    pool.install(|| {
        paths.par_chunks(32).for_each(|chunk| {
            if IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
                return;
            }

            let batch_results = scanner_arc.scan_files_batch(chunk);
            let mut last_path = chunk.last().unwrap();
            for (path, res_opt) in chunk.iter().zip(batch_results.into_iter()) {
                if IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
                    return;
                }
                last_path = path;
                if let Ok(res) = res_opt {
                    if res.status == samulibre_types::FileScanStatus::Infected {
                        threats_count.fetch_add(1, Ordering::Relaxed);
                        let threat_name = res
                            .detection_name
                            .clone()
                            .unwrap_or_else(|| "Amenaza.Desconocida".to_string());
                        let severity = res.confidence_level.severity_label().to_string();
                        let (origin_source, origin_url, human_explanation, suggested_action) =
                            samulibre_scanner::extract_file_origin_and_story(path, &threat_name);
                        let rec = samulibre_types::ThreatRecord {
                            id: uuid::Uuid::new_v4().to_string(),
                            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                            file_path: path.to_string_lossy().to_string(),
                            threat_name,
                            engine: res.engine.clone(),
                            sha256: res.sha256.clone(),
                            severity,
                            action_taken: if res.confidence_level == samulibre_types::ConfidenceLevel::Medio {
                                "Pendiente (Revisión Analista)".to_string()
                            } else {
                                "Pendiente".to_string()
                            },
                            quarantine_id: None,
                            origin_source,
                            origin_url,
                            human_explanation,
                            suggested_action,
                            confidence_level: res.confidence_level,
                            calibrated_score: res.calibrated_score,
                            evidences: res.evidences.clone(),
                            classification: res.classification.clone(),
                            validation_status: samulibre_types::ValidationStatus::Pendiente,
                            authenticode: res.authenticode.clone(),
                        };
                        if let Ok(mut list) = detected_threats.lock() {
                            list.push(rec);
                        }
                    }
                }
            }

            let curr_scanned = scanned_count.fetch_add(chunk.len(), Ordering::Relaxed) + chunk.len();

            let mut do_update = false;
            if let Ok(mut last) = last_ui_update.try_lock() {
                if last.elapsed() >= std::time::Duration::from_millis(40) {
                    *last = std::time::Instant::now();
                    do_update = true;
                }
            }

            if do_update {
                let t_count = threats_count.load(Ordering::Relaxed);
                let elapsed_sec = start_time.elapsed().as_secs_f64().max(0.01);
                let speed = (curr_scanned as f64 / elapsed_sec) as usize;
                let current_label = format!(
                    "{} [{} arch/s | {} hilos EcoQoS]",
                    last_path.file_name().unwrap_or_default().to_string_lossy(),
                    speed,
                    scan_threads
                );
                let _ = proxy.send_event(CustomUserEvent::ScanProgress {
                    files_scanned: curr_scanned,
                    total_files: total_files_count,
                    current_file: current_label,
                    threats_found: t_count,
                    is_done: false,
                });
            }
        });
    });

    let final_scanned = scanned_count.load(Ordering::SeqCst);
    let final_threats = threats_count.load(Ordering::SeqCst);
    let infected = if let Ok(guard) = detected_threats.lock() {
        guard.clone()
    } else {
        Vec::new()
    };
    (final_scanned, final_threats, infected)
}

fn collect_files_shallow(dir: &Path, max_depth: usize) -> Vec<PathBuf> {
    if !dir.exists() {
        return Vec::new();
    }
    WalkDir::new(dir)
        .max_depth(max_depth)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            let path_str = e.path().to_string_lossy();
            !name.starts_with('.')
                && name != "node_modules"
                && name != "target"
                && name != "$Recycle.Bin"
                && !path_str.contains("Antivitus-SamuLibre")
                && !path_str.contains("quarantine")
                && !path_str.contains("threat_history.json")
                && !path_str.contains("exclusions.json")
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect()
}

fn execute_scan_loop(
    proxy: EventLoopProxy<CustomUserEvent>,
    scanner_mutex: Arc<Mutex<samulibre_scanner::MultiEngineScanner>>,
) {
    let scanner_arc = if let Ok(s) = scanner_mutex.lock() {
        Arc::new(s.clone())
    } else {
        IS_SCAN_IN_PROGRESS.store(false, Ordering::SeqCst);
        return;
    };

    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    let scan_threads = if num_cpus > 8 {
        5
    } else if num_cpus > 4 {
        num_cpus - 2
    } else {
        1.max(num_cpus - 1)
    };
    let free_cores = num_cpus.saturating_sub(scan_threads);

    let _ = proxy.send_event(CustomUserEvent::ScanProgress {
        files_scanned: 0,
        total_files: 0,
        current_file: format!(
            "Iniciando escaneo rápido EcoQoS ({} hilos activos, {} núcleos libres)...",
            scan_threads, free_cores
        ),
        threats_found: 0,
        is_done: false,
    });

    let mut candidate_paths = Vec::new();

    // 1. Procesos en ejecución: escanear binarios activos en memoria
    {
        let mut sys = sysinfo::System::new();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
        for (_pid, proc) in sys.processes() {
            if let Some(exe_path) = proc.exe() {
                if exe_path.exists() && exe_path.is_file() {
                    candidate_paths.push(exe_path.to_path_buf());
                }
            }
        }
    }

    // 2. Carpetas de inicio automático (Startup) y rutas críticas de Windows / SO
    #[cfg(target_os = "windows")]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let p = PathBuf::from(&profile);
            let user_startup = p.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup");
            if user_startup.exists() {
                candidate_paths.extend(collect_files_shallow(&user_startup, 2));
            }
            let desktop = p.join("Desktop");
            if desktop.exists() {
                candidate_paths.extend(collect_files_shallow(&desktop, 2));
            }
            let downloads = p.join("Downloads");
            if downloads.exists() {
                candidate_paths.extend(collect_files_shallow(&downloads, 2));
            }
            let temp = p.join(r"AppData\Local\Temp");
            if temp.exists() {
                candidate_paths.extend(collect_files_shallow(&temp, 2));
            }
        }
        let common_startup = PathBuf::from(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup");
        if common_startup.exists() {
            candidate_paths.extend(collect_files_shallow(&common_startup, 2));
        }
        let hosts = PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts");
        if hosts.exists() {
            candidate_paths.push(hosts);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(&home);
            candidate_paths.extend(collect_files_shallow(&p.join("Desktop"), 2));
            candidate_paths.extend(collect_files_shallow(&p.join("Downloads"), 2));
            candidate_paths.extend(collect_files_shallow(&p.join(".config/autostart"), 2));
        }
        candidate_paths.extend(collect_files_shallow(&PathBuf::from("/tmp"), 2));
        candidate_paths.extend(collect_files_shallow(&PathBuf::from("/dev/shm"), 1));
    }

    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(entries) = std::fs::read_dir(cwd) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_file() {
                        let p = entry.path();
                        let p_str = p.to_string_lossy();
                        if !p_str.contains("target")
                            && !p_str.contains("quarantine")
                            && !p_str.contains("threat_history.json")
                        {
                            candidate_paths.push(p);
                        }
                    }
                }
            }
        }
    }

    // Deduplicar rutas
    candidate_paths.sort();
    candidate_paths.dedup();
    candidate_paths.retain(|p| {
        let p_str = p.to_string_lossy();
        !p_str.contains("Antivitus-SamuLibre")
            && !p_str.contains("quarantine")
            && !p_str.contains("threat_history.json")
            && !p_str.ends_with(".quarantine")
    });

    let scan_start = std::time::Instant::now();
    let (total_scanned, threats_found, infected_files) =
        scan_paths_parallel(candidate_paths, scanner_arc, proxy.clone());
    let elapsed_ms = scan_start.elapsed().as_millis() as u64;

    if !infected_files.is_empty() {
        let mut history = load_threat_history();
        for threat in &infected_files {
            if !history.iter().any(|h| {
                h.file_path == threat.file_path
                    && h.sha256 == threat.sha256
                    && h.action_taken == "Pendiente"
            }) {
                history.insert(0, threat.clone());
            }
        }
        save_threat_history(&history);
        let _ = proxy.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
        trigger_vt_auto_verification_for_infected(infected_files.clone(), proxy.clone());
    }

    IS_SCAN_IN_PROGRESS.store(false, Ordering::SeqCst);

    let _ = proxy.send_event(CustomUserEvent::ScanCompleted {
        files_scanned: total_scanned,
        threats_found,
        elapsed_ms,
        infected_files: infected_files.clone(),
    });

    let _ = proxy.send_event(CustomUserEvent::ScanProgress {
        files_scanned: total_scanned,
        total_files: total_scanned,
        current_file: if threats_found > 0 {
            format!("Escaneo multi-hilo finalizado en {:.2}s. {} amenaza(s) encontradas.", elapsed_ms as f64 / 1000.0, threats_found)
        } else {
            format!("Escaneo multi-hilo finalizado en {:.2}s. 0 amenazas. Sistema completamente limpio.", elapsed_ms as f64 / 1000.0)
        },
        threats_found,
        is_done: true,
    });
}

fn execute_full_scan_loop(
    proxy: EventLoopProxy<CustomUserEvent>,
    scanner_mutex: Arc<Mutex<samulibre_scanner::MultiEngineScanner>>,
) {
    let scanner_arc = if let Ok(s) = scanner_mutex.lock() {
        Arc::new(s.clone())
    } else {
        IS_SCAN_IN_PROGRESS.store(false, Ordering::SeqCst);
        return;
    };

    let mut dirs = Vec::new();
    #[cfg(target_os = "windows")]
    {
        if let Ok(sys_drive) = std::env::var("SystemDrive") {
            dirs.push(PathBuf::from(format!("{}\\", sys_drive)));
        } else {
            dirs.push(PathBuf::from("C:\\"));
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        dirs.push(PathBuf::from("/"));
    }

    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    let scan_threads = num_cpus.clamp(4, 16);
    let free_cores = num_cpus.saturating_sub(scan_threads);

    let _ = proxy.send_event(CustomUserEvent::ScanProgress {
        files_scanned: 0,
        total_files: 0,
        current_file: format!(
            "Iniciando Escaneo Completo por flujo continuo ({} hilos activos, {} núcleos libres)...",
            scan_threads, free_cores
        ),
        threats_found: 0,
        is_done: false,
    });

    let total_discovered = Arc::new(AtomicUsize::new(0));
    let counting_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dirs_for_counter = dirs.clone();
    let total_discovered_c = Arc::clone(&total_discovered);
    let counting_done_c = Arc::clone(&counting_done);

    // Hilo ligero de conteo previo en paralelo para mostrar % real sin frenar el escaneo
    let _counter_handle = std::thread::spawn(move || {
        let mut count = 0usize;
        for dir in dirs_for_counter {
            if !dir.exists() {
                continue;
            }
            for entry in WalkDir::new(&dir)
                .max_depth(30)
                .into_iter()
                .filter_entry(|e| {
                    let name = e.file_name().to_string_lossy();
                    let path_str = e.path().to_string_lossy();
                    !name.starts_with('.')
                        && name != "node_modules"
                        && name != "target"
                        && name != "$Recycle.Bin"
                        && name != "System Volume Information"
                        && !path_str.contains("Antivitus-SamuLibre")
                        && !path_str.contains("EBWebView")
                        && !path_str.contains("samu_diag_")
                        && !path_str.contains("samulibre_tor_test_")
                        && !path_str.contains("quarantine")
                        && !path_str.contains("threat_history.json")
                        && !path_str.contains("exclusions.json")
                        && !path_str.contains(r"\Windows\WinSxS")
                        && !path_str.contains(r"\Windows\Installer")
                        && !path_str.contains(r"\AppData\Local\Packages")
                })
                .filter_map(|e| e.ok())
            {
                if IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
                    return;
                }
                if entry.file_type().is_file() {
                    count += 1;
                    if count % 2048 == 0 {
                        total_discovered_c.store(count, Ordering::Relaxed);
                    }
                }
            }
        }
        total_discovered_c.store(count, Ordering::Relaxed);
        counting_done_c.store(true, Ordering::Relaxed);
    });

    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<PathBuf>>(128);
    let rx_arc = Arc::new(Mutex::new(rx));

    // Productor: recorre el disco en segundo plano y transmite lotes de 256 rutas al canal
    let producer_handle = std::thread::spawn(move || {
        let mut pending_batch: Vec<PathBuf> = Vec::with_capacity(256);
        for dir in dirs {
            if !dir.exists() {
                continue;
            }
            for entry in WalkDir::new(&dir)
                .max_depth(30)
                .into_iter()
                .filter_entry(|e| {
                    let name = e.file_name().to_string_lossy();
                    let path_str = e.path().to_string_lossy();
                    !name.starts_with('.')
                        && name != "node_modules"
                        && name != "target"
                        && name != "$Recycle.Bin"
                        && name != "System Volume Information"
                        && !path_str.contains("Antivitus-SamuLibre")
                        && !path_str.contains("EBWebView")
                        && !path_str.contains("samu_diag_")
                        && !path_str.contains("samulibre_tor_test_")
                        && !path_str.contains("quarantine")
                        && !path_str.contains("threat_history.json")
                        && !path_str.contains("exclusions.json")
                        && !path_str.contains(r"\Windows\WinSxS")
                        && !path_str.contains(r"\Windows\Installer")
                        && !path_str.contains(r"\AppData\Local\Packages")
                })
                .filter_map(|e| e.ok())
            {
                if IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
                    return;
                }
                if entry.file_type().is_file() {
                    let p_str = entry.path().to_string_lossy();
                    let p_lower = p_str.to_lowercase();
                    if p_str.contains("Antivitus-SamuLibre")
                        || p_str.contains("EBWebView")
                        || p_str.contains("samu_diag_")
                        || p_str.contains("samulibre_tor_test_")
                        || p_str.contains("quarantine")
                        || p_str.contains("threat_history.json")
                        || p_lower.ends_with(".quarantine")
                        || p_lower.ends_with(".vmdk")
                        || p_lower.ends_with(".vmem")
                        || p_lower.ends_with(".vhdx")
                        || p_lower.ends_with(".vhd")
                        || p_lower.ends_with(".vdi")
                        || p_lower.ends_with(".iso")
                        || (p_lower.ends_with(".sys") && (p_lower.contains("pagefile") || p_lower.contains("hiberfil") || p_lower.contains("swapfile")))
                    {
                        continue;
                    }
                    pending_batch.push(entry.into_path());
                    if pending_batch.len() >= 256 {
                        let mut batch_to_send = std::mem::replace(&mut pending_batch, Vec::with_capacity(256));
                        loop {
                            if IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
                                return;
                            }
                            match tx.try_send(batch_to_send) {
                                Ok(()) => break,
                                Err(std::sync::mpsc::TrySendError::Full(b)) => {
                                    batch_to_send = b;
                                    std::thread::sleep(std::time::Duration::from_millis(5));
                                }
                                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return,
                            }
                        }
                    }
                }
            }
        }
        if !pending_batch.is_empty() && !IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
            let _ = tx.send(pending_batch);
        }
    });

    let scanned_count = Arc::new(AtomicUsize::new(0));
    let threats_count = Arc::new(AtomicUsize::new(0));
    let detected_threats = Arc::new(Mutex::new(Vec::<samulibre_types::ThreatRecord>::new()));
    let last_ui_update = Arc::new(Mutex::new(std::time::Instant::now()));
    let start_time = std::time::Instant::now();

    let mut workers = Vec::new();
    for i in 0..scan_threads {
        let rx = Arc::clone(&rx_arc);
        let scanner = Arc::clone(&scanner_arc);
        let proxy_w = proxy.clone();
        let scanned = Arc::clone(&scanned_count);
        let threats = Arc::clone(&threats_count);
        let total_discovered_w = Arc::clone(&total_discovered);
        let counting_done_w = Arc::clone(&counting_done);
        let det_list = Arc::clone(&detected_threats);
        let last_ui = Arc::clone(&last_ui_update);

        let handle = std::thread::Builder::new()
            .name(format!("samu-fullscan-{}", i))
            .spawn(move || {
                loop {
                    if IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
                        break;
                    }

                    let batch: Vec<PathBuf> = {
                        let lock = rx.lock().unwrap();
                        match lock.recv_timeout(std::time::Duration::from_millis(40)) {
                            Ok(b) => b,
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    };

                    if IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
                        break;
                    }

                    let batch_results = scanner.scan_files_batch(&batch);
                    for (path, res_opt) in batch.iter().zip(batch_results.into_iter()) {
                        if let Ok(res) = res_opt {
                            if res.status == samulibre_types::FileScanStatus::Infected {
                                threats.fetch_add(1, Ordering::Relaxed);
                                let threat_name = res
                                    .detection_name
                                    .clone()
                                    .unwrap_or_else(|| "Amenaza.Desconocida".to_string());
                                let severity = res.confidence_level.severity_label().to_string();
                                let (origin_source, origin_url, human_explanation, suggested_action) =
                                    samulibre_scanner::extract_file_origin_and_story(path, &threat_name);
                                let rec = samulibre_types::ThreatRecord {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                                    file_path: path.to_string_lossy().to_string(),
                                    threat_name,
                                    engine: res.engine.clone(),
                                    sha256: res.sha256.clone(),
                                    severity,
                                    action_taken: if res.confidence_level == samulibre_types::ConfidenceLevel::Medio {
                                        "Pendiente (Revisión Analista)".to_string()
                                    } else {
                                        "Pendiente".to_string()
                                    },
                                    quarantine_id: None,
                                    origin_source,
                                    origin_url,
                                    human_explanation,
                                    suggested_action,
                                    confidence_level: res.confidence_level,
                                    calibrated_score: res.calibrated_score,
                                    evidences: res.evidences.clone(),
                                    classification: res.classification.clone(),
                                    validation_status: samulibre_types::ValidationStatus::Pendiente,
                                    authenticode: res.authenticode.clone(),
                                };
                                if let Ok(mut list) = det_list.lock() {
                                    list.push(rec);
                                }
                            }
                        }
                    }

                    let curr_scanned = scanned.fetch_add(batch.len(), Ordering::Relaxed) + batch.len();

                    let mut do_update = false;
                    if let Ok(mut last) = last_ui.try_lock() {
                        if last.elapsed() >= std::time::Duration::from_millis(50) {
                            *last = std::time::Instant::now();
                            do_update = true;
                        }
                    }

                    if do_update {
                        let t_count = threats.load(Ordering::Relaxed);
                        let elapsed_sec = start_time.elapsed().as_secs_f64().max(0.01);
                        let speed = (curr_scanned as f64 / elapsed_sec) as usize;
                        let file_name = batch.last().and_then(|p| p.file_name()).unwrap_or_default().to_string_lossy();
                        let current_label = format!(
                            "{} [{} arch/s | {} hilos]",
                            file_name, speed, scan_threads
                        );
                        let real_total = if counting_done_w.load(Ordering::Relaxed) {
                            total_discovered_w.load(Ordering::Relaxed)
                        } else {
                            0
                        };
                        let _ = proxy_w.send_event(CustomUserEvent::ScanProgress {
                            files_scanned: curr_scanned,
                            total_files: real_total,
                            current_file: current_label,
                            threats_found: t_count,
                            is_done: false,
                        });
                    }
                }
            });

        if let Ok(h) = handle {
            workers.push(h);
        }
    }

    for w in workers {
        let _ = w.join();
    }
    drop(rx_arc);
    let _ = producer_handle.join();

    let total_scanned = scanned_count.load(Ordering::SeqCst);
    let total_threats = threats_count.load(Ordering::SeqCst);
    let infected_files = if let Ok(guard) = detected_threats.lock() {
        guard.clone()
    } else {
        Vec::new()
    };
    let elapsed_ms = start_time.elapsed().as_millis() as u64;

    if !infected_files.is_empty() {
        let mut history = load_threat_history();
        for threat in &infected_files {
            if !history.iter().any(|h| {
                h.file_path == threat.file_path
                    && h.sha256 == threat.sha256
                    && h.action_taken == "Pendiente"
            }) {
                history.insert(0, threat.clone());
            }
        }
        save_threat_history(&history);
        let _ = proxy.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
        trigger_vt_auto_verification_for_infected(infected_files.clone(), proxy.clone());
    }

    IS_SCAN_IN_PROGRESS.store(false, Ordering::SeqCst);

    let _ = proxy.send_event(CustomUserEvent::ScanCompleted {
        files_scanned: total_scanned,
        threats_found: total_threats,
        elapsed_ms,
        infected_files: infected_files.clone(),
    });

    if IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
        let _ = proxy.send_event(CustomUserEvent::ScanProgress {
            files_scanned: total_scanned,
            total_files: total_scanned,
            current_file: "Análisis completo cancelado por el usuario.".to_string(),
            threats_found: total_threats,
            is_done: true,
        });
        return;
    }

    let _ = proxy.send_event(CustomUserEvent::ScanProgress {
        files_scanned: total_scanned,
        total_files: total_scanned,
        current_file: if total_threats > 0 {
            format!(
                "Escaneo completo finalizado en {:.2}s. {} amenaza(s) encontradas.",
                elapsed_ms as f64 / 1000.0,
                total_threats
            )
        } else {
            format!(
                "Escaneo completo finalizado en {:.2}s. 0 amenazas. Sistema completamente limpio.",
                elapsed_ms as f64 / 1000.0
            )
        },
        threats_found: total_threats,
        is_done: true,
    });
}
