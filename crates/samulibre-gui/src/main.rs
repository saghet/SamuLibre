#![windows_subsystem = "windows"]

use anyhow::Result;
use samulibre_core::SamuLibreCore;
use serde::{Deserialize, Serialize};
use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem, MenuEvent};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tao::{
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
    window::WindowBuilder,
};
use tracing::info;
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
        pub fn SetThreadAffinityMask(hThread: isize, dwThreadAffinityMask: usize) -> usize;
        pub fn GetCurrentProcess() -> isize;
    }

    #[link(name = "psapi")]
    extern "system" {
        pub fn EmptyWorkingSet(hProcess: isize) -> i32;
    }

    pub const THREAD_PRIORITY_LOWEST: i32 = -2;

    pub fn set_current_thread_affinity_and_priority(num_threads: usize) {
        unsafe {
            let thread = GetCurrentThread();
            let mask = (1usize << num_threads.min(64)) - 1;
            SetThreadAffinityMask(thread, mask);
            SetThreadPriority(thread, THREAD_PRIORITY_LOWEST);
        }
    }

    pub fn set_current_thread_eco_qos() {
        unsafe {
            let thread = GetCurrentThread();
            SetThreadPriority(thread, THREAD_PRIORITY_LOWEST);
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
            // Asigna la prioridad más baja (nice 19) en el planificador de Linux
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

#[derive(Debug, Clone)]
enum CustomUserEvent {
    ScanProgress {
        files_scanned: usize,
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
    #[allow(dead_code)]
    ThreatDetected {
        record: samulibre_types::ThreatRecord,
    },
    ThreatHistoryLoaded {
        history: Vec<samulibre_types::ThreatRecord>,
    },
    AutostartStatusLoaded {
        enabled: bool,
    },
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
        if let Ok(home) = std::env::var("HOME") {
            let user_data = PathBuf::from(&home).join(".local/share/samulibre");
            if user_data.join("data").exists() {
                return user_data;
            }
        }
        let sys_opt = PathBuf::from("/opt/samulibre");
        if sys_opt.join("data").exists() {
            return sys_opt;
        }
        let usr_share = PathBuf::from("/usr/share/samulibre");
        if usr_share.join("data").exists() {
            return usr_share;
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
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
    if is_running_as_admin() {
        return true;
    }

    // Solicitar elevación UAC nativa de Windows
    let status = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Start-Process cmd.exe -ArgumentList '/c (net session >nul 2>&1) && exit 0 || exit 1' -Verb RunAs -WindowStyle Hidden -Wait",
        ])
        .creation_flags(0x08000000)
        .status();

    match status {
        Ok(s) => s.success(),
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
pub fn request_uac_admin_confirmation(_action_description: &str) -> bool {
    is_running_as_admin()
}

fn is_windows_autostart_enabled() -> bool {
    #[cfg(target_os = "windows")]
    {
        let output = std::process::Command::new("reg")
            .args(&["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "SamuLibre"])
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
            let confirmed = request_uac_admin_confirmation("modificar las opciones de inicio con Windows");
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
            if let Ok(records) = serde_json::from_str::<Vec<samulibre_types::ThreatRecord>>(&content) {
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

fn log_step(msg: &str) {
    use std::io::Write;
    let root = get_project_root();
    let log_path = root.join("data").join("app_error.log");
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(log_path) {
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
        cmd.args(["-NoProfile", "-NonInteractive", "-Command", script]);
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
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
            .args(["--file-selection", "--multiple", "--separator=\n", "--title=Seleccionar Archivos para Escanear - SamuLibre"])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let files: Vec<PathBuf> = text.lines()
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
            .args(["--getopenfilename", "--multiple", "--separate-output", ".", "Todos los archivos (*)"])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let files: Vec<PathBuf> = text.lines()
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
        cmd.args(["-NoProfile", "-NonInteractive", "-Command", script]);
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
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
            .args(["--file-selection", "--directory", "--title=Seleccionar Carpeta para Escaneo Exhaustivo - SamuLibre"])
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
            log_step(&format!("run_app: Listener no pudo enlazar: {:?}. Probando conex a instancia existente...", e));
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", SINGLE_INSTANCE_PORT)) {
                log_step("run_app: Señal SHOW enviada a instancia existente. Saliendo.");
                let _ = stream.write_all(b"SHOW\n");
            } else {
                log_step("run_app: No se pudo conectar a instancia existente tampoco.");
            }
            return Ok(());
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

    log_step("run_app: Creando e inicializando Core...");
    let core = Arc::new(Mutex::new(SamuLibreCore::new(&canary_dir, &vpn_dir, true)));
    {
        if let Ok(c) = core.lock() {
            log_step("run_app: Llamando a c.initialize()...");
            let _ = c.initialize();
            log_step("run_app: c.initialize() completado.");
        }
    }

    let core_for_ipc = Arc::clone(&core);
    let core_for_actions = Arc::clone(&core);

    log_step("run_app: Creando event_loop...");
    let event_loop = EventLoopBuilder::<CustomUserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    log_step("run_app: EventLoop creado OK");

    // Hilo receptor de señales de Instancia Única
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
    log_step(&format!("run_app: Icon decodificado: {}x{}", icon_w, icon_h));

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

    let mut window_builder = WindowBuilder::new()
        .with_title("SamuLibre - Suite de Seguridad Open Source")
        .with_inner_size(tao::dpi::LogicalSize::new(1060.0, 690.0))
        .with_min_inner_size(tao::dpi::LogicalSize::new(840.0, 560.0))
        .with_visible(false)
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
    let item_show = MenuItem::new("🛡️ Mostrar SamuLibre", true, None);
    let item_scan = MenuItem::new("⚡ Escaneo Rápido", true, None);
    let item_update = MenuItem::new("🔄 Actualizar Firmas", true, None);
    let sep = PredefinedMenuItem::separator();
    let item_quit = MenuItem::new("🔒 Salir de SamuLibre (Requiere Admin)", true, None);

    let _ = tray_menu.append_items(&[
        &item_show,
        &item_scan,
        &item_update,
        &sep,
        &item_quit,
    ]);

    let show_id = item_show.id().clone();
    let scan_id = item_scan.id().clone();
    let update_id = item_update.id().clone();
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
                } else if event.id == update_id {
                    let _ = proxy_tray.send_event(CustomUserEvent::TriggerUpdateSignatures);
                } else if event.id == quit_id {
                    let _ = proxy_tray.send_event(CustomUserEvent::Quit);
                }
            }

            // Eventos de interacción directa con el icono (Solo Clic Izquierdo abre ventana; Clic Derecho mantiene el menú abierto)
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

    let raw_html = include_str!("../../../data/ui/index.html");
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

    log_step("run_app: Creando WebViewBuilder...");
    let proxy_for_ipc = proxy.clone();
    let builder = WebViewBuilder::new()
        .with_html(&html_content)
        .with_ipc_handler(move |request| {
            let body = request.body();
            if let Ok(msg) = serde_json::from_str::<IpcMessage>(body) {
                match msg.action.as_str() {
                    "start_real_scan" => {
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::TriggerScan);
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
                                }

                                let _ = proxy_browse_folder.send_event(CustomUserEvent::ScanCompleted {
                                    files_scanned: total_scanned,
                                    threats_found,
                                    elapsed_ms,
                                    infected_files,
                                });

                                let _ = proxy_browse_folder.send_event(CustomUserEvent::ScanProgress {
                                    files_scanned: total_scanned,
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
                                }

                                let _ = proxy_paths.send_event(CustomUserEvent::ScanCompleted {
                                    files_scanned: total_scanned,
                                    threats_found,
                                    elapsed_ms,
                                    infected_files,
                                });

                                let _ = proxy_paths.send_event(CustomUserEvent::ScanProgress {
                                    files_scanned: total_scanned,
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
                        let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                            title: "⏹️ Deteniendo Análisis".to_string(),
                            details: "Cancelación solicitada por el usuario. Deteniendo análisis...".to_string(),
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
                            let excl_path = get_project_root().join("data").join("exclusions.json");
                            let mut exclusions: Vec<String> = if let Ok(data) = fs::read_to_string(&excl_path) {
                                serde_json::from_str(&data).unwrap_or_default()
                            } else {
                                Vec::new()
                            };
                            if !exclusions.contains(&path_str) {
                                exclusions.push(path_str.clone());
                                let _ = fs::write(&excl_path, serde_json::to_string_pretty(&exclusions).unwrap_or_default());
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
                                title: "✔ Archivo Excluido".to_string(),
                                details: format!("'{}' añadido a la lista de confianza/exclusiones.", path_str),
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
                                info!("GUI simuló instalación oficial de {}", kb);
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
                                info!("GUI desplegó canarios señuelo anti-ransomware");
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
                        let raw_payload = msg.payload.unwrap_or_else(|| "CH".to_string());
                        let (country_code, double_encryption) = if raw_payload.contains('|') {
                            let parts: Vec<&str> = raw_payload.split('|').collect();
                            (parts[0].to_string(), parts.get(1) == Some(&"double"))
                        } else {
                            (raw_payload, false)
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

                    _ => {
                        info!("Acción IPC no reconocida: {}", msg.action);
                    }
                }
            }
        });

    log_step("run_app: Llamando a builder.build(&window)...");
    let webview = match builder.build(&window) {
        Ok(w) => {
            log_step("run_app: WebView creado con éxito");
            w
        }
        Err(e) => {
            log_step(&format!("run_app: Error en builder.build: {:?}", e));
            return Err(e.into());
        }
    };

    // Hilo para sincronizar el estado inicial de parches, VPN, historial y auditoría con la UI
    let proxy_init = proxy.clone();
    let core_init = Arc::clone(&core);
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(350));
        if let Ok(c) = core_init.lock() {
            // Verificaci?n inicial diaria de KBs para supersesi?n nativa y cat?logo actualizado
            let _ = c.run_daily_kb_verification();
            let rules = c.get_patch_rules();
            let os_info = c.get_os_info();
            let sentinel_status = Some(c.get_sentinel_status());
            let kb_monitor_status = Some(c.get_kb_monitor_status());
            let _ = proxy_init.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });

            let vpn_state = c.get_vpn_state();
            let vpn_countries = c.get_vpn_countries();
            let _ = proxy_init.send_event(CustomUserEvent::VpnStateUpdated {
                state: vpn_state,
                countries: vpn_countries,
            });

            let history = c.get_signature_update_history();
            let _ = proxy_init.send_event(CustomUserEvent::UpdateHistoryLoaded { entries: history });

            let audit = c.run_internal_security_audit();
            let _ = proxy_init.send_event(CustomUserEvent::AuditReportLoaded { report: audit });

            let shield_status = c.get_shield_status();
            let _ = proxy_init.send_event(CustomUserEvent::ShieldStatusUpdated { status: shield_status });

            let quarantine = c.get_quarantined_records();
            let _ = proxy_init.send_event(CustomUserEvent::QuarantineListLoaded { records: quarantine });

            let persistence = c.get_persistence_entries();
            let _ = proxy_init.send_event(CustomUserEvent::PersistenceListLoaded { entries: persistence });

            let sockets = c.get_network_sockets();
            let _ = proxy_init.send_event(CustomUserEvent::NetworkSocketsLoaded { sockets });

            let autostart_enabled = is_windows_autostart_enabled();
            let _ = proxy_init.send_event(CustomUserEvent::AutostartStatusLoaded { enabled: autostart_enabled });

            let history = load_threat_history();
            let _ = proxy_init.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
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
                    let title = "🛡️ Centinela SamuLibre: Parche Virtual Aplicado".to_string();
                    let details = format!("Se mitigaron automáticamente: {}", auto_patched.join(", "));
                    let _ = proxy_sentinel.send_event(CustomUserEvent::RealTimeAlert { title, details });
                }
                let rules = c.get_patch_rules();
                let os_info = c.get_os_info();
                let sentinel_status = Some(c.get_sentinel_status());
                let kb_monitor_status = Some(c.get_kb_monitor_status());
                let _ = proxy_sentinel.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status, kb_monitor_status });
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

            if let Ok(c) = core_shield_loop.lock() {
                let alerts = c.run_continuous_shield_check();
                for alert in alerts {
                    let _ = proxy_shield_loop.send_event(CustomUserEvent::RealTimeAlert {
                        title: alert.title,
                        details: alert.details,
                    });
                }
                let status = c.get_shield_status();
                let _ = proxy_shield_loop.send_event(CustomUserEvent::ShieldStatusUpdated { status });
            }

            // Cada 12 ciclos (~60 segundos), recortar working set para garantizar RAM < 40 MB
            if cycle_counter % 12 == 0 {
                win_eco::trim_process_working_set();
            }
        }
    });

    // Hilo de actualización horaria periódica (cada 1 hora = 3600 segundos) con EcoQoS
    let proxy_hourly = proxy.clone();
    let core_hourly = Arc::clone(&core);
    std::thread::spawn(move || {
        win_eco::set_current_thread_eco_qos();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
            if let Ok(c) = core_hourly.lock() {
                if let Ok(mut s) = c.scanner.lock() {
                    if let Ok(report) = s.update_signatures() {
                        let _ = proxy_hourly.send_event(CustomUserEvent::SignaturesUpdated {
                            total: report.total_signatures,
                            new_added: report.new_added,
                            timestamp: report.timestamp,
                            feed: report.feed_source,
                        });
                    }
                }
                let entries = c.get_signature_update_history();
                let _ = proxy_hourly.send_event(CustomUserEvent::UpdateHistoryLoaded { entries });
            }
        }
    });

    // Hilo de sondeo periódico de latencias VPN en tiempo real (cada 25 segundos)
    let proxy_vpn_latencies = proxy.clone();
    let core_vpn_latencies = Arc::clone(&core);
    std::thread::spawn(move || {
        win_eco::set_current_thread_eco_qos();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(25));
            if let Ok(c) = core_vpn_latencies.lock() {
                let latencies = c.refresh_vpn_latencies();
                let tunnel_ping = c.get_active_vpn_tunnel_latency();
                let _ = proxy_vpn_latencies.send_event(CustomUserEvent::VpnLatenciesUpdated {
                    latencies,
                    tunnel_ping,
                });
            }
        }
    });

    // Hilo de telemetría de alta frecuencia para el túnel activo (cada 5 segundos si está conectado)
    let proxy_tunnel_ping = proxy.clone();
    let core_tunnel_ping = Arc::clone(&core);
    std::thread::spawn(move || {
        win_eco::set_current_thread_eco_qos();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            if let Ok(c) = core_tunnel_ping.lock() {
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
                    let _ = proxy_tunnel_ping.send_event(CustomUserEvent::VpnStateUpdated { state, countries });
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

            Event::UserEvent(CustomUserEvent::TriggerUpdateSignatures) => {
                let proxy_update = proxy.clone();
                let core_update = Arc::clone(&core_for_actions);

                std::thread::spawn(move || {
                    if let Ok(c) = core_update.lock() {
                        if let Ok(mut s) = c.scanner.lock() {
                            if let Ok(report) = s.update_signatures() {
                                let _ = proxy_update.send_event(CustomUserEvent::SignaturesUpdated {
                                    total: report.total_signatures,
                                    new_added: report.new_added,
                                    timestamp: report.timestamp,
                                    feed: report.feed_source,
                                });
                            }
                        }
                        let history = c.get_signature_update_history();
                        let _ = proxy_update.send_event(CustomUserEvent::UpdateHistoryLoaded { entries: history });
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

            Event::UserEvent(CustomUserEvent::CopilotAnswerLoaded { response }) => {
                let res_json = serde_json::to_string(&response).unwrap_or_else(|_| "null".to_string());
                let script = format!(
                    "if (window.onCopilotAnswerLoaded) {{ window.onCopilotAnswerLoaded({}); }}",
                    res_json
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
                current_file,
                threats_found,
                is_done,
            }) => {
                let file_json = serde_json::to_string(&current_file).unwrap_or_else(|_| "\"\"".to_string());
                let script = format!(
                    "if (window.onScanProgressUpdate) {{ window.onScanProgressUpdate({}, {}, {}, {}); }}",
                    files_scanned, file_json, threats_found, is_done
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

            Event::UserEvent(CustomUserEvent::AutostartStatusLoaded { enabled }) => {
                let script = format!(
                    "if (window.onAutostartStatusLoaded) {{ window.onAutostartStatusLoaded({}); }}",
                    enabled
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::Quit) => {
                #[cfg(target_os = "windows")]
                {
                    if !is_running_as_admin() {
                        let confirmed = request_uac_admin_confirmation("detener la protección de SamuLibre y salir");
                        if !confirmed {
                            log_step("Intento de salida bloqueado: Permisos de Administrador denegados por UAC.");
                            let _ = proxy.send_event(CustomUserEvent::RealTimeAlert {
                                title: "🛡️ Protección contra Manipulación".to_string(),
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
    let scanned_count = Arc::new(AtomicUsize::new(0));
    let threats_count = Arc::new(AtomicUsize::new(0));
    let detected_threats = Arc::new(Mutex::new(Vec::<samulibre_types::ThreatRecord>::new()));

    let last_ui_update = Arc::new(Mutex::new(std::time::Instant::now()));
    let start_time = std::time::Instant::now();

    let num_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
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
        paths.par_iter().for_each(|path| {
            if IS_SCAN_CANCELLED.load(Ordering::Relaxed) {
                return;
            }

            // Micro-pausa de 150us para permitir descanso térmico al CPU y evitar estrangulamiento
            std::thread::sleep(std::time::Duration::from_micros(150));

            let curr_scanned = scanned_count.fetch_add(1, Ordering::Relaxed) + 1;

            if let Ok(res) = scanner_arc.scan_file(path) {
                if res.status == samulibre_types::FileScanStatus::Infected || res.status == samulibre_types::FileScanStatus::Suspicious {
                    threats_count.fetch_add(1, Ordering::Relaxed);
                    let threat_name = res.detection_name.clone().unwrap_or_else(|| "Amenaza.Desconocida".to_string());
                    let severity = if threat_name.to_lowercase().contains("critical") || threat_name.to_lowercase().contains("wiper") || threat_name.to_lowercase().contains("ransomware") || threat_name.to_lowercase().contains("eicar") {
                        "Crítica".to_string()
                    } else if threat_name.to_lowercase().contains("trojan") || threat_name.to_lowercase().contains("exploit") || threat_name.to_lowercase().contains("dropper") {
                        "Alta".to_string()
                    } else {
                        "Media".to_string()
                    };
                    let (origin_source, origin_url, human_explanation, suggested_action) = samulibre_scanner::extract_file_origin_and_story(path, &threat_name);
                    let rec = samulibre_types::ThreatRecord {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        file_path: path.to_string_lossy().to_string(),
                        threat_name,
                        engine: res.engine.clone(),
                        sha256: res.sha256.clone(),
                        severity,
                        action_taken: "Pendiente".to_string(),
                        quarantine_id: None,
                        origin_source,
                        origin_url,
                        human_explanation,
                        suggested_action,
                    };
                    if let Ok(mut list) = detected_threats.lock() {
                        list.push(rec);
                    }
                }
            }

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
                let current_label = format!("{} [{} arch/s | {} hilos EcoQoS]", path.file_name().unwrap_or_default().to_string_lossy(), speed, scan_threads);
                let _ = proxy.send_event(CustomUserEvent::ScanProgress {
                    files_scanned: curr_scanned,
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

    let mut dirs = Vec::new();
    #[cfg(target_os = "windows")]
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let p = PathBuf::from(profile);
        dirs.push(p.join("Downloads"));
        dirs.push(p.join("Desktop"));
        dirs.push(p.join("Documents"));
        dirs.push(p.join("AppData").join("Local").join("Temp"));
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home);
            dirs.push(p.join("Downloads"));
            dirs.push(p.join("Desktop"));
            dirs.push(p.join("Documents"));
            dirs.push(p.join(".local/share"));
        }
        dirs.push(PathBuf::from("/tmp"));
        dirs.push(PathBuf::from("/var/tmp"));
        dirs.push(PathBuf::from("/dev/shm"));
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd);
    }

    let num_cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let scan_threads = if num_cpus > 8 { 5 } else if num_cpus > 4 { num_cpus - 2 } else { 1.max(num_cpus - 1) };
    let free_cores = num_cpus.saturating_sub(scan_threads);

    let _ = proxy.send_event(CustomUserEvent::ScanProgress {
        files_scanned: 0,
        current_file: format!("Preparando escaneo EcoQoS ({} hilos activos, {} núcleos libres)...", scan_threads, free_cores),
        threats_found: 0,
        is_done: false,
    });

    let mut candidate_paths = Vec::new();
    for dir in dirs {
        if !dir.exists() {
            continue;
        }
        for entry in WalkDir::new(&dir)
            .max_depth(25)
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
                IS_SCAN_IN_PROGRESS.store(false, Ordering::SeqCst);
                let _ = proxy.send_event(CustomUserEvent::ScanProgress {
                    files_scanned: 0,
                    current_file: "Análisis detenido por el usuario.".to_string(),
                    threats_found: 0,
                    is_done: true,
                });
                return;
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

    let scan_start = std::time::Instant::now();
    let (total_scanned, threats_found, infected_files) = scan_paths_parallel(candidate_paths, scanner_arc, proxy.clone());
    let elapsed_ms = scan_start.elapsed().as_millis() as u64;

    if !infected_files.is_empty() {
        let mut history = load_threat_history();
        for threat in &infected_files {
            if !history.iter().any(|h| h.file_path == threat.file_path && h.sha256 == threat.sha256 && h.action_taken == "Pendiente") {
                history.insert(0, threat.clone());
            }
        }
        save_threat_history(&history);
        let _ = proxy.send_event(CustomUserEvent::ThreatHistoryLoaded { history });
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
        current_file: if threats_found > 0 {
            format!("Escaneo multi-hilo finalizado en {:.2}s. {} amenaza(s) encontradas.", elapsed_ms as f64 / 1000.0, threats_found)
        } else {
            format!("Escaneo multi-hilo finalizado en {:.2}s. 0 amenazas. Sistema completamente limpio.", elapsed_ms as f64 / 1000.0)
        },
        threats_found,
        is_done: true,
    });
}
