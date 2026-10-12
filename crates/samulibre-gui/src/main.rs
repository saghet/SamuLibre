#![windows_subsystem = "windows"]

use anyhow::Result;
use samulibre_core::SamuLibreCore;
use serde::{Deserialize, Serialize};
use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem, MenuEvent};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
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

    pub const THREAD_PRIORITY_LOWEST: i32 = -2;

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
    let item_quit = MenuItem::new("❌ Salir de SamuLibre", true, None);

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
                        std::thread::spawn(move || {
                            if let Some(folder) = open_native_folder_dialog() {
                                if let Ok(c) = core_browse_folder.lock() {
                                    let mut results = Vec::new();
                                    for entry in WalkDir::new(&folder).max_depth(4).into_iter().filter_map(|e| e.ok()) {
                                        if entry.file_type().is_file() {
                                            if let Ok(r) = c.scan_file_path(entry.path()) {
                                                results.push(r);
                                                if results.len() >= 60 {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    let _ = proxy_browse_folder.send_event(CustomUserEvent::BatchScanResults { results });
                                }
                            }
                        });
                    }

                    "scan_custom_path" => {
                        if let Some(payload_str) = msg.payload {
                            let proxy_paths = proxy_for_ipc.clone();
                            let core_paths = Arc::clone(&core_for_ipc);
                            std::thread::spawn(move || {
                                let mut paths_to_scan = Vec::new();
                                if let Ok(arr) = serde_json::from_str::<Vec<String>>(&payload_str) {
                                    paths_to_scan = arr.into_iter().map(PathBuf::from).collect();
                                } else {
                                    paths_to_scan.push(PathBuf::from(payload_str));
                                }

                                if let Ok(c) = core_paths.lock() {
                                    let mut results = Vec::new();
                                    for path in paths_to_scan {
                                        if path.is_file() {
                                            if let Ok(r) = c.scan_file_path(&path) {
                                                results.push(r);
                                            }
                                        } else if path.is_dir() {
                                            for entry in WalkDir::new(&path).max_depth(3).into_iter().filter_map(|e| e.ok()) {
                                                if entry.file_type().is_file() {
                                                    if let Ok(r) = c.scan_file_path(entry.path()) {
                                                        results.push(r);
                                                        if results.len() >= 60 { break; }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if results.len() == 1 {
                                        let _ = proxy_paths.send_event(CustomUserEvent::SingleScanResult { result: results.remove(0) });
                                    } else if !results.is_empty() {
                                        let _ = proxy_paths.send_event(CustomUserEvent::BatchScanResults { results });
                                    }
                                }
                            });
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
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status });
                        }
                    }

                    "reaudit_so" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let _ = c.reaudit_vulnerabilities();
                            let rules = c.get_patch_rules();
                            let os_info = c.get_os_info();
                            let sentinel_status = Some(c.get_sentinel_status());
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status });
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
                                let _ = proxy_cloned.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status });
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
                                let _ = proxy_cloned.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status });
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
                            let _ = proxy_for_ipc.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status });
                        }
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
            let rules = c.get_patch_rules();
            let os_info = c.get_os_info();
            let sentinel_status = Some(c.get_sentinel_status());
            let _ = proxy_init.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status });

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
        }
    });

    // Hilo Demonio Centinela de CVEs en segundo plano (EcoQoS - ciclo continuo cada 15 min)
    let proxy_sentinel = proxy.clone();
    let core_sentinel = Arc::clone(&core);
    std::thread::spawn(move || {
        win_eco::set_current_thread_eco_qos();
        loop {
            // Dormir 15 minutos entre ciclos periódicos de auditoría
            std::thread::sleep(std::time::Duration::from_secs(900));
            if let Ok(c) = core_sentinel.lock() {
                let (_unmitigated, _active, _native, auto_patched) = c.run_sentinel_audit_cycle();
                if !auto_patched.is_empty() {
                    let title = "🛡️ Centinela SamuLibre: Parche Virtual Aplicado".to_string();
                    let details = format!("Se mitigaron automáticamente: {}", auto_patched.join(", "));
                    let _ = proxy_sentinel.send_event(CustomUserEvent::RealTimeAlert { title, details });
                }
                let rules = c.get_patch_rules();
                let os_info = c.get_os_info();
                let sentinel_status = Some(c.get_sentinel_status());
                let _ = proxy_sentinel.send_event(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status });
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

            Event::UserEvent(CustomUserEvent::UpdatePatchRules { rules, os_info, sentinel_status }) => {
                let rules_json = serde_json::to_string(&rules).unwrap_or_else(|_| "[]".to_string());
                let os_json = serde_json::to_string(&os_info).unwrap_or_else(|_| "null".to_string());
                let sentinel_json = serde_json::to_string(&sentinel_status).unwrap_or_else(|_| "null".to_string());
                let script = format!(
                    "if (window.onPatchRulesUpdated) {{ window.onPatchRulesUpdated({}, {}, {}); }}",
                    rules_json, os_json, sentinel_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::ShowWindow) => {
                window.set_visible(true);
                window.set_minimized(false);
                window.set_focus();
            }

            Event::UserEvent(CustomUserEvent::TriggerScan) => {
                window.set_visible(true);
                window.set_minimized(false);
                window.set_focus();
                let _ = webview.evaluate_script("if (window.triggerQuickScan) { window.triggerQuickScan(); }");

                let proxy_scan = proxy.clone();
                let scanner_arc = if let Ok(c) = core_for_actions.lock() {
                    Arc::clone(&c.scanner)
                } else {
                    return;
                };

                std::thread::spawn(move || {
                    execute_scan_loop(proxy_scan, scanner_arc);
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

            Event::UserEvent(CustomUserEvent::RealTimeAlert { title, details }) => {
                let title_json = serde_json::to_string(&title).unwrap_or_else(|_| "\"\"".to_string());
                let details_json = serde_json::to_string(&details).unwrap_or_else(|_| "\"\"".to_string());
                let script = format!(
                    "if (window.showToast) {{ window.showToast({}, {}, true); }}",
                    title_json, details_json
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::Quit) => {
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

fn execute_scan_loop(
    proxy: EventLoopProxy<CustomUserEvent>,
    scanner_mutex: Arc<Mutex<samulibre_scanner::MultiEngineScanner>>,
) {
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

    let mut scanned_count = 0;
    let mut threats_count = 0;
    let mut last_ui_update = std::time::Instant::now();

    for dir in dirs {
        if !dir.exists() {
            continue;
        }
        for entry in WalkDir::new(&dir).max_depth(3).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                scanned_count += 1;
                if let Ok(s) = scanner_mutex.lock() {
                    if let Ok(res) = s.scan_file(path) {
                        if res.status == samulibre_types::FileScanStatus::Infected {
                            threats_count += 1;
                        }
                    }
                }

                if last_ui_update.elapsed() >= std::time::Duration::from_millis(35) {
                    let _ = proxy.send_event(CustomUserEvent::ScanProgress {
                        files_scanned: scanned_count,
                        current_file: path.to_string_lossy().to_string(),
                        threats_found: threats_count,
                        is_done: false,
                    });
                    last_ui_update = std::time::Instant::now();
                }
            }
        }
    }

    let _ = proxy.send_event(CustomUserEvent::ScanProgress {
        files_scanned: scanned_count,
        current_file: "Verificación de procesos y archivos completada.".to_string(),
        threats_found: threats_count,
        is_done: true,
    });
}
