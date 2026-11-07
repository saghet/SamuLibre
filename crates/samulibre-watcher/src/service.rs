use anyhow::Result;
use samulibre_types::SubsystemState;
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::info;

pub const SERVICE_NAME: &str = "SamuLibreWatcher";
pub const SERVICE_DISPLAY_NAME: &str = "SamuLibre Real-Time Protection Service";

/// Consulta el estado riguroso del servicio en Windows SCM o demonio en espacio de usuario
pub fn query_windows_service_state() -> (SubsystemState, String) {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("sc.exe");
        cmd.args(["query", SERVICE_NAME]);
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        if let Ok(output) = cmd.output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stdout.contains("RUNNING") {
                return (
                    SubsystemState::Running,
                    format!(
                        "Servicio Windows SCM '{}' activo y en ejecución permanente.",
                        SERVICE_NAME
                    ),
                );
            } else if stdout.contains("STOPPED") {
                return (
                    SubsystemState::Stopped,
                    format!(
                        "Servicio Windows SCM '{}' instalado pero en estado DETENIDO.",
                        SERVICE_NAME
                    ),
                );
            } else if stdout.contains("START_PENDING") {
                return (
                    SubsystemState::Starting,
                    format!(
                        "Servicio Windows SCM '{}' en proceso de arranque.",
                        SERVICE_NAME
                    ),
                );
            } else if stdout.contains("1060")
                || stderr.contains("1060")
                || stdout.contains("no existe")
            {
                // Verificar si hay proceso demonio con PID
                let pid_file = Path::new("data").join("samulibre_service.pid");
                if pid_file.exists() {
                    if let Ok(pid_str) = fs::read_to_string(&pid_file) {
                        if let Ok(pid) = pid_str.trim().parse::<u32>() {
                            if is_pid_alive(pid) {
                                return (
                                    SubsystemState::Degraded,
                                    format!("Demonio en espacio de usuario activo con PID {} (No registrado como Servicio SCM).", pid),
                                );
                            }
                        }
                    }
                }
                return (
                    SubsystemState::NotInstalled,
                    format!("El servicio de Windows '{}' no está registrado en el SCM (código 1060). La protección opera en espacio de usuario.", SERVICE_NAME),
                );
            }
        }
    }

    // Si hay un archivo PID activo en modo demonio
    let pid_file = Path::new("data").join("samulibre_service.pid");
    if pid_file.exists() {
        if let Ok(pid_str) = fs::read_to_string(&pid_file) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                if is_pid_alive(pid) {
                    return (
                        SubsystemState::Degraded,
                        format!("Demonio activo en espacio de usuario (PID: {}).", pid),
                    );
                }
            }
        }
    }

    (
        SubsystemState::Stopped,
        "No hay servicio Windows ni proceso demonio activo en el sistema.".to_string(),
    )
}

/// Verifica si el servicio Windows o el proceso demonio está ejecutándose
pub fn is_service_or_daemon_running() -> bool {
    // 1. Comprobar si el proceso del PID guardado sigue activo
    let pid_file = Path::new("data").join("samulibre_service.pid");
    if pid_file.exists() {
        if let Ok(pid_str) = fs::read_to_string(&pid_file) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                if is_pid_alive(pid) {
                    return true;
                }
            }
        }
    }

    // 2. En Windows, consultar Service Control Manager (sc.exe query)
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("sc.exe");
        cmd.args(["query", SERVICE_NAME]);
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        if let Ok(output) = cmd.output() {
            let out_str = String::from_utf8_lossy(&output.stdout);
            if out_str.contains("RUNNING") {
                return true;
            }
        }
    }

    // 3. Comprobar si data/realtime_telemetry.json fue actualizado recientemente (menos de 60 segundos)
    let telem_file = Path::new("data").join("realtime_telemetry.json");
    if telem_file.exists() {
        if let Ok(meta) = fs::metadata(&telem_file) {
            if let Ok(modified) = meta.modified() {
                if let Ok(elapsed) = modified.elapsed() {
                    if elapsed.as_secs() < 60 {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Comprueba si un PID específico sigue activo en el sistema operativo
fn is_pid_alive(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("tasklist");
        cmd.args(["/FI", &format!("PID eq {}", pid), "/NH"]);
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        if let Ok(out) = cmd.output() {
            let s = String::from_utf8_lossy(&out.stdout);
            return s.contains(&pid.to_string());
        }
        false
    }

    #[cfg(not(target_os = "windows"))]
    {
        Path::new(&format!("/proc/{}", pid)).exists()
    }
}

/// Registra el proceso actual en el archivo PID de servicio
pub fn record_service_pid() -> Result<()> {
    let _ = fs::create_dir_all("data");
    let pid_file = Path::new("data").join("samulibre_service.pid");
    fs::write(&pid_file, std::process::id().to_string())?;
    Ok(())
}

/// Limpia el archivo PID al terminar la ejecución
pub fn remove_service_pid() {
    let pid_file = Path::new("data").join("samulibre_service.pid");
    let _ = fs::remove_file(pid_file);
}

/// Comprueba si el proceso actual corre con privilegios elevados de Administrador
pub fn is_running_as_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/c", "net session >nul 2>&1"]);
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
        if let Ok(out) = cmd.status() {
            return out.success();
        }
        false
    }
    #[cfg(not(target_os = "windows"))]
    {
        unsafe { libc::geteuid() == 0 }
    }
}

/// Instala el servicio en el Service Control Manager de Windows con soporte UAC
pub fn install_windows_service_elevated(exe_path: &Path) -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        let bin_arg = format!("\"{}\" service run", exe_path.display());
        let create_cmd = format!(
            "sc.exe create {} binPath= \"{}\" start= auto DisplayName= \"{}\" & sc.exe failure {} reset= 86400 actions= restart/5000/restart/10000/none & sc.exe start {}",
            SERVICE_NAME, bin_arg, SERVICE_DISPLAY_NAME, SERVICE_NAME, SERVICE_NAME
        );

        if is_running_as_admin() {
            let mut cmd = Command::new("cmd.exe");
            cmd.args(["/c", &create_cmd]);
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
            let output = cmd.output()?;
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            if output.status.success() {
                info!(
                    "Servicio Windows '{}' instalado y arrancado con éxito.",
                    SERVICE_NAME
                );
                Ok(format!(
                    "Servicio Windows registrado y arrancado: {}",
                    stdout
                ))
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                anyhow::bail!("Error al instalar servicio en SCM: {} {}", stdout, stderr);
            }
        } else {
            // Solicitar elevación nativa UAC de Windows
            let ps_script = format!(
                "Start-Process cmd.exe -ArgumentList '/c {}' -Verb RunAs -WindowStyle Hidden -Wait",
                create_cmd
            );
            let mut cmd = Command::new("powershell.exe");
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_script]);
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
            let status = cmd.status()?;
            if status.success() {
                let (state, _detail) = query_windows_service_state();
                if state == SubsystemState::Running
                    || state == SubsystemState::Starting
                    || state == SubsystemState::Stopped
                {
                    return Ok(format!(
                        "Servicio instalado vía UAC con éxito. Estado: {:?}",
                        state
                    ));
                }
            }
            anyhow::bail!("La instalación del servicio requiere elevación de Administrador (UAC).");
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        anyhow::bail!("La instalación vía Service Control Manager solo está soportada en Windows");
    }
}

/// Desinstala el servicio de Windows con soporte UAC
pub fn uninstall_windows_service_elevated() -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        let delete_cmd = format!(
            "sc.exe stop {} & sc.exe delete {}",
            SERVICE_NAME, SERVICE_NAME
        );
        if is_running_as_admin() {
            let mut cmd = Command::new("cmd.exe");
            cmd.args(["/c", &delete_cmd]);
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
            let output = cmd.output()?;
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Ok(format!("Servicio eliminado del sistema: {}", stdout))
        } else {
            let ps_script = format!(
                "Start-Process cmd.exe -ArgumentList '/c {}' -Verb RunAs -WindowStyle Hidden -Wait",
                delete_cmd
            );
            let mut cmd = Command::new("powershell.exe");
            cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_script]);
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
            let _ = cmd.status();
            Ok("Servicio desinstalado vía UAC.".to_string())
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        anyhow::bail!("Solo soportado en Windows");
    }
}

/// Instala el servicio en el Service Control Manager de Windows (Requiere Administrador)
pub fn install_windows_service(exe_path: &Path) -> Result<String> {
    install_windows_service_elevated(exe_path)
}

/// Desinstala el servicio de Windows
pub fn uninstall_windows_service() -> Result<String> {
    uninstall_windows_service_elevated()
}

/// Inicia el servicio en segundo plano
pub fn start_service() -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        // 1. Si no está instalado en SCM, intentar instalarlo y arrancarlo con elevación UAC
        let (state, _) = query_windows_service_state();
        if state == SubsystemState::NotInstalled {
            let exe = if let Ok(e) = std::env::current_exe() {
                let dir = e.parent().unwrap_or(Path::new("."));
                let cli_exe = dir.join("samulibre.exe");
                if cli_exe.exists() {
                    cli_exe
                } else {
                    e
                }
            } else {
                std::path::PathBuf::from("samulibre.exe")
            };
            return install_windows_service_elevated(&exe);
        }

        // 2. Si ya está instalado en SCM, intentar arrancar directamente
        let mut cmd = Command::new("sc.exe");
        cmd.args(["start", SERVICE_NAME]);
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
        if let Ok(output) = cmd.output() {
            if output.status.success() {
                return Ok("Servicio Windows SCM iniciado con éxito.".to_string());
            } else {
                let err_str = String::from_utf8_lossy(&output.stderr);
                if err_str.contains("5") || output.status.code() == Some(5) {
                    // Acceso denegado -> elevar vía UAC
                    let ps_script = format!(
                        "Start-Process sc.exe -ArgumentList 'start {}' -Verb RunAs -WindowStyle Hidden -Wait",
                        SERVICE_NAME
                    );
                    let mut uac_cmd = Command::new("powershell.exe");
                    uac_cmd.args(["-NoProfile", "-NonInteractive", "-Command", &ps_script]);
                    uac_cmd.creation_flags(0x08000000);
                    let _ = uac_cmd.status();
                    return Ok("Servicio Windows iniciado con elevación UAC.".to_string());
                }
            }
        }
    }

    // Fallback: Si no está registrado en SCM o falla, iniciar proceso desacoplado
    if let Ok(exe_path) = std::env::current_exe() {
        let dir = exe_path.parent().unwrap_or(Path::new("."));
        let target_exe = if dir.join("samulibre.exe").exists() {
            dir.join("samulibre.exe")
        } else {
            exe_path
        };
        let mut daemon_cmd = Command::new(target_exe);
        daemon_cmd.arg("service").arg("run");
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            daemon_cmd.creation_flags(0x08000000 | 0x00000200); // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
        }
        let child = daemon_cmd.spawn()?;
        Ok(format!(
            "Proceso demonio de protección en tiempo real iniciado con PID {}",
            child.id()
        ))
    } else {
        anyhow::bail!("No se pudo determinar el ejecutable actual para iniciar el demonio.");
    }
}

/// Detiene el servicio o proceso demonio
pub fn stop_service() -> Result<String> {
    let pid_file = Path::new("data").join("samulibre_service.pid");
    if pid_file.exists() {
        if let Ok(pid_str) = fs::read_to_string(&pid_file) {
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                #[cfg(target_os = "windows")]
                {
                    let mut cmd = Command::new("taskkill");
                    cmd.args(["/F", "/PID", &pid.to_string()]);
                    use std::os::windows::process::CommandExt;
                    cmd.creation_flags(0x08000000);
                    let _ = cmd.output();
                }
                #[cfg(not(target_os = "windows"))]
                {
                    let _ = Command::new("kill")
                        .arg("-15")
                        .arg(pid.to_string())
                        .output();
                }
            }
        }
        let _ = fs::remove_file(&pid_file);
    }

    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("sc.exe");
        cmd.args(["stop", SERVICE_NAME]);
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
        let _ = cmd.output();
    }

    Ok("Protección en segundo plano detenida correctamente.".to_string())
}

/// Ejecuta el servicio integrando el despachador oficial SCM de Windows con fallback a demonio
pub fn run_service_dispatcher<F>(worker: F) -> Result<()>
where
    F: FnOnce() -> Result<()> + Send + 'static,
{
    #[cfg(target_os = "windows")]
    {
        use std::time::Duration;
        use windows_service::{
            define_windows_service,
            service::{
                ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
                ServiceType,
            },
            service_control_handler::{self, ServiceControlHandlerResult},
            service_dispatcher,
        };

        define_windows_service!(ffi_service_main, my_service_main);

        fn my_service_main(_arguments: Vec<std::ffi::OsString>) {
            let event_handler = move |control_event| -> ServiceControlHandlerResult {
                match control_event {
                    ServiceControl::Stop | ServiceControl::Interrogate => {
                        ServiceControlHandlerResult::NoError
                    }
                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            };

            if let Ok(status_handle) =
                service_control_handler::register(SERVICE_NAME, event_handler)
            {
                let running_status = ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::Running,
                    controls_accepted: ServiceControlAccept::STOP,
                    exit_code: ServiceExitCode::Win32(0),
                    checkpoint: 0,
                    wait_hint: Duration::default(),
                    process_id: None,
                };
                let _ = status_handle.set_service_status(running_status);

                let _ = record_service_pid();
                let quarantine_dir = Path::new("data").join("quarantine");
                let scanner = std::sync::Arc::new(std::sync::Mutex::new(
                    samulibre_scanner::MultiEngineScanner::new(),
                ));
                let watcher = crate::RealTimeWatcher::new(scanner, &quarantine_dir);
                let _ = watcher.start_background_watcher(|alert| {
                    tracing::warn!(
                        "[SERVICE SYSTEM 24/7] Amenaza interceptada: {} {:?}",
                        alert.title,
                        alert.target_path
                    );
                });

                loop {
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }

        match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            Ok(_) => Ok(()),
            Err(e) => {
                info!("Despachador SCM no activo (ejecución standalone: {:?}), usando bucle estándar...", e);
                worker()
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        worker()
    }
}
