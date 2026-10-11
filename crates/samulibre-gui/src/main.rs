use anyhow::Result;
use samulibre_core::SamuLibreCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tao::{
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use tracing::info;
use wry::WebViewBuilder;

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
    let _ = fs::create_dir_all(&canary_dir);
    let _ = fs::create_dir_all(&vpn_dir);

    let core = Arc::new(Mutex::new(SamuLibreCore::new(&canary_dir, &vpn_dir, true)));
    {
        if let Ok(c) = core.lock() {
            let _ = c.initialize();
        }
    }

    let core_for_ipc = Arc::clone(&core);

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("SamuLibre - Suite de Seguridad Open Source")
        .with_inner_size(tao::dpi::LogicalSize::new(1180.0, 800.0))
        .with_decorations(true)
        .build(&event_loop)?;

    let html_content = include_str!("../../../data/ui/index.html");

    let _webview = WebViewBuilder::new()
        .with_html(html_content)
        .with_ipc_handler(move |request| {
            let body = request.body();
            if let Ok(msg) = serde_json::from_str::<IpcMessage>(body) {
                match msg.action.as_str() {
                    "get_status" => {
                        if let Ok(c) = core_for_ipc.lock() {
                            let status = c.get_status();
                            info!("GUI solicitó estado: {:?}", status);
                        }
                    }
                    "scan" => {
                        let path_str = msg.payload.unwrap_or_else(|| "data/test_samples".to_string());
                        if let Ok(c) = core_for_ipc.lock() {
                            let res = c.scanner.scan_file(Path::new(&path_str));
                            info!("GUI escaneó archivo {}: {:?}", path_str, res);
                        }
                    }
                    "simulate_kb" => {
                        let kb = msg.payload.unwrap_or_else(|| "KB5041585".to_string());
                        if let Ok(mut c) = core_for_ipc.lock() {
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
