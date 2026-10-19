use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use samulibre_core::SamuLibreCore;
use samulibre_types::{
    AndroidPackageInfo, AndroidSecurityInfo, ScanResult, TunPacketAction,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use tracing::info;

static CORE_INSTANCE: OnceLock<Mutex<SamuLibreCore>> = OnceLock::new();

#[derive(Debug, Serialize, Deserialize)]
struct IpcRequest {
    action: String,
    #[serde(default)]
    payload: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IpcResponse {
    success: bool,
    action: String,
    #[serde(default)]
    data: Option<serde_json::Value>,
    #[serde(default)]
    error: Option<String>,
}

fn get_core() -> Option<&'static Mutex<SamuLibreCore>> {
    CORE_INSTANCE.get()
}

/// Inicializa el núcleo de SamuLibre en Android con el directorio de datos privado del sandbox
#[no_mangle]
pub extern "system" fn Java_org_samulibre_app_NativeBridge_initCore(
    mut env: JNIEnv,
    _class: JClass,
    app_data_dir: JString,
) -> jboolean {
    let dir_str: String = match env.get_string(&app_data_dir) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };

    let base_dir = PathBuf::from(dir_str);
    let canary_dir = base_dir.join("canaries");
    let vpn_dir = base_dir.join("vpn");
    let _ = std::fs::create_dir_all(&canary_dir);
    let _ = std::fs::create_dir_all(&vpn_dir);

    info!("Iniciando SamuLibre Core en Android desde: {:?}", base_dir);
    let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);
    let _ = core.initialize();

    // Cargar catálogo ASB en el patcher
    if let Ok(mut patcher) = core.patcher.lock() {
        patcher.load_android_asb_catalog();
    }

    if CORE_INSTANCE.set(Mutex::new(core)).is_ok() {
        JNI_TRUE
    } else {
        JNI_TRUE // Ya inicializado
    }
}

/// Devuelve la versión de SamuLibre Engine
#[no_mangle]
pub extern "system" fn Java_org_samulibre_app_NativeBridge_getCoreVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let ver = "SamuLibre Android Mobile EDR v0.2.0 (Zero-Root Shield)";
    let output = env.new_string(ver).unwrap_or_else(|_| env.new_string("0.2.0").unwrap());
    output.into_raw()
}

/// Despacha comandos IPC JSON enviados por la UI WebView o servicios en segundo plano de Android
#[no_mangle]
pub extern "system" fn Java_org_samulibre_app_NativeBridge_dispatchIpc(
    mut env: JNIEnv,
    _class: JClass,
    action_json: JString,
) -> jstring {
    let json_text: String = match env.get_string(&action_json) {
        Ok(s) => s.into(),
        Err(e) => {
            let err_resp = serde_json::to_string(&IpcResponse {
                success: false,
                action: "error".to_string(),
                data: None,
                error: Some(format!("Error decodificando JString: {:?}", e)),
            })
            .unwrap_or_default();
            return env.new_string(err_resp).unwrap().into_raw();
        }
    };

    let req: IpcRequest = match serde_json::from_str(&json_text) {
        Ok(r) => r,
        Err(e) => {
            let err_resp = serde_json::to_string(&IpcResponse {
                success: false,
                action: "parse_error".to_string(),
                data: None,
                error: Some(format!("JSON inválido: {:?}", e)),
            })
            .unwrap_or_default();
            return env.new_string(err_resp).unwrap().into_raw();
        }
    };

    let response = execute_ipc_action(&req);
    let out_json = serde_json::to_string(&response).unwrap_or_default();
    env.new_string(out_json).unwrap().into_raw()
}

/// Ejecuta la acción correspondiente en el motor SamuLibre
fn execute_ipc_action(req: &IpcRequest) -> IpcResponse {
    let core_lock = match get_core() {
        Some(c) => c,
        None => {
            return IpcResponse {
                success: false,
                action: req.action.clone(),
                data: None,
                error: Some("SamuLibre Core no ha sido inicializado.".to_string()),
            };
        }
    };

    let core = match core_lock.lock() {
        Ok(c) => c,
        Err(_) => {
            return IpcResponse {
                success: false,
                action: req.action.clone(),
                data: None,
                error: Some("Lock poisoning en SamuLibre Core".to_string()),
            };
        }
    };

    match req.action.as_str() {
        "get_dashboard_status" => {
            let status = core.get_status();
            IpcResponse {
                success: true,
                action: req.action.clone(),
                data: serde_json::to_value(&status).ok(),
                error: None,
            }
        }

        "audit_android_security" => {
            if let Some(payload_str) = &req.payload {
                if let Ok(info) = serde_json::from_str::<AndroidSecurityInfo>(payload_str) {
                    if let Ok(mut patcher) = core.patcher.lock() {
                        let evaluated_rules = patcher.audit_android_security(&info);
                        return IpcResponse {
                            success: true,
                            action: req.action.clone(),
                            data: serde_json::to_value(&evaluated_rules).ok(),
                            error: None,
                        };
                    }
                }
            }
            IpcResponse {
                success: false,
                action: req.action.clone(),
                data: None,
                error: Some("Payload de AndroidSecurityInfo no válido o ausente".to_string()),
            }
        }

        "audit_android_packages" => {
            if let Some(payload_str) = &req.payload {
                if let Ok(packages) = serde_json::from_str::<Vec<AndroidPackageInfo>>(payload_str) {
                    if let Ok(shield) = core.shield.lock() {
                        let alerts = shield.audit_android_packages(&packages);
                        return IpcResponse {
                            success: true,
                            action: req.action.clone(),
                            data: serde_json::to_value(&alerts).ok(),
                            error: None,
                        };
                    }
                }
            }
            IpcResponse {
                success: false,
                action: req.action.clone(),
                data: None,
                error: Some("Lista de AndroidPackageInfo inválida".to_string()),
            }
        }

        "get_android_asb_advisories" => {
            if let Ok(patcher) = core.patcher.lock() {
                IpcResponse {
                    success: true,
                    action: req.action.clone(),
                    data: serde_json::to_value(&patcher.monitored_asbs).ok(),
                    error: None,
                }
            } else {
                IpcResponse {
                    success: false,
                    action: req.action.clone(),
                    data: None,
                    error: Some("Error accediendo a patcher".to_string()),
                }
            }
        }

        "toggle_virtual_patch" => {
            if let Some(cve) = &req.payload {
                if let Ok(mut patcher) = core.patcher.lock() {
                    let current = patcher.get_rules().iter().find(|r| r.cve == *cve).map(|r| r.status.clone());
                    let enable = current != Some(samulibre_types::PatchStatus::VirtualPatchActive);
                    if let Ok(rule) = patcher.toggle_patch(cve, enable) {
                        return IpcResponse {
                            success: true,
                            action: req.action.clone(),
                            data: serde_json::to_value(&rule).ok(),
                            error: None,
                        };
                    }
                }
            }
            IpcResponse {
                success: false,
                action: req.action.clone(),
                data: None,
                error: Some("Error al alternar regla de parchado virtual".to_string()),
            }
        }

        "toggle_port_shield" => {
            if let Some(payload_str) = &req.payload {
                #[derive(Deserialize)]
                struct PortPayload {
                    port: u16,
                    close: bool,
                }
                if let Ok(p) = serde_json::from_str::<PortPayload>(payload_str) {
                    if let Ok(mut shield) = core.shield.lock() {
                        let msg = shield.toggle_port_shield(p.port, p.close).unwrap_or_else(|e| e.to_string());
                        return IpcResponse {
                            success: true,
                            action: req.action.clone(),
                            data: Some(serde_json::json!({ "message": msg, "closed_ports": shield.get_closed_ports() })),
                            error: None,
                        };
                    }
                }
            }
            IpcResponse {
                success: false,
                action: req.action.clone(),
                data: None,
                error: Some("Parámetros de toggle_port_shield inválidos".to_string()),
            }
        }

        "close_all_risk_ports" => {
            if let Ok(mut shield) = core.shield.lock() {
                let msg = shield.close_all_risk_ports().unwrap_or_else(|e| e.to_string());
                IpcResponse {
                    success: true,
                    action: req.action.clone(),
                    data: Some(serde_json::json!({ "message": msg, "closed_ports": shield.get_closed_ports() })),
                    error: None,
                }
            } else {
                IpcResponse {
                    success: false,
                    action: req.action.clone(),
                    data: None,
                    error: Some("Error accediendo al escudo de red".to_string()),
                }
            }
        }

        "get_vpn_info" => {
            let (state, countries) = if let Ok(vpn) = core.vpn.lock() {
                (vpn.get_state(), vpn.get_available_countries())
            } else {
                (core.get_vpn_state(), Vec::new())
            };
            IpcResponse {
                success: true,
                action: req.action.clone(),
                data: Some(serde_json::json!({
                    "state": state,
                    "countries": countries
                })),
                error: None,
            }
        }

        "refresh_vpn_pings" => {
            let latencies = core.refresh_vpn_latencies();
            IpcResponse {
                success: true,
                action: req.action.clone(),
                data: serde_json::to_value(&latencies).ok(),
                error: None,
            }
        }

        "connect_vpn" => {
            let payload = req.payload.as_deref().unwrap_or("CH");
            let parts: Vec<&str> = payload.split('|').collect();
            let country_id = parts[0];
            let double = parts.get(1).map(|&s| s == "double").unwrap_or(false);
            let _ = core.connect_vpn_ext(country_id, false, double);
            let (state, countries) = if let Ok(vpn) = core.vpn.lock() {
                (vpn.get_state(), vpn.get_available_countries())
            } else {
                (core.get_vpn_state(), Vec::new())
            };
            IpcResponse {
                success: true,
                action: req.action.clone(),
                data: Some(serde_json::json!({
                    "state": state,
                    "countries": countries
                })),
                error: None,
            }
        }

        "disconnect_vpn" => {
            let _ = core.disconnect_vpn();
            let (state, countries) = if let Ok(vpn) = core.vpn.lock() {
                (vpn.get_state(), vpn.get_available_countries())
            } else {
                (core.get_vpn_state(), Vec::new())
            };
            IpcResponse {
                success: true,
                action: req.action.clone(),
                data: Some(serde_json::json!({
                    "state": state,
                    "countries": countries
                })),
                error: None,
            }
        }

        "get_patch_rules" | "reaudit_so" => {
            if let Ok(patcher) = core.patcher.lock() {
                let rules = patcher.get_rules();
                let asbs = patcher.monitored_asbs.clone();
                IpcResponse {
                    success: true,
                    action: req.action.clone(),
                    data: Some(serde_json::json!({
                        "rules": rules,
                        "asb_advisories": asbs,
                        "is_android": true,
                        "sentinel_status": {
                            "total_cves_audited": rules.len(),
                            "auto_patch_enabled": true,
                            "last_audit_time": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
                        }
                    })),
                    error: None,
                }
            } else {
                IpcResponse {
                    success: false,
                    action: req.action.clone(),
                    data: None,
                    error: Some("Error accediendo a reglas ASB del patcher".to_string()),
                }
            }
        }

        "get_shield_status" => {
            let status = core.get_shield_status();
            IpcResponse {
                success: true,
                action: req.action.clone(),
                data: serde_json::to_value(&status).ok(),
                error: None,
            }
        }

        "get_network_sockets" => {
            let sockets = core.get_network_sockets();
            let closed_ports = if let Ok(shield) = core.shield.lock() {
                shield.get_closed_ports()
            } else {
                Vec::new()
            };
            IpcResponse {
                success: true,
                action: req.action.clone(),
                data: Some(serde_json::json!({
                    "sockets": sockets,
                    "closed_ports": closed_ports
                })),
                error: None,
            }
        }

        "run_internal_audit" => {
            let report = core.run_internal_security_audit();
            IpcResponse {
                success: true,
                action: req.action.clone(),
                data: serde_json::to_value(&report).ok(),
                error: None,
            }
        }

        "get_update_history" => {
            let history = core.get_signature_update_history();
            IpcResponse {
                success: true,
                action: req.action.clone(),
                data: serde_json::to_value(&history).ok(),
                error: None,
            }
        }

        "update_signatures_now" => {
            let (new_count, total) = if let Ok(mut scanner) = core.scanner.lock() {
                if let Ok(rep) = scanner.update_signatures() {
                    (rep.new_added, rep.total_signatures)
                } else {
                    (0, scanner.signature_count())
                }
            } else {
                (0, 0)
            };
            IpcResponse {
                success: true,
                action: req.action.clone(),
                data: Some(serde_json::json!({
                    "new_signatures": new_count,
                    "total_signatures": total
                })),
                error: None,
            }
        }

        "get_quarantine_records" => {
            let records = core.get_quarantined_records();
            IpcResponse {
                success: true,
                action: req.action.clone(),
                data: serde_json::to_value(&records).ok(),
                error: None,
            }
        }

        "scan_custom_path" => {
            if let Some(path_str) = &req.payload {
                let p = Path::new(path_str);
                let result = core.scan_file_path(p).unwrap_or_else(|e| ScanResult {
                    file_path: path_str.clone(),
                    sha256: "unknown".to_string(),
                    status: samulibre_types::FileScanStatus::AccessDenied,
                    detection_name: Some(format!("Error: {}", e)),
                    engine: "SamuLibre Mobile Engine".to_string(),
                    scan_time_ms: 0,
                });
                IpcResponse {
                    success: true,
                    action: req.action.clone(),
                    data: serde_json::to_value(&result).ok(),
                    error: None,
                }
            } else {
                IpcResponse {
                    success: false,
                    action: req.action.clone(),
                    data: None,
                    error: Some("Ruta de archivo no provista".to_string()),
                }
            }
        }

        "ask_copilot" => {
            if let Some(query) = &req.payload {
                let response = core.ask_copilot(query);
                IpcResponse {
                    success: true,
                    action: req.action.clone(),
                    data: serde_json::to_value(&response).ok(),
                    error: None,
                }
            } else {
                IpcResponse {
                    success: false,
                    action: req.action.clone(),
                    data: None,
                    error: Some("Pregunta vacía".to_string()),
                }
            }
        }

        _ => IpcResponse {
            success: false,
            action: req.action.clone(),
            data: None,
            error: Some(format!("Acción no reconocida: {}", req.action)),
        },
    }
}

/// Inspecciona un paquete recibido por la interfaz TUN del VpnService de Android
#[no_mangle]
pub extern "system" fn Java_org_samulibre_app_NativeBridge_processTunPacket(
    env: JNIEnv,
    _class: JClass,
    packet: JByteArray,
) -> jstring {
    let bytes: Vec<u8> = match env.convert_byte_array(&packet) {
        Ok(b) => b,
        Err(_) => {
            let resp = serde_json::json!({ "action": "ACCEPT" });
            return env.new_string(resp.to_string()).unwrap().into_raw();
        }
    };

    if let Some(core_lock) = get_core() {
        if let Ok(core) = core_lock.lock() {
            if let Ok(shield) = core.shield.lock() {
                let action = shield.process_tun_packet(&bytes);
                let json_action = match action {
                    TunPacketAction::Accept => serde_json::json!({ "action": "ACCEPT" }),
                    TunPacketAction::Drop { reason, rule_id, src_ip, dst_ip, port } => {
                        serde_json::json!({
                            "action": "DROP",
                            "reason": reason,
                            "rule_id": rule_id,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "port": port
                        })
                    }
                };
                return env.new_string(json_action.to_string()).unwrap().into_raw();
            }
        }
    }

    let default_resp = serde_json::json!({ "action": "ACCEPT" });
    env.new_string(default_resp.to_string()).unwrap().into_raw()
}

/// Escanea un archivo APK recién descargado o instalado
#[no_mangle]
pub extern "system" fn Java_org_samulibre_app_NativeBridge_scanApkFile(
    mut env: JNIEnv,
    _class: JClass,
    apk_path: JString,
) -> jstring {
    let path_str: String = match env.get_string(&apk_path) {
        Ok(s) => s.into(),
        Err(_) => {
            let res = serde_json::json!({ "status": "AccessDenied" });
            return env.new_string(res.to_string()).unwrap().into_raw();
        }
    };

    let p = Path::new(&path_str);
    let result = if let Some(core_lock) = get_core() {
        if let Ok(core) = core_lock.lock() {
            core.scan_file_path(p).ok()
        } else {
            None
        }
    } else {
        None
    };

    let json_result = serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string());
    env.new_string(json_result).unwrap().into_raw()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_action_execution() {
        let temp_dir = std::env::temp_dir().join(format!("samulibre_jni_test_{}", std::process::id()));
        let canary = temp_dir.join("canaries");
        let vpn = temp_dir.join("vpn");
        let _ = std::fs::create_dir_all(&canary);
        let _ = std::fs::create_dir_all(&vpn);

        let core = SamuLibreCore::new(&canary, &vpn, true);
        let _ = core.initialize();
        if let Ok(mut patcher) = core.patcher.lock() {
            patcher.load_android_asb_catalog();
        }
        let _ = CORE_INSTANCE.set(Mutex::new(core));

        let req = IpcRequest {
            action: "get_dashboard_status".to_string(),
            payload: None,
        };
        let resp = execute_ipc_action(&req);
        assert!(resp.success);
        assert!(resp.data.is_some());

        // Probar auditoría de seguridad Android
        let android_info = AndroidSecurityInfo {
            sdk_int: 31,
            release_version: "12".to_string(),
            security_patch_level: "2021-05-01".to_string(),
            kernel_version: "5.4.86".to_string(),
            manufacturer: "Motorola".to_string(),
            model: "Moto G Power".to_string(),
            is_root_detected: false,
            unpatched_asb_cves: vec![],
            active_tun_rules_count: 0,
            overlay_shield_active: true,
            accessibility_guard_active: true,
        };
        let audit_req = IpcRequest {
            action: "audit_android_security".to_string(),
            payload: Some(serde_json::to_string(&android_info).unwrap()),
        };
        let audit_resp = execute_ipc_action(&audit_req);
        assert!(audit_resp.success);
        assert!(audit_resp.data.is_some());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
