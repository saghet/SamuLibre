use crate::types::{TorProtectionHealth, TorSecureModeConfig, TorSecureModeState};
use crate::wfp::WfpController;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;
use sysinfo::{ProcessesToUpdate, System};
use tracing::{info, warn};

const TOR_LIMITATIONS_NOTICE: &str = "Aviso técnico: Tor Secure Mode bloquea conexiones directas IPv4/IPv6/UDP/DNS de las aplicaciones protegidas mediante WFP para evitar fugas de red, pero no garantiza anonimato absoluto frente a correlación de tráfico global, huellas digitales del navegador (fingerprinting), explotación del navegador o fugas en capas de aplicación.";

#[derive(Debug, Clone)]
pub struct TorDiscoveryInfo {
    pub tor_browser_pids: Vec<u32>,
    pub tor_browser_paths: Vec<String>,
    pub tor_daemon_pid: Option<u32>,
    pub tor_daemon_path: Option<String>,
    pub pluggable_transports: Vec<String>,
    pub bridges_configured: bool,
    pub detected_socks_port: Option<u16>,
    pub detected_control_port: Option<u16>,
}

/// Controlador de Tor Secure Mode con Kill Switch Fail-Closed sobre WFP.
pub struct TorSecureModeManager {
    pub config: TorSecureModeConfig,
    pub applied_filter_ids: Vec<u64>,
    pub direct_leak_attempts_blocked: u64,
    last_socks_reachable: bool,
    last_discovery: Option<TorDiscoveryInfo>,
}

impl TorSecureModeManager {
    pub fn new(config: TorSecureModeConfig) -> Self {
        Self {
            config,
            applied_filter_ids: Vec::new(),
            direct_leak_attempts_blocked: 0,
            last_socks_reachable: false,
            last_discovery: None,
        }
    }

    /// Detecta procesos de Tor Browser, daemon `tor.exe` y pluggable transports (`obfs4proxy`, `snowflake`, `lyrebird`)
    pub fn discover_tor_environment(&mut self) -> TorDiscoveryInfo {
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All);

        let mut tor_browser_pids = Vec::new();
        let mut tor_browser_paths = Vec::new();
        let mut tor_daemon_pid = None;
        let mut tor_daemon_path = None;
        let mut pluggable_transports = Vec::new();
        let mut detected_socks_port = None;
        let mut detected_control_port = None;
        let mut bridges_configured = false;

        for (pid, proc) in sys.processes() {
            let name = proc.name().to_string_lossy().to_lowercase();
            let exe_str = proc
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let exe_lower = exe_str.to_lowercase();

            if (name == "firefox.exe" || name == "torbrowser.exe")
                && (exe_lower.contains("tor browser") || exe_lower.contains("torbrowser"))
            {
                tor_browser_pids.push(pid.as_u32());
                if !exe_str.is_empty() && !tor_browser_paths.contains(&exe_str) {
                    tor_browser_paths.push(exe_str.clone());
                }
            } else if name == "tor.exe" || name == "tor" {
                tor_daemon_pid = Some(pid.as_u32());
                if !exe_str.is_empty() {
                    tor_daemon_path = Some(exe_str.clone());
                    // Intentar localizar torrc cerca de tor.exe (Tor Browser Data/Tor/torrc)
                    if let Some(tor_dir) = Path::new(&exe_str).parent() {
                        for candidate in [
                            tor_dir.join("torrc"),
                            tor_dir.join("../../Data/Tor/torrc"),
                            tor_dir.join("../Data/Tor/torrc"),
                        ] {
                            if let Ok(content) = fs::read_to_string(&candidate) {
                                let (sp, cp, br) = parse_torrc(&content);
                                if sp.is_some() {
                                    detected_socks_port = sp;
                                }
                                if cp.is_some() {
                                    detected_control_port = cp;
                                }
                                if br {
                                    bridges_configured = true;
                                }
                                break;
                            }
                        }
                    }
                }
            } else if name.contains("obfs4proxy")
                || name.contains("snowflake-client")
                || name.contains("lyrebird")
                || name.contains("conjure-client")
            {
                if !pluggable_transports.contains(&name) {
                    pluggable_transports.push(name);
                }
            }
        }

        // También inspeccionar rutas configuradas manualmente aunque el proceso no haya arrancado aún
        for configured_path in &self.config.protected_app_paths {
            if !configured_path.is_empty() && !tor_browser_paths.contains(configured_path) {
                tor_browser_paths.push(configured_path.clone());
            }
        }

        let info = TorDiscoveryInfo {
            tor_browser_pids,
            tor_browser_paths,
            tor_daemon_pid,
            tor_daemon_path,
            pluggable_transports,
            bridges_configured,
            detected_socks_port,
            detected_control_port,
        };
        self.last_discovery = Some(info.clone());
        info
    }

    /// Verifica conectividad real al proxy SOCKS5 local enviando saludo SOCKS5 (`0x05 0x01 0x00`).
    pub fn probe_socks5_health(&mut self, port: u16) -> bool {
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let ok = match TcpStream::connect_timeout(&addr, Duration::from_millis(350)) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(350)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(350)));
                if stream.write_all(&[0x05, 0x01, 0x00]).is_ok() {
                    let mut resp = [0u8; 2];
                    stream.read_exact(&mut resp).is_ok() && resp[0] == 0x05
                } else {
                    false
                }
            }
            Err(_) => false,
        };
        self.last_socks_reachable = ok;
        ok
    }

    /// Aplica o actualiza las políticas WFP de Tor Secure Mode (Fail-Closed).
    /// Las reglas de aislamiento se aplican *antes* o *independientemente* de si Tor está conectado,
    /// manteniendo el Kill Switch si el servicio Tor cae.
    pub fn sync_policies(&mut self, wfp: &mut WfpController) -> TorSecureModeState {
        let discovery = self.discover_tor_environment();
        let socks_port = discovery.detected_socks_port.unwrap_or(self.config.socks_port);
        let control_port = discovery.detected_control_port.unwrap_or(self.config.control_port);
        let socks_ok = self.probe_socks5_health(socks_port);

        if !self.config.enabled {
            if !self.applied_filter_ids.is_empty() {
                wfp.remove_filters(&self.applied_filter_ids);
                self.applied_filter_ids.clear();
                info!("Filtros WFP de Tor Secure Mode removidos al desactivar modo.");
            }
            return self.build_state(&discovery, socks_port, socks_ok, TorProtectionHealth::Inactive, "Tor Secure Mode desactivado.");
        }

        // Si está activado, aseguramos que los filtros WFP estén activos (Fail-Closed!)
        if self.applied_filter_ids.is_empty() && wfp.status().initialized {
            for app_path in &discovery.tor_browser_paths {
                match wfp.apply_tor_app_isolation(
                    app_path,
                    socks_port,
                    control_port,
                    self.config.block_ipv6_for_protected_apps,
                ) {
                    Ok(ids) => {
                        info!("Tor Secure Mode: aplicados {} filtros WFP sobre {}", ids.len(), app_path);
                        self.applied_filter_ids.extend(ids);
                    }
                    Err(e) => {
                        warn!("No se pudo aplicar aislamiento Tor WFP para {}: {}", app_path, e);
                    }
                }
            }
        }

        // Evaluar salud real:
        // Si Tor daemon/SOCKS cae mientras Tor Secure Mode está activo, mantenemos el bloqueo (Kill Switch!)
        let (health, msg) = if !wfp.status().initialized {
            (
                TorProtectionHealth::Degraded,
                "Tor Secure Mode activado, pero WFP requiere privilegios de Administrador/Servicio para aplicar bloqueo en kernel.".to_string(),
            )
        } else if !socks_ok && self.config.kill_switch_fail_closed {
            (
                TorProtectionHealth::TorDownKillSwitchActive,
                format!(
                    "KILL SWITCH ACTIVO: Proxy SOCKS5 Tor (127.0.0.1:{}) no responde. Conexiones directas bloqueadas en WFP para evitar fugas.",
                    socks_port
                ),
            )
        } else if discovery.tor_browser_paths.is_empty() {
            (
                TorProtectionHealth::Degraded,
                "Tor Secure Mode armado. Agregue la ruta de Tor Browser o inicie Tor Browser para aplicar aislamiento por AppID.".to_string(),
            )
        } else {
            (
                TorProtectionHealth::Protected,
                format!(
                    "Tor Secure Mode ACTIVO: tráfico directo IPv4/IPv6/DNS bloqueado; solo permitido loopback SOCKS5 127.0.0.1:{}.",
                    socks_port
                ),
            )
        };

        self.build_state(&discovery, socks_port, socks_ok, health, &msg)
    }

    pub fn register_leak_attempt(&mut self) {
        self.direct_leak_attempts_blocked += 1;
    }

    fn build_state(
        &self,
        discovery: &TorDiscoveryInfo,
        socks_port: u16,
        socks_reachable: bool,
        health: TorProtectionHealth,
        status_message: &str,
    ) -> TorSecureModeState {
        TorSecureModeState {
            health,
            enabled: self.config.enabled,
            tor_browser_detected: !discovery.tor_browser_pids.is_empty(),
            tor_browser_pids: discovery.tor_browser_pids.clone(),
            tor_browser_paths: discovery.tor_browser_paths.clone(),
            tor_daemon_detected: discovery.tor_daemon_pid.is_some(),
            tor_daemon_pid: discovery.tor_daemon_pid,
            socks_port,
            socks_reachable,
            bridges_configured: discovery.bridges_configured,
            pluggable_transports: discovery.pluggable_transports.clone(),
            kill_switch_active: self.config.enabled && self.config.kill_switch_fail_closed,
            wfp_filters_applied: self.applied_filter_ids.len(),
            direct_leak_attempts_blocked: self.direct_leak_attempts_blocked,
            status_message: status_message.to_string(),
            limitations_notice: TOR_LIMITATIONS_NOTICE.to_string(),
        }
    }
}

pub fn parse_torrc(content: &str) -> (Option<u16>, Option<u16>, bool) {
    let mut socks_port = None;
    let mut control_port = None;
    let mut bridges = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        match parts[0].to_lowercase().as_str() {
            "socksport" if parts.len() >= 2 => {
                let port_part = parts[1].split(':').last().unwrap_or(parts[1]);
                if let Ok(p) = port_part.parse::<u16>() {
                    socks_port = Some(p);
                }
            }
            "controlport" if parts.len() >= 2 => {
                let port_part = parts[1].split(':').last().unwrap_or(parts[1]);
                if let Ok(p) = port_part.parse::<u16>() {
                    control_port = Some(p);
                }
            }
            "usebridges" if parts.len() >= 2 && parts[1] == "1" => {
                bridges = true;
            }
            "bridge" | "clienttransportplugin" => {
                bridges = true;
            }
            _ => {}
        }
    }

    (socks_port, control_port, bridges)
}
