use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

/// Veredicto de inspección de conexión por el Firewall Adaptativo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallVerdict {
    pub allowed: bool,
    pub reason: String,
    pub severity: String,
    pub should_isolate_pid: bool,
}

/// Binarios Living-off-the-Land (LOLBins) que frecuentemente se abusan para descargar payloads o C2
const LOLBINS: &[&str] = &[
    "powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "schtasks.exe", "at.exe",
    "wmic.exe", "bash", "sh", "nc", "netcat", "ncat", "socat",
];

/// Puertos comunes de Command & Control (C2) y reverse shells
const C2_SUSPICIOUS_PORTS: &[u16] = &[
    1337, 31337, 4444, 4445, 5555, 6666, 7777, 8888, 9001, 9999, 4443,
];

/// Comprueba si una dirección IP pertenece a un rango privado / loopback (RFC 1918)
pub fn is_private_or_local_ip(ip_str: &str) -> bool {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local()
            }
            IpAddr::V6(v6) => v6.is_loopback(),
        }
    } else {
        // Si no se puede parsear como IP, verificar strings comunes
        ip_str == "127.0.0.1" || ip_str == "localhost" || ip_str.starts_with("192.168.") || ip_str.starts_with("10.")
    }
}

pub struct AdaptiveFirewall {
    pub blocked_ips: HashSet<String>,
    pub blocked_ports: HashSet<u16>,
    pub whitelisted_pids: HashSet<u32>,
}

impl AdaptiveFirewall {
    pub fn new() -> Self {
        Self {
            blocked_ips: HashSet::new(),
            blocked_ports: HashSet::new(),
            whitelisted_pids: HashSet::new(),
        }
    }

    /// Evalúa un intento de conexión saliente de un proceso local hacia un host remoto
    pub fn inspect_outbound_connection(
        &mut self,
        _pid: u32,
        proc_name: &str,
        remote_ip: &str,
        remote_port: u16,
    ) -> FirewallVerdict {
        let lower_name = proc_name.to_lowercase();

        // 1. Verificar lista negra de IPs
        if self.blocked_ips.contains(remote_ip) {
            return FirewallVerdict {
                allowed: false,
                reason: format!("Dirección IP remota {} bloqueada explícitamente en el firewall.", remote_ip),
                severity: "Alta".to_string(),
                should_isolate_pid: false,
            };
        }

        // 2. Verificar lista negra de puertos
        if self.blocked_ports.contains(&remote_port) {
            return FirewallVerdict {
                allowed: false,
                reason: format!("Puerto destino {} clausurado preventivamente.", remote_port),
                severity: "Media".to_string(),
                should_isolate_pid: false,
            };
        }

        let is_private = is_private_or_local_ip(remote_ip);

        // 3. Bloqueo de LOLBins intentando conectarse a Internet exterior
        let is_lolbin = LOLBINS.iter().any(|&l| lower_name.contains(l));
        if is_lolbin && !is_private {
            return FirewallVerdict {
                allowed: false,
                reason: format!(
                    "LOLBin detectado ({}) abriendo conexión saliente hacia IP externa no confiable {}:{}.",
                    proc_name, remote_ip, remote_port
                ),
                severity: "Crítica".to_string(),
                should_isolate_pid: true,
            };
        }

        // 4. Bloqueo de puertos C2 conocidos
        if C2_SUSPICIOUS_PORTS.contains(&remote_port) && !is_private {
            return FirewallVerdict {
                allowed: false,
                reason: format!(
                    "Conexión hacia puerto sospechoso de Command & Control (C2) {}:{} por proceso {}.",
                    remote_ip, remote_port, proc_name
                ),
                severity: "Crítica".to_string(),
                should_isolate_pid: true,
            };
        }

        FirewallVerdict {
            allowed: true,
            reason: "Conexión autorizada por política de firewall adaptativo.".to_string(),
            severity: "Informativa".to_string(),
            should_isolate_pid: false,
        }
    }

    pub fn block_ip(&mut self, ip: &str) {
        self.blocked_ips.insert(ip.to_string());
    }

    pub fn block_port(&mut self, port: u16) {
        self.blocked_ports.insert(port);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lolbin_outbound_blocked() {
        let mut fw = AdaptiveFirewall::new();
        let verdict = fw.inspect_outbound_connection(1234, "powershell.exe", "45.33.32.156", 443);
        assert!(!verdict.allowed);
        assert!(verdict.should_isolate_pid);
        assert!(verdict.reason.contains("LOLBin"));
    }

    #[test]
    fn test_browser_normal_connection_allowed() {
        let mut fw = AdaptiveFirewall::new();
        let verdict = fw.inspect_outbound_connection(5678, "chrome.exe", "142.250.190.46", 443);
        assert!(verdict.allowed);
    }

    #[test]
    fn test_c2_suspicious_port_blocked() {
        let mut fw = AdaptiveFirewall::new();
        let verdict = fw.inspect_outbound_connection(9999, "unknown_worker.exe", "198.51.100.22", 4444);
        assert!(!verdict.allowed);
        assert!(verdict.reason.contains("C2"));
    }
}
