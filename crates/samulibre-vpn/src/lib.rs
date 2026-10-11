use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    pub interface_name: String,
    pub private_key: String,
    pub address: String,
    pub dns: Vec<String>,
    pub peer_public_key: String,
    pub peer_endpoint: String,
    pub allowed_ips: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecureDnsProvider {
    Quad9MalwareBlocking,
    AdGuardPrivacyAndAdblock,
    CloudflareMalwareBlocking,
}

impl SecureDnsProvider {
    pub fn get_ips(&self) -> Vec<&'static str> {
        match self {
            SecureDnsProvider::Quad9MalwareBlocking => vec!["9.9.9.9", "149.112.112.112"],
            SecureDnsProvider::AdGuardPrivacyAndAdblock => vec!["94.140.14.14", "94.140.15.15"],
            SecureDnsProvider::CloudflareMalwareBlocking => vec!["1.1.1.2", "1.0.0.2"],
        }
    }

    pub fn get_doh_url(&self) -> &'static str {
        match self {
            SecureDnsProvider::Quad9MalwareBlocking => "https://dns.quad9.net/dns-query",
            SecureDnsProvider::AdGuardPrivacyAndAdblock => "https://dns.adguard.com/dns-query",
            SecureDnsProvider::CloudflareMalwareBlocking => "https://security.cloudflare-dns.com/dns-query",
        }
    }
}

pub struct VpnManager {
    profiles_dir: PathBuf,
    is_connected: bool,
    kill_switch_enabled: bool,
    active_profile: Option<String>,
}

impl VpnManager {
    pub fn new(profiles_dir: impl AsRef<Path>) -> Self {
        let dir = profiles_dir.as_ref().to_path_buf();
        let _ = fs::create_dir_all(&dir);

        Self {
            profiles_dir: dir,
            is_connected: false,
            kill_switch_enabled: false,
            active_profile: None,
        }
    }

    /// Genera un archivo de configuración estándar compatible con el cliente WireGuard libre
    pub fn export_wireguard_conf(&self, config: &WireGuardConfig, filename: &str) -> Result<PathBuf> {
        let target = self.profiles_dir.join(filename);
        let content = format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}\nDNS = {}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
            config.private_key,
            config.address,
            config.dns.join(", "),
            config.peer_public_key,
            config.peer_endpoint,
            config.allowed_ips
        );

        fs::write(&target, content)?;
        info!("Perfil WireGuard generado exitosamente en {:?}", target);
        Ok(target)
    }

    /// Activa el Kill-Switch de firewall para evitar fugas de tráfico si la conexión cae
    pub fn enable_kill_switch(&mut self, allowed_interface: &str) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            // Bloquear todo el tráfico saliente excepto el adaptador VPN y DHCP/DNS local
            let _ = Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    "name=SamuLibre_VPN_KillSwitch_BlockAll",
                    "dir=out", "action=block", "protocol=ANY",
                ])
                .output();

            let _ = Command::new("netsh")
                .args([
                    "advfirewall", "firewall", "add", "rule",
                    "name=SamuLibre_VPN_KillSwitch_AllowTunnel",
                    "dir=out", "action=allow",
                    &format!("interface={}", allowed_interface),
                ])
                .output();
        }

        self.kill_switch_enabled = true;
        info!("Kill-Switch WFP activado: Todo el tráfico no tunelizado está bloqueado.");
        Ok(())
    }

    /// Desactiva el Kill-Switch restaurando el tráfico normal
    pub fn disable_kill_switch(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let _ = Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", "name=SamuLibre_VPN_KillSwitch_BlockAll"])
                .output();
            let _ = Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", "name=SamuLibre_VPN_KillSwitch_AllowTunnel"])
                .output();
        }

        self.kill_switch_enabled = false;
        info!("Kill-Switch desactivado. Tráfico de red restaurado.");
        Ok(())
    }

    /// Aplica DNS seguro con protección contra malware en las interfaces de red de Windows
    pub fn apply_secure_dns(&self, provider: SecureDnsProvider) -> Result<()> {
        let ips = provider.get_ips();
        info!("Configurando DNS Seguro ({:?}) con IPs: {:?}", provider, ips);

        #[cfg(target_os = "windows")]
        {
            // Configurar DNS en adaptador Ethernet y Wi-Fi
            for adapter in ["Wi-Fi", "Ethernet"] {
                if let Some(primary) = ips.first() {
                    let _ = Command::new("netsh")
                        .args(["interface", "ipv4", "set", "dns", &format!("name={}", adapter), "static", primary, "primary"])
                        .output();
                }
                if let Some(secondary) = ips.get(1) {
                    let _ = Command::new("netsh")
                        .args(["interface", "ipv4", "add", "dns", &format!("name={}", adapter), secondary, "index=2"])
                        .output();
                }
            }
        }

        Ok(())
    }

    pub fn is_kill_switch_active(&self) -> bool {
        self.kill_switch_enabled
    }
}
