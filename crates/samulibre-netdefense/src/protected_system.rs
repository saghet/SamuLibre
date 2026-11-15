use std::path::Path;

/// Guardián de binarios críticos del SO y Loopback IPC para evitar bloqueos accidentales que rompan Windows o apps locales.
pub struct ProtectedSystemGuard;

impl ProtectedSystemGuard {
    pub const CORE_SYSTEM_BINARIES: &'static [&'static str] = &[
        "system",
        "ntoskrnl.exe",
        "svchost.exe",
        "lsass.exe",
        "csrss.exe",
        "services.exe",
        "smss.exe",
        "wininit.exe",
        "winlogon.exe",
        "conhost.exe",
        "dns.exe",
        "spoolsv.exe",
        "runtimebroker.exe",
        "sihost.exe",
        "explorer.exe",
        "samulibre-watcher.exe",
        "samulibre-gui.exe",
        "samulibre-cli.exe",
        "samulibre.exe",
    ];

    pub const OEM_AND_ESSENTIAL_DIRS: &'static [&'static str] = &[
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",
        "\\program files\\asus\\",
        "\\program files (x86)\\asus\\",
        "\\program files\\intel\\",
        "\\program files\\nvidia corporation\\",
        "\\program files\\amd\\",
    ];

    pub fn is_loopback_ip(ip: &str) -> bool {
        ip == "127.0.0.1" || ip == "::1" || ip.starts_with("127.")
    }

    pub fn is_private_or_local_ip(ip: &str) -> bool {
        if Self::is_loopback_ip(ip) || ip == "0.0.0.0" || ip == "::" || ip.starts_with("169.254.") {
            return true;
        }
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            match addr {
                std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
                std::net::IpAddr::V6(v6) => {
                    v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
                }
            }
        } else {
            false
        }
    }

    /// Evalúa si un ejecutable está protegido contra bloqueo automático/accidental (con validación anti-suplantación T1036).
    pub fn evaluate_protection(path: &Path, file_name: &str) -> (bool, Option<String>) {
        let name_lower = file_name.to_lowercase();
        let path_lower = path.to_string_lossy().to_lowercase();

        if name_lower == "system" {
            return (
                true,
                Some("Núcleo del Sistema Operativo Windows (PID 4)".to_string()),
            );
        }

        if name_lower.starts_with("samulibre") {
            return (
                true,
                Some("Componente esencial de SamuLibre Security Suite".to_string()),
            );
        }

        let is_core = Self::CORE_SYSTEM_BINARIES
            .iter()
            .any(|&b| b.eq_ignore_ascii_case(&name_lower));

        if is_core {
            let in_sys_dir = path_lower.contains("\\windows\\system32\\")
                || path_lower.contains("\\windows\\syswow64\\")
                || path_lower.contains("\\windows\\winsxs\\");
            if in_sys_dir {
                return (
                    true,
                    Some(format!(
                        "Binario crítico de Windows en ruta protegida ({})",
                        file_name
                    )),
                );
            }
            // Si tiene nombre de binario crítico fuera de System32/SysWOW64, NO se protege (posible T1036 Masquerading)
            return (false, None);
        }

        (false, None)
    }

    pub fn is_oem_or_system_path(path_lower: &str) -> bool {
        Self::OEM_AND_ESSENTIAL_DIRS
            .iter()
            .any(|dir| path_lower.contains(dir))
    }
}
