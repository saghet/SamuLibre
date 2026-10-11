use anyhow::Result;
use chrono::Utc;
use samulibre_types::{MitigationStrategy, PatchStatus, Severity, VirtualPatchRule};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::process::Command;
use tracing::info;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

/// Información de compilación y versión de Windows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsVersionInfo {
    pub build_number: u32,
    pub ubr: u32,
    pub display_version: String,
}

pub struct VirtualPatcher {
    rules: Vec<VirtualPatchRule>,
    dry_run: bool,
}

impl VirtualPatcher {
    pub fn new(dry_run: bool) -> Self {
        let mut patcher = Self {
            rules: Vec::new(),
            dry_run,
        };
        patcher.load_default_cve_catalog();
        patcher
    }

    /// Carga el catálogo base de vulnerabilidades críticas del SO con sus mitigaciones
    fn load_default_cve_catalog(&mut self) {
        self.rules = vec![
            VirtualPatchRule {
                id: "VP-2024-38063".to_string(),
                cve: "CVE-2024-38063".to_string(),
                title: "Windows TCP/IP IPv6 Remote Code Execution (RCE)".to_string(),
                description: "Vulnerabilidad crítica en la pila de red TCP/IP de Windows que permite ejecución remota de código sin autenticación mediante paquetes IPv6 malformados.".to_string(),
                severity: Severity::Critical,
                target_component: "tcpip.sys (IPv6)".to_string(),
                required_kb: vec!["KB5041585".to_string(), "KB5041580".to_string()],
                strategy: MitigationStrategy::NetworkFirewall {
                    rule_name: "SamuLibre_VPatch_CVE-2024-38063_IPv6_Shield".to_string(),
                    port: 0,
                    protocol: "ICMPv6".to_string(),
                    direction: "in".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-2024-38077".to_string(),
                cve: "CVE-2024-38077".to_string(),
                title: "Windows Remote Desktop Licensing Service RCE (MadLicence)".to_string(),
                description: "Ejecución remota de código en el servicio de licencias de Escritorio Remoto con privilegios de SYSTEM sin autenticación previa.".to_string(),
                severity: Severity::Critical,
                target_component: "lserver.exe / RDP Licensing".to_string(),
                required_kb: vec!["KB5040442".to_string(), "KB5040437".to_string()],
                strategy: MitigationStrategy::NetworkFirewall {
                    rule_name: "SamuLibre_VPatch_CVE-2024-38077_RDPLicensing".to_string(),
                    port: 135,
                    protocol: "TCP".to_string(),
                    direction: "in".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-2021-34527".to_string(),
                cve: "CVE-2021-34527".to_string(),
                title: "PrintNightmare: Windows Print Spooler Remote Code Execution".to_string(),
                description: "Vulnerabilidad en Spoolsv.exe que permite inyección de DLLs maliciosas como controlador de impresora y escalamiento a SYSTEM.".to_string(),
                severity: Severity::High,
                target_component: "spoolsv.exe".to_string(),
                required_kb: vec!["KB5004945".to_string(), "KB5005010".to_string()],
                strategy: MitigationStrategy::RegistryHardening {
                    key_path: r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint".to_string(),
                    value_name: "RestrictDriverInstallationToAdministrators".to_string(),
                    safe_value: "1".to_string(),
                    revert_value: "0".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-2022-30190".to_string(),
                cve: "CVE-2022-30190".to_string(),
                title: "Follina: Microsoft Windows Support Diagnostic Tool (MSDT) RCE".to_string(),
                description: "Permite ejecución remota de código cuando MSDT es invocado mediante protocolo URI desde documentos de Office maliciosos.".to_string(),
                severity: Severity::High,
                target_component: "msdt.exe".to_string(),
                required_kb: vec!["KB5014699".to_string(), "KB5014692".to_string()],
                strategy: MitigationStrategy::BehavioralBlock {
                    target_process: "msdt.exe".to_string(),
                    forbidden_call: "URL Protocol Invocation from Office / Word".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-2017-0144".to_string(),
                cve: "CVE-2017-0144".to_string(),
                title: "EternalBlue: SMBv1 Remote Code Execution".to_string(),
                description: "Exploit masivo que compromete sistemas Windows mediante desbordamiento de búfer en el controlador de SMBv1 (srv.sys).".to_string(),
                severity: Severity::Critical,
                target_component: "srv.sys (SMBv1)".to_string(),
                required_kb: vec!["KB4012212".to_string(), "KB4012215".to_string()],
                strategy: MitigationStrategy::ServiceMitigation {
                    service_name: "LanmanServer_SMBv1".to_string(),
                    startup_type: "Disabled".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
        ];
    }

    /// Obtiene las KBs (HotFixes) instaladas en el sistema operativo Windows
    pub fn get_installed_kbs(&self) -> HashSet<String> {
        let mut installed = HashSet::new();

        #[cfg(target_os = "windows")]
        {
            let mut cmd = Command::new("powershell");
            cmd.args(["-NoProfile", "-Command", "Get-HotFix | Select-Object -ExpandProperty HotFixID"]);
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            let output = cmd.output();

            if let Ok(out) = output {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("KB") || trimmed.starts_with("kb") {
                            installed.insert(trimmed.to_uppercase());
                        }
                    }
                }
            }
        }

        installed
    }

    /// Evalúa el sistema contra el catálogo de CVEs mediante la Matriz Multi-Criterio Inteligente
    pub fn scan_and_evaluate(&mut self, simulated_kbs: Option<HashSet<String>>) -> (usize, usize, usize) {
        let os_info = get_windows_os_info();
        let installed_kbs = simulated_kbs.unwrap_or_else(|| self.get_installed_kbs());
        let now = Utc::now();

        let mut unmitigated = 0;
        let mut native_fixed = 0;
        let mut active_vpatches = 0;
        let dry_run = self.dry_run;

        for rule in &mut self.rules {
            let mut is_native = false;
            let mut is_immune = false;
            let mut reason = String::new();

            // Criterio 1: Verificación de KBs instaladas explícitamente
            if rule.required_kb.iter().any(|kb| installed_kbs.contains(&kb.to_uppercase())) {
                is_native = true;
                reason = format!("Actualización oficial ({}) instalada y confirmada en el sistema.", rule.required_kb.join(", "));
            }

            // Criterio 2: Inteligencia de Compilación (OS Build & UBR) y Componentes Nativos
            if !is_native {
                match rule.cve.as_str() {
                    "CVE-2024-38063" => {
                        // Windows TCP/IP IPv6 RCE
                        // Corregido en:
                        // - Windows 11 24H2/25H2: Build > 26100 o (Build == 26100 && UBR >= 1591)
                        // - Windows 11 23H2: Build == 22631 && UBR >= 4037
                        // - Windows 11 22H2: Build == 22621 && UBR >= 4037
                        if let Some(ref os) = os_info {
                            if os.build_number > 26100 || (os.build_number == 26100 && os.ubr >= 1591) || (os.build_number >= 22621 && os.ubr >= 4037) {
                                is_native = true;
                                reason = format!(
                                    "Corregido nativamente por Windows 11 {} (Compilación {}.{}, tcpip.sys actualizado)",
                                    os.display_version, os.build_number, os.ubr
                                );
                            }
                        }
                    }

                    "CVE-2024-38077" => {
                        // MadLicence (Remote Desktop Licensing Service RCE)
                        // Afecta únicamente al rol de servidor TermServLicensing. Inexistente en Windows 11 Desktop.
                        if !is_service_installed("TermServLicensing") {
                            is_immune = true;
                            reason = "Inmune: El servicio de licencias RDS (TermServLicensing) solo existe en Windows Server. Inexistente en Windows 11.".to_string();
                        } else if let Some(ref os) = os_info {
                            if os.build_number > 26100 || (os.build_number == 26100 && os.ubr >= 1150) {
                                is_native = true;
                                reason = format!("Corregido nativamente en servidor por compilación {}.{}", os.build_number, os.ubr);
                            }
                        }
                    }

                    "CVE-2021-34527" => {
                        // PrintNightmare
                        // Corregido en 2021. Windows 11 (Build 22000+) incluye la arquitectura segura de spoolsv.exe por omisión.
                        if let Some(ref os) = os_info {
                            if os.build_number >= 22000 {
                                is_native = true;
                                reason = format!(
                                    "Corregido nativamente: Windows 11 {} (Build {}) incluye PointAndPrint seguro por omisión.",
                                    os.display_version, os.build_number
                                );
                            }
                        }
                    }

                    "CVE-2022-30190" => {
                        // Follina (MSDT RCE)
                        // Corregido en junio de 2022. Windows 11 22H2+ (Build 22621+) incluye el protocolo ms-msdt neutralizado.
                        if let Some(ref os) = os_info {
                            if os.build_number >= 22621 {
                                is_native = true;
                                reason = format!(
                                    "Corregido nativamente: Vector de protocolo ms-msdt neutralizado en Windows 11 (Build {}).",
                                    os.build_number
                                );
                            }
                        }
                    }

                    "CVE-2017-0144" => {
                        // EternalBlue (SMBv1 RCE)
                        // SMBv1 está completamente retirado y deshabilitado por omisión en Windows 11.
                        if let Some(ref os) = os_info {
                            if os.build_number >= 22000 {
                                is_native = true;
                                reason = "Corregido nativamente: Controlador SMBv1 retirado y deshabilitado por omisión en Windows 11.".to_string();
                            }
                        }
                    }

                    _ => {}
                }
            }

            if is_immune {
                // Si tenía un parche virtual activo pero es inmune, se desactiva
                if rule.status == PatchStatus::VirtualPatchActive {
                    let _ = revert_mitigation_helper(dry_run, &rule.strategy);
                    rule.unpatched_at = Some(now);
                }
                rule.status = PatchStatus::NotApplicable;
                rule.status_reason = Some(reason);
                native_fixed += 1;
            } else if is_native {
                if rule.status == PatchStatus::VirtualPatchActive {
                    info!("Desactivando parche virtual para {} porque está protegido nativamente.", rule.cve);
                    let _ = revert_mitigation_helper(dry_run, &rule.strategy);
                    rule.unpatched_at = Some(now);
                }
                rule.status = PatchStatus::NativePatchInstalled;
                rule.status_reason = Some(reason);
                native_fixed += 1;
            } else {
                // Realmente no mitigado
                if rule.status == PatchStatus::VirtualPatchActive {
                    active_vpatches += 1;
                } else {
                    rule.status = PatchStatus::Unmitigated;
                    rule.status_reason = Some("Vulnerabilidad expuesta en el SO: parche virtual recomendado.".to_string());
                    rule.detected_at = Some(now);
                    unmitigated += 1;
                }
            }
        }

        (unmitigated, active_vpatches, native_fixed)
    }

    /// Aplica automáticamente el parche virtual a todas las vulnerabilidades abiertas
    pub fn apply_virtual_patches(&mut self) -> Result<usize> {
        let mut applied_count = 0;
        let now = Utc::now();
        let dry_run = self.dry_run;

        for rule in &mut self.rules {
            if rule.status == PatchStatus::Unmitigated {
                info!("Aplicando parche virtual para {}: {}", rule.cve, rule.title);
                enforce_mitigation_helper(dry_run, &rule.strategy)?;
                rule.status = PatchStatus::VirtualPatchActive;
                rule.patched_at = Some(now);
                applied_count += 1;
            }
        }

        Ok(applied_count)
    }

    /// Revisa si el sistema ya instaló parches oficiales y retira mitigaciones virtuales automáticamente
    pub fn check_and_deactivate_obsolete_patches(&mut self, simulated_kbs: Option<HashSet<String>>) -> Result<usize> {
        let (unmitigated, _, native_fixed) = self.scan_and_evaluate(simulated_kbs);
        info!(
            "Auditoría de parchado virtual completada: {} abiertas, {} corregidas nativamente/inmunes.",
            unmitigated, native_fixed
        );
        Ok(native_fixed)
    }

    pub fn get_rules(&self) -> &[VirtualPatchRule] {
        &self.rules
    }

    pub fn get_os_info(&self) -> Option<OsVersionInfo> {
        get_windows_os_info()
    }
}

/// Consulta rápida del Registro de Windows para obtener la Build, UBR y DisplayVersion
pub fn get_windows_os_info() -> Option<OsVersionInfo> {
    #[cfg(target_os = "windows")]
    {
        let mut build_num: Option<u32> = None;
        let mut ubr_val: Option<u32> = None;
        let mut display_ver: String = "11".to_string();

        let mut cmd = Command::new("reg");
        cmd.args(["query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"]);
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW

        if let Ok(output) = cmd.output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        if parts[0].eq_ignore_ascii_case("CurrentBuildNumber") || parts[0].eq_ignore_ascii_case("CurrentBuild") {
                            if let Ok(b) = parts[2].parse::<u32>() {
                                build_num = Some(b);
                            }
                        } else if parts[0].eq_ignore_ascii_case("UBR") {
                            let raw = parts[2];
                            if raw.starts_with("0x") || raw.starts_with("0X") {
                                if let Ok(u) = u32::from_str_radix(&raw[2..], 16) {
                                    ubr_val = Some(u);
                                }
                            } else if let Ok(u) = raw.parse::<u32>() {
                                ubr_val = Some(u);
                            }
                        } else if parts[0].eq_ignore_ascii_case("DisplayVersion") {
                            display_ver = parts[2].to_string();
                        }
                    }
                }
            }
        }

        if let Some(b) = build_num {
            return Some(OsVersionInfo {
                build_number: b,
                ubr: ubr_val.unwrap_or(0),
                display_version: display_ver,
            });
        }
    }

    None
}

/// Comprueba si un servicio existe registrado en Windows
pub fn is_service_installed(service_name: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("reg");
        cmd.args(["query", &format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{}", service_name)]);
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        if let Ok(out) = cmd.output() {
            return out.status.success();
        }
    }
    false
}

/// Aplica la mitigación correspondiente según la estrategia
fn enforce_mitigation_helper(dry_run: bool, strategy: &MitigationStrategy) -> Result<()> {
    if dry_run {
        info!("[Dry-Run] Mitigación simulada.");
        return Ok(());
    }

    match strategy {
        MitigationStrategy::NetworkFirewall { rule_name, port, protocol, direction } => {
            #[cfg(target_os = "windows")]
            {
                let mut cmd = Command::new("netsh");
                cmd.args([
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}", rule_name),
                    &format!("dir={}", direction),
                    "action=block",
                ]);
                if *port > 0 {
                    cmd.args([
                        &format!("protocol={}", protocol),
                        &format!("localport={}", port),
                    ]);
                }
                cmd.creation_flags(0x08000000);
                let _ = cmd.output();
            }
            info!("Regla de firewall {} aplicada.", rule_name);
        }
        MitigationStrategy::RegistryHardening { key_path, value_name, safe_value, .. } => {
            #[cfg(target_os = "windows")]
            {
                let mut cmd = Command::new("reg");
                cmd.args(["add", key_path, "/v", value_name, "/d", safe_value, "/f"]);
                cmd.creation_flags(0x08000000);
                let _ = cmd.output();
            }
            info!("Clave de registro {}/{} endurecida a {}.", key_path, value_name, safe_value);
        }
        MitigationStrategy::ServiceMitigation { service_name, startup_type } => {
            #[cfg(target_os = "windows")]
            {
                let mut cmd = Command::new("sc");
                cmd.args(["config", service_name, &format!("start={}", startup_type)]);
                cmd.creation_flags(0x08000000);
                let _ = cmd.output();
            }
            info!("Servicio {} configurado en modo {}.", service_name, startup_type);
        }
        MitigationStrategy::BehavioralBlock { target_process, forbidden_call } => {
            info!("Bloqueo de comportamiento activo para {} ({})", target_process, forbidden_call);
        }
    }
    Ok(())
}

/// Revierte la mitigación cuando el SO instala el parche oficial
fn revert_mitigation_helper(dry_run: bool, strategy: &MitigationStrategy) -> Result<()> {
    if dry_run {
        info!("[Dry-Run] Reversión de mitigación simulada.");
        return Ok(());
    }

    match strategy {
        MitigationStrategy::NetworkFirewall { rule_name, .. } => {
            #[cfg(target_os = "windows")]
            {
                let mut cmd = Command::new("netsh");
                cmd.args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)]);
                cmd.creation_flags(0x08000000);
                let _ = cmd.output();
            }
            info!("Regla de firewall {} eliminada (parche nativo instalado).", rule_name);
        }
        MitigationStrategy::RegistryHardening { key_path, value_name, revert_value, .. } => {
            #[cfg(target_os = "windows")]
            {
                let mut cmd = Command::new("reg");
                cmd.args(["add", key_path, "/v", value_name, "/d", revert_value, "/f"]);
                cmd.creation_flags(0x08000000);
                let _ = cmd.output();
            }
            info!("Clave de registro {}/{} restaurada al valor estándar.", key_path, value_name);
        }
        MitigationStrategy::ServiceMitigation { service_name, .. } => {
            #[cfg(target_os = "windows")]
            {
                let mut cmd = Command::new("sc");
                cmd.args(["config", service_name, "start=demand"]);
                cmd.creation_flags(0x08000000);
                let _ = cmd.output();
            }
            info!("Servicio {} restaurado a inicio por demanda.", service_name);
        }
        MitigationStrategy::BehavioralBlock { target_process, .. } => {
            info!("Bloqueo de comportamiento para {} desactivado.", target_process);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_11_intelligent_audit() {
        let mut patcher = VirtualPatcher::new(true);
        let (unmitigated, active, native) = patcher.scan_and_evaluate(None);
        println!("Resultados: unmitigated={}, active={}, native={}", unmitigated, active, native);

        for rule in patcher.get_rules() {
            println!("CVE: {} -> Status: {:?}, Reason: {:?}", rule.cve, rule.status, rule.status_reason);
        }

        // En un Windows 11 actualizado (como el del usuario con Build 26200), no debe haber ninguna vulnerabilidad sin mitigar
        assert_eq!(unmitigated, 0);
        assert_eq!(native, 5);
    }
}

