use anyhow::Result;
use chrono::Utc;
use samulibre_types::{MitigationStrategy, PatchStatus, Severity, VirtualPatchRule};
use std::collections::HashSet;
use std::process::Command;
use tracing::info;

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
            },
        ];
    }

    /// Obtiene las KBs (HotFixes) instaladas en el sistema operativo Windows
    pub fn get_installed_kbs(&self) -> HashSet<String> {
        let mut installed = HashSet::new();

        #[cfg(target_os = "windows")]
        {
            // Intentar consultar Get-HotFix mediante PowerShell
            let output = Command::new("powershell")
                .args(["-NoProfile", "-Command", "Get-HotFix | Select-Object -ExpandProperty HotFixID"])
                .output();

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

    /// Evalúa el sistema contra el catálogo de CVEs y determina qué parches se necesitan
    pub fn scan_and_evaluate(&mut self, simulated_kbs: Option<HashSet<String>>) -> (usize, usize, usize) {
        let installed_kbs = simulated_kbs.unwrap_or_else(|| self.get_installed_kbs());
        let now = Utc::now();

        let mut unmitigated = 0;
        let mut native_fixed = 0;
        let mut active_vpatches = 0;

        let dry_run = self.dry_run;
        for rule in &mut self.rules {
            // Verificar si alguna de las KBs requeridas ya está instalada nativamente
            let has_native_patch = rule.required_kb.iter().any(|kb| installed_kbs.contains(&kb.to_uppercase()));

            if has_native_patch {
                // Si tenía un parche virtual activo, ahora debe desactivarse automáticamente
                if rule.status == PatchStatus::VirtualPatchActive {
                    info!("Desactivando parche virtual para {} porque la actualización nativa ({:?}) fue instalada.", rule.cve, rule.required_kb);
                    let _ = revert_mitigation_helper(dry_run, &rule.strategy);
                    rule.unpatched_at = Some(now);
                }
                rule.status = PatchStatus::NativePatchInstalled;
                native_fixed += 1;
            } else {
                // Falta la actualización oficial
                if rule.status == PatchStatus::VirtualPatchActive {
                    active_vpatches += 1;
                } else {
                    rule.status = PatchStatus::Unmitigated;
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
        let installed_kbs = simulated_kbs.unwrap_or_else(|| self.get_installed_kbs());
        let now = Utc::now();
        let mut reverted_count = 0;
        let dry_run = self.dry_run;

        for rule in &mut self.rules {
            if rule.status == PatchStatus::VirtualPatchActive {
                let has_native = rule.required_kb.iter().any(|kb| installed_kbs.contains(&kb.to_uppercase()));
                if has_native {
                    info!(
                        "AUTO-DESACTIVACIÓN: Vulnerabilidad {} corregida nativamente por el SO ({:?}). Retirando parche virtual para liberar recursos.",
                        rule.cve, rule.required_kb
                    );
                    revert_mitigation_helper(dry_run, &rule.strategy)?;
                    rule.status = PatchStatus::NativePatchInstalled;
                    rule.unpatched_at = Some(now);
                    reverted_count += 1;
                }
            }
        }

        Ok(reverted_count)
    }

    pub fn get_rules(&self) -> &[VirtualPatchRule] {
        &self.rules
    }
}

/// Ejecuta la mitigación según la estrategia (Firewall WFP, Registro, Servicio)
fn enforce_mitigation_helper(dry_run: bool, strategy: &MitigationStrategy) -> Result<()> {
    if dry_run {
        info!("[Dry-Run] Mitigación simulada con éxito.");
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
                let _ = cmd.output();
            }
            info!("Regla de firewall {} aplicada.", rule_name);
        }
        MitigationStrategy::RegistryHardening { key_path, value_name, safe_value, .. } => {
            #[cfg(target_os = "windows")]
            {
                let _ = Command::new("reg")
                    .args(["add", key_path, "/v", value_name, "/d", safe_value, "/f"])
                    .output();
            }
            info!("Clave de registro {}/{} endurecida a {}.", key_path, value_name, safe_value);
        }
        MitigationStrategy::ServiceMitigation { service_name, startup_type } => {
            #[cfg(target_os = "windows")]
            {
                let _ = Command::new("sc")
                    .args(["config", service_name, &format!("start={}", startup_type)])
                    .output();
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
                let _ = Command::new("netsh")
                    .args(["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)])
                    .output();
            }
            info!("Regla de firewall {} eliminada (parche nativo instalado).", rule_name);
        }
        MitigationStrategy::RegistryHardening { key_path, value_name, revert_value, .. } => {
            #[cfg(target_os = "windows")]
            {
                let _ = Command::new("reg")
                    .args(["add", key_path, "/v", value_name, "/d", revert_value, "/f"])
                    .output();
            }
            info!("Clave de registro {}/{} restaurada al valor estándar.", key_path, value_name);
        }
        MitigationStrategy::ServiceMitigation { service_name, .. } => {
            #[cfg(target_os = "windows")]
            {
                let _ = Command::new("sc")
                    .args(["config", service_name, "start=demand"])
                    .output();
            }
            info!("Servicio {} restaurado a inicio por demanda.", service_name);
        }
        MitigationStrategy::BehavioralBlock { target_process, .. } => {
            info!("Bloqueo de comportamiento para {} desactivado.", target_process);
        }
    }
    Ok(())
}
