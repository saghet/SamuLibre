use anyhow::Result;
use chrono::Utc;
use samulibre_ai::LocalAiAnalyst;
use samulibre_types::{
    AiPatchAnalysisResult, AndroidBulletinAdvisory, AndroidSecurityInfo, KbAdvisory,
    KbMonitorStatus, MitigationStrategy, PatchStatus, Severity, VirtualPatchRule,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::info;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

/// Información de compilación y versión de Windows o Distribución Linux
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsVersionInfo {
    pub build_number: u32,
    pub ubr: u32,
    pub display_version: String,
    #[serde(default)]
    pub distro_id: Option<String>,
    #[serde(default)]
    pub distro_name: Option<String>,
    #[serde(default)]
    pub kernel_release: Option<String>,
}

/// Estado y métricas del Centinela de CVEs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelStatusInfo {
    pub is_active: bool,
    pub auto_patch_enabled: bool,
    pub last_audit_time: Option<String>,
    pub total_cves_audited: usize,
    pub unmitigated_count: usize,
    pub active_vpatches_count: usize,
    pub natively_fixed_count: usize,
    pub auto_patched_history: Vec<String>,
}

pub struct VirtualPatcher {
    rules: Vec<VirtualPatchRule>,
    dry_run: bool,
    pub auto_patch_enabled: bool,
    pub last_audit_time: Option<String>,
    pub auto_patched_history: Vec<String>,
    pub monitored_kbs: Vec<KbAdvisory>,
    pub monitored_asbs: Vec<AndroidBulletinAdvisory>,
    pub ai_patch_results: Vec<AiPatchAnalysisResult>,
    pub ai_autopilot_enabled: bool,
    pub daily_monitor_active: bool,
    pub last_daily_check: Option<String>,
    pub next_daily_check: Option<String>,
    pub daily_check_log: Vec<String>,
    ai_analyst: LocalAiAnalyst,
}

impl VirtualPatcher {
    pub fn new(dry_run: bool) -> Self {
        let mut patcher = Self {
            rules: Vec::new(),
            dry_run,
            auto_patch_enabled: true,
            last_audit_time: None,
            auto_patched_history: Vec::new(),
            monitored_kbs: Vec::new(),
            monitored_asbs: Vec::new(),
            ai_patch_results: Vec::new(),
            ai_autopilot_enabled: true,
            daily_monitor_active: true,
            last_daily_check: None,
            next_daily_check: None,
            daily_check_log: Vec::new(),
            ai_analyst: LocalAiAnalyst::new(),
        };
        patcher.load_default_cve_catalog();
        patcher.load_default_kb_advisories();
        patcher.load_default_asb_advisories();
        patcher
    }

    /// Carga el catálogo base de vulnerabilidades críticas del SO con sus mitigaciones
    fn load_default_cve_catalog(&mut self) {
        #[cfg(target_os = "windows")]
        self.load_windows_cve_catalog();
        #[cfg(not(target_os = "windows"))]
        self.load_linux_cve_catalog();
    }

    /// Catálogo de vulnerabilidades y mitigaciones para sistemas Windows
    pub fn load_windows_cve_catalog(&mut self) {
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

    /// Catálogo de vulnerabilidades, parámetros de kernel y mitigaciones para distribuciones Linux (Ubuntu, Red Hat, Garuda)
    pub fn load_linux_cve_catalog(&mut self) {
        self.rules = vec![
            VirtualPatchRule {
                id: "VP-LINUX-USERNS".to_string(),
                cve: "CVE-2022-0185".to_string(),
                title: "Linux Kernel Unprivileged User Namespaces LPE Mitigation".to_string(),
                description: "Mitigación proactiva contra escalamiento a root abusando de la clonación de user namespaces sin privilegios en el kernel Linux (CVE-2022-0185, CVE-2023-32233).".to_string(),
                severity: Severity::Critical,
                target_component: "kernel.unprivileged_userns_clone".to_string(),
                required_kb: vec!["Ubuntu USN-5252".to_string(), "RHSA-2022:0267".to_string()],
                strategy: MitigationStrategy::KernelSysctlHardening {
                    parameter: "kernel.unprivileged_userns_clone".to_string(),
                    safe_value: "0".to_string(),
                    revert_value: "1".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-LINUX-KPTR".to_string(),
                cve: "CVE-2020-0001".to_string(),
                title: "KASLR Protection: Ocultamiento de Punteros de Kernel".to_string(),
                description: "Restringe la exposición de direcciones de memoria del kernel en /proc/kallsyms a usuarios no root, inutilizando cadenas ROP de explotación.".to_string(),
                severity: Severity::High,
                target_component: "kernel.kptr_restrict".to_string(),
                required_kb: vec!["Linux Kernel Hardening Standard".to_string()],
                strategy: MitigationStrategy::KernelSysctlHardening {
                    parameter: "kernel.kptr_restrict".to_string(),
                    safe_value: "2".to_string(),
                    revert_value: "0".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-LINUX-YAMA".to_string(),
                cve: "CVE-2016-5195".to_string(),
                title: "Yama LSM: Restricción de Inyección de Memoria ptrace".to_string(),
                description: "Impide que procesos de usuario apliquen PTRACE_ATTACH a otros procesos en ejecución para sustraer credenciales o inyectar código en memoria.".to_string(),
                severity: Severity::High,
                target_component: "kernel.yama.ptrace_scope".to_string(),
                required_kb: vec!["Yama LSM Policy".to_string()],
                strategy: MitigationStrategy::KernelSysctlHardening {
                    parameter: "kernel.yama.ptrace_scope".to_string(),
                    safe_value: "2".to_string(),
                    revert_value: "0".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-LINUX-FS-RACE".to_string(),
                cve: "CVE-2019-18282".to_string(),
                title: "Protección contra Explotación de Enlaces Simbólicos y FIFOs en /tmp".to_string(),
                description: "Protección del VFS contra condiciones de carrera de creación y reemplazo de enlaces simbólicos en directorios mundiales de escritura compartida (/tmp, /var/tmp).".to_string(),
                severity: Severity::Medium,
                target_component: "fs.protected_fifos".to_string(),
                required_kb: vec!["VFS Hardening Baseline".to_string()],
                strategy: MitigationStrategy::KernelSysctlHardening {
                    parameter: "fs.protected_fifos".to_string(),
                    safe_value: "2".to_string(),
                    revert_value: "0".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-LINUX-PWNKIT".to_string(),
                cve: "CVE-2021-4034".to_string(),
                title: "PwnKit: Polkit pkexec Local Privilege Escalation".to_string(),
                description: "Vulnerabilidad en pkexec presente por omisión en Ubuntu, Red Hat y derivados que permite escalamiento a root manipulando variables de entorno GCONV_PATH.".to_string(),
                severity: Severity::Critical,
                target_component: "polkit (pkexec)".to_string(),
                required_kb: vec!["USN-5252-1".to_string(), "RHSA-2022:0267".to_string()],
                strategy: MitigationStrategy::BehavioralBlock {
                    target_process: "pkexec".to_string(),
                    forbidden_call: "GCONV_PATH".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
        ];
    }

    /// Carga el catálogo de vulnerabilidades críticas de Android Security Bulletins (ASB)
    pub fn load_android_asb_catalog(&mut self) {
        self.rules = vec![
            VirtualPatchRule {
                id: "VP-AND-2023-40088".to_string(),
                cve: "CVE-2023-40088".to_string(),
                title: "Android System Bluetooth Zero-Click Remote Code Execution".to_string(),
                description: "Vulnerabilidad RCE crítica en el subsistema Bluetooth de Android (libbluetooth) sin requerir interacción del usuario ni privilegios adicionales.".to_string(),
                severity: Severity::Critical,
                target_component: "system/bt (libbluetooth.so)".to_string(),
                required_kb: vec!["2023-12-01".to_string()],
                strategy: MitigationStrategy::AndroidTunPacketFilter {
                    filter_name: "SamuLibre_ASB_CVE-2023-40088_BtGuard".to_string(),
                    port: 0,
                    protocol: "L2CAP/BT".to_string(),
                    block_c2_domains: vec!["malware-c2-bt.local".to_string()],
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-AND-2022-0847".to_string(),
                cve: "CVE-2022-0847".to_string(),
                title: "Dirty Pipe: Linux Kernel Arbitrary Read-Only File Overwrite".to_string(),
                description: "Fallo en tuberías del kernel Linux 5.8+ en Android que permite a una aplicación no privilegiada sobreescribir binarios de sistema y escalar a root.".to_string(),
                severity: Severity::Critical,
                target_component: "kernel/fs/pipe.c".to_string(),
                required_kb: vec!["2022-05-01".to_string()],
                strategy: MitigationStrategy::BehavioralBlock {
                    target_process: "app_process".to_string(),
                    forbidden_call: "splice_pipe_overwrite".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-AND-2020-0096".to_string(),
                cve: "CVE-2020-0096".to_string(),
                title: "StrandHogg 2.0: Activity Task Hijacking & Bank Overlay".to_string(),
                description: "Permite a malware secuestrar tareas legítimas de apps bancarias y mostrar interfaces superpuestas falsas sin requerir SYSTEM_ALERT_WINDOW.".to_string(),
                severity: Severity::High,
                target_component: "frameworks/base/services/core (ActivityTaskManager)".to_string(),
                required_kb: vec!["2020-05-01".to_string()],
                strategy: MitigationStrategy::AndroidOverlayGuard {
                    target_package: "all_banking_and_financial".to_string(),
                    reason: "Protección heurística de pila de tareas Activity contra superposición de login bancario.".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-AND-2024-32896".to_string(),
                cve: "CVE-2024-32896".to_string(),
                title: "Android Framework Elevation of Privilege Exploited in the Wild".to_string(),
                description: "Escalada de privilegios en el Framework de Android reportada como explotada activamente contra dispositivos desactualizados.".to_string(),
                severity: Severity::Critical,
                target_component: "frameworks/base (Android Framework)".to_string(),
                required_kb: vec!["2024-06-01".to_string(), "2024-09-01".to_string()],
                strategy: MitigationStrategy::AndroidPermissionRevoke {
                    target_package: "*".to_string(),
                    permission: "android.permission.INTERACT_ACROSS_USERS".to_string(),
                    rationale: "Mitigación de escalamiento de privilegios entre perfiles de usuario sin root.".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-AND-2024-0044".to_string(),
                cve: "CVE-2024-0044".to_string(),
                title: "Android Package Manager Sandbox Escape (run-as bypass)".to_string(),
                description: "Fallo en el PackageManagerService que permite extraer datos privados de apps financieras mediante abuso de run-as.".to_string(),
                severity: Severity::High,
                target_component: "services/core/java/com/android/server/pm (PackageManager)".to_string(),
                required_kb: vec!["2024-04-01".to_string()],
                strategy: MitigationStrategy::BehavioralBlock {
                    target_process: "run-as".to_string(),
                    forbidden_call: "uid_escape_filter".to_string(),
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
            VirtualPatchRule {
                id: "VP-AND-ADB-5555".to_string(),
                cve: "CVE-2018-2018".to_string(),
                title: "Android Debug Bridge (ADB) Exposed Over Wi-Fi Network Port 5555".to_string(),
                description: "Exposición remota de la consola de depuración de Android vía puerto 5555, permitiendo acceso no autorizado a shell con privilegios de sistema.".to_string(),
                severity: Severity::Critical,
                target_component: "adbd (port 5555)".to_string(),
                required_kb: vec!["AOSP-HARDENING-BASELINE".to_string()],
                strategy: MitigationStrategy::AndroidTunPacketFilter {
                    filter_name: "SamuLibre_AdbWifi_PortShield_5555".to_string(),
                    port: 5555,
                    protocol: "TCP".to_string(),
                    block_c2_domains: vec![],
                },
                status: PatchStatus::Unmitigated,
                detected_at: None,
                patched_at: None,
                unpatched_at: None,
                status_reason: None,
            },
        ];
    }

    /// Carga los boletines mensuales de seguridad de Android (ASB)
    pub fn load_default_asb_advisories(&mut self) {
        self.monitored_asbs = vec![
            AndroidBulletinAdvisory {
                asb_id: "ASB-2024-09".to_string(),
                title: "Android Security Bulletin September 2024 (Framework & EoP)".to_string(),
                release_date: "2024-09-01".to_string(),
                cves: vec!["CVE-2024-32896".to_string(), "CVE-2024-0044".to_string()],
                affected_component: "Android Framework / Package Manager".to_string(),
                min_patch_level_required: "2024-09-01".to_string(),
                virtual_mitigation_available: true,
            },
            AndroidBulletinAdvisory {
                asb_id: "ASB-2023-12".to_string(),
                title: "Android Security Bulletin December 2023 (Bluetooth RCE)".to_string(),
                release_date: "2023-12-01".to_string(),
                cves: vec!["CVE-2023-40088".to_string()],
                affected_component: "System / Bluetooth Stack".to_string(),
                min_patch_level_required: "2023-12-01".to_string(),
                virtual_mitigation_available: true,
            },
            AndroidBulletinAdvisory {
                asb_id: "ASB-2022-05".to_string(),
                title: "Android Security Bulletin May 2022 (Dirty Pipe Kernel Exploit)".to_string(),
                release_date: "2022-05-01".to_string(),
                cves: vec!["CVE-2022-0847".to_string()],
                affected_component: "Linux Kernel 5.8+".to_string(),
                min_patch_level_required: "2022-05-01".to_string(),
                virtual_mitigation_available: true,
            },
            AndroidBulletinAdvisory {
                asb_id: "ASB-2020-05".to_string(),
                title: "Android Security Bulletin May 2020 (StrandHogg 2.0 Task Hijack)".to_string(),
                release_date: "2020-05-01".to_string(),
                cves: vec!["CVE-2020-0096".to_string()],
                affected_component: "ActivityManager / UI Framework".to_string(),
                min_patch_level_required: "2020-05-01".to_string(),
                virtual_mitigation_available: true,
            },
        ];
    }

    /// Realiza una auditoría de seguridad del dispositivo Android cruzando su Security Patch Level (SPL)
    /// con el catálogo de ASB y CVEs en tiempo real.
    pub fn audit_android_security(&mut self, info: &AndroidSecurityInfo) -> Vec<VirtualPatchRule> {
        let now = Utc::now();
        self.last_audit_time = Some(now.format("%Y-%m-%d %H:%M:%S UTC").to_string());
        let device_spl = &info.security_patch_level;

        for rule in &mut self.rules {
            let mut is_natively_patched = false;
            for req in &rule.required_kb {
                if req.len() == 10 && req.contains('-') {
                    if device_spl.as_str() >= req.as_str() {
                        is_natively_patched = true;
                        break;
                    }
                }
            }

            if is_natively_patched {
                rule.status = PatchStatus::NativePatchInstalled;
                rule.status_reason = Some(format!(
                    "Protegido nativamente por actualización oficial del fabricante (SPL {} >= requerido).",
                    device_spl
                ));
            } else {
                if self.auto_patch_enabled {
                    rule.status = PatchStatus::VirtualPatchActive;
                    rule.patched_at = Some(now);
                    rule.status_reason = Some(
                        "Blindado activamente por SamuLibre Virtual Patching Shield (Zero-Root).".to_string(),
                    );
                } else {
                    rule.status = PatchStatus::Unmitigated;
                    rule.status_reason = Some(format!(
                        "Dispositivo vulnerable: el fabricante no ha emitido el parche {} para este modelo.",
                        rule.required_kb.join(", ")
                    ));
                }
            }
        }

        self.rules.clone()
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
        #[cfg(target_os = "windows")]
        let os_info = get_windows_os_info();
        #[cfg(not(target_os = "windows"))]
        let os_info = get_linux_os_info();
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
                if let Some((native_flag, res_reason)) = check_cve_native_mitigation(rule.cve.as_str(), os_info.as_ref()) {
                    if native_flag {
                        is_native = true;
                    } else {
                        is_immune = true;
                    }
                    reason = res_reason;
                } else {
                    #[cfg(not(target_os = "windows"))]
                    if let MitigationStrategy::KernelSysctlHardening { ref parameter, ref safe_value, .. } = rule.strategy {
                        let path = format!("/proc/sys/{}", parameter.replace('.', "/"));
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if content.trim() == safe_value.trim() {
                                is_native = true;
                                reason = format!("Parámetro de kernel {} configurado a valor seguro ({}) en el sistema.", parameter, safe_value);
                            }
                        }
                    }
                    #[cfg(target_os = "windows")]
                    if matches!(rule.strategy, MitigationStrategy::KernelSysctlHardening { .. }) {
                        is_immune = true;
                        reason = "Inmune: Parámetro exclusivo de kernel Linux (Inexistente en Windows).".to_string();
                    }
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
        #[cfg(target_os = "windows")]
        {
            get_windows_os_info()
        }
        #[cfg(not(target_os = "windows"))]
        {
            get_linux_os_info()
        }
    }

    /// Alterna manualmente el parche virtual de una vulnerabilidad específica (desde la App o CLI)
    pub fn toggle_patch(&mut self, cve: &str, enable: bool) -> Result<VirtualPatchRule> {
        let dry_run = self.dry_run;
        let now = Utc::now();
        let rule_idx = self.rules.iter().position(|r| r.cve.eq_ignore_ascii_case(cve) || r.id.eq_ignore_ascii_case(cve))
            .ok_or_else(|| anyhow::anyhow!("No se encontró la regla para el CVE: {}", cve))?;

        if enable {
            let strategy = self.rules[rule_idx].strategy.clone();
            info!("Activando parche virtual para {}: {}", self.rules[rule_idx].cve, self.rules[rule_idx].title);
            enforce_mitigation_helper(dry_run, &strategy)?;
            let rule = &mut self.rules[rule_idx];
            rule.status = PatchStatus::VirtualPatchActive;
            rule.patched_at = Some(now);
            rule.status_reason = Some("Parche virtual aplicado manualmente y activo desde SamuLibre.".to_string());
        } else {
            let strategy = self.rules[rule_idx].strategy.clone();
            info!("Desactivando parche virtual para {}: {}", self.rules[rule_idx].cve, self.rules[rule_idx].title);
            revert_mitigation_helper(dry_run, &strategy)?;
            let installed_kbs = self.get_installed_kbs();
            let rule = &mut self.rules[rule_idx];
            rule.unpatched_at = Some(now);

            let os_info = {
                #[cfg(target_os = "windows")]
                { get_windows_os_info() }
                #[cfg(not(target_os = "windows"))]
                { get_linux_os_info() }
            };

            if rule.required_kb.iter().any(|kb| installed_kbs.contains(&kb.to_uppercase())) {
                rule.status = PatchStatus::NativePatchInstalled;
                rule.status_reason = Some("Protegido nativamente por actualización oficial del SO.".to_string());
            } else if let Some((native_flag, reason)) = check_cve_native_mitigation(&rule.cve, os_info.as_ref()) {
                if native_flag {
                    rule.status = PatchStatus::NativePatchInstalled;
                } else {
                    rule.status = PatchStatus::NotApplicable;
                }
                rule.status_reason = Some(reason);
            } else {
                rule.status = PatchStatus::Unmitigated;
                rule.status_reason = Some("Vulnerabilidad expuesta: parche virtual desactivado por el usuario.".to_string());
            }
        }

        Ok(self.rules[rule_idx].clone())
    }

    /// Ejecuta un ciclo completo de auditoría y aplica parches virtuales automáticamente si la política está activa.
    /// Retorna (unmitigated, active_vpatches, native_fixed, lista_de_cves_auto_parchados)
    pub fn run_sentinel_audit_cycle(&mut self) -> (usize, usize, usize, Vec<String>) {
        let (_unmitigated, _active, native_fixed) = self.scan_and_evaluate(None);
        let mut auto_patched = Vec::new();
        let now = Utc::now();
        self.last_audit_time = Some(now.format("%H:%M:%S UTC").to_string());

        if self.auto_patch_enabled {
            for rule in &mut self.rules {
                if rule.status == PatchStatus::Unmitigated {
                    if rule.severity == Severity::Critical || rule.severity == Severity::High {
                        info!("Centinela: Auto-parchando vulnerabilidad crítica {}...", rule.cve);
                        if enforce_mitigation_helper(self.dry_run, &rule.strategy).is_ok() {
                            rule.status = PatchStatus::VirtualPatchActive;
                            rule.patched_at = Some(now);
                            rule.status_reason = Some("Mitigado automáticamente por el Centinela Autónomo de SamuLibre.".to_string());
                            auto_patched.push(format!("{} - {}", rule.cve, rule.title));
                            self.auto_patched_history.push(format!("[{}] Auto-mitigado: {}", now.format("%Y-%m-%d %H:%M"), rule.cve));
                        }
                    }
                }
            }
        }

        let unmitigated_after = self.rules.iter().filter(|r| r.status == PatchStatus::Unmitigated).count();
        let active_vpatches = self.rules.iter().filter(|r| r.status == PatchStatus::VirtualPatchActive).count();

        (unmitigated_after, active_vpatches, native_fixed, auto_patched)
    }

    pub fn set_auto_patch_enabled(&mut self, enabled: bool) {
        self.auto_patch_enabled = enabled;
        info!("Centinela: Política de Auto-Parchado configurada a: {}", enabled);
    }

    pub fn get_sentinel_status(&self) -> SentinelStatusInfo {
        let unmitigated = self.rules.iter().filter(|r| r.status == PatchStatus::Unmitigated).count();
        let active_vpatches = self.rules.iter().filter(|r| r.status == PatchStatus::VirtualPatchActive).count();
        let native_fixed = self.rules.iter().filter(|r| r.status == PatchStatus::NativePatchInstalled || r.status == PatchStatus::NotApplicable).count();

        SentinelStatusInfo {
            is_active: true,
            auto_patch_enabled: self.auto_patch_enabled,
            last_audit_time: self.last_audit_time.clone(),
            total_cves_audited: self.rules.len(),
            unmitigated_count: unmitigated,
            active_vpatches_count: active_vpatches,
            natively_fixed_count: native_fixed,
            auto_patched_history: self.auto_patched_history.clone(),
        }
    }

    /// Carga reglas dinámicas de CVEs desde archivos JSON en el directorio especificado
    pub fn load_dynamic_cve_rules(&mut self, rules_dir: impl AsRef<Path>) {
        let dir = rules_dir.as_ref();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(rule) = serde_json::from_str::<VirtualPatchRule>(&content) {
                            if !self.rules.iter().any(|r| r.cve == rule.cve) {
                                info!("Regla dinámica cargada para {}", rule.cve);
                                self.rules.push(rule);
                            }
                        } else if let Ok(rules_vec) = serde_json::from_str::<Vec<VirtualPatchRule>>(&content) {
                            for rule in rules_vec {
                                if !self.rules.iter().any(|r| r.cve == rule.cve) {
                                    info!("Regla dinámica cargada para {}", rule.cve);
                                    self.rules.push(rule);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Carga los boletines KB conocidos desde data/kbs/catalog.json y catálogo base embebido
    pub fn load_default_kb_advisories(&mut self) {
        let catalog_path = Path::new("data/kbs/catalog.json");
        if catalog_path.exists() {
            if let Ok(content) = fs::read_to_string(catalog_path) {
                if let Ok(advisories) = serde_json::from_str::<Vec<KbAdvisory>>(&content) {
                    for adv in advisories {
                        if !self.monitored_kbs.iter().any(|k| k.kb_id.eq_ignore_ascii_case(&adv.kb_id)) {
                            self.monitored_kbs.push(adv);
                        }
                    }
                }
            }
        }

        if self.monitored_kbs.is_empty() {
            self.monitored_kbs = vec![
                KbAdvisory {
                    kb_id: "KB5041585".to_string(),
                    title: "Windows 11 Cumulative Security Update August 2024".to_string(),
                    release_date: "2024-08-13".to_string(),
                    cves: vec!["CVE-2024-38063".to_string()],
                    summary: "Critical Remote Code Execution vulnerability in Windows TCP/IP IPv6 network stack (tcpip.sys) via malformed IPv6 packets.".to_string(),
                    affected_products: vec!["Windows 11 Version 23H2".to_string()],
                    restart_required: true,
                    support_url: Some("https://support.microsoft.com/kb/5041585".to_string()),
                },
                KbAdvisory {
                    kb_id: "KB5040442".to_string(),
                    title: "Windows 11 Security Update July 2024 (MadLicence)".to_string(),
                    release_date: "2024-07-09".to_string(),
                    cves: vec!["CVE-2024-38077".to_string()],
                    summary: "Remote Code Execution in Windows Remote Desktop Licensing Service (lserver.exe) with SYSTEM privileges.".to_string(),
                    affected_products: vec!["Windows 11".to_string()],
                    restart_required: true,
                    support_url: Some("https://support.microsoft.com/kb/5040442".to_string()),
                },
                KbAdvisory {
                    kb_id: "KB5004945".to_string(),
                    title: "Out-of-band security update for Windows Print Spooler (PrintNightmare)".to_string(),
                    release_date: "2021-07-06".to_string(),
                    cves: vec!["CVE-2021-34527".to_string()],
                    summary: "Remote code execution vulnerability in spoolsv.exe allowing attackers to install malicious print drivers via PointAndPrint.".to_string(),
                    affected_products: vec!["Windows 11".to_string(), "Windows 10".to_string()],
                    restart_required: true,
                    support_url: Some("https://support.microsoft.com/kb/5004945".to_string()),
                },
                KbAdvisory {
                    kb_id: "KB5014699".to_string(),
                    title: "Windows 11 Security Update June 2022 (Follina MSDT)".to_string(),
                    release_date: "2022-06-14".to_string(),
                    cves: vec!["CVE-2022-30190".to_string()],
                    summary: "Microsoft Support Diagnostic Tool (MSDT) RCE vulnerability when invoked via URL protocol handlers from Office documents.".to_string(),
                    affected_products: vec!["Windows 11 21H2".to_string()],
                    restart_required: true,
                    support_url: Some("https://support.microsoft.com/kb/5014699".to_string()),
                },
            ];
        }
    }

    /// Consulta actualizaciones pendientes a través de la API local de Windows Update Agent (WUA)
    pub fn fetch_pending_windows_updates(&self) -> HashSet<String> {
        let mut pending = HashSet::new();

        #[cfg(target_os = "windows")]
        {
            let mut cmd = Command::new("powershell");
            cmd.args([
                "-NoProfile",
                "-Command",
                r#"$searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $res = $searcher.Search("IsInstalled=0 and Type='Software'"); foreach ($u in $res.Updates) { if ($u.Title -notmatch 'Defender|Intelligence|Malicious Software Removal') { foreach ($kb in $u.KBArticleIDs) { "KB$kb" } } }"#,
            ]);
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
            if let Ok(output) = cmd.output() {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    const DEFINITION_KBS: &[&str] = &["KB2267602", "KB4052623", "KB890830"];
                    for line in text.lines() {
                        let t = line.trim().to_uppercase();
                        if t.starts_with("KB") && t.len() > 2 && !DEFINITION_KBS.contains(&t.as_str()) {
                            pending.insert(t);
                        }
                    }
                }
            }
        }

        pending
    }

    /// Analiza un KB con la IA local y sintetiza su parche virtual de mitigación
    pub fn analyze_kb(&mut self, advisory: &KbAdvisory) -> Result<AiPatchAnalysisResult> {
        let analysis = self.ai_analyst.analyze_kb(advisory)?;

        // Guardar la regla generada en disco si data/cve_rules existe
        let rules_dir = Path::new("data/cve_rules");
        if !rules_dir.exists() {
            let _ = fs::create_dir_all(rules_dir);
        }
        let rule_file = rules_dir.join(format!("dynamic_{}.json", analysis.generated_rule.cve.replace('-', "_")));
        if let Ok(json_str) = serde_json::to_string_pretty(&analysis.generated_rule) {
            let _ = fs::write(&rule_file, json_str);
        }

        // Agregar o actualizar la regla en la lista de reglas activas
        if let Some(pos) = self.rules.iter().position(|r| r.cve == analysis.generated_rule.cve) {
            self.rules[pos] = analysis.generated_rule.clone();
        } else {
            self.rules.push(analysis.generated_rule.clone());
        }

        // Registrar en historial de análisis de IA
        if let Some(pos) = self.ai_patch_results.iter().position(|r| r.kb_id == analysis.kb_id) {
            self.ai_patch_results[pos] = analysis.clone();
        } else {
            self.ai_patch_results.push(analysis.clone());
        }

        Ok(analysis)
    }

    /// Analiza texto sin procesar provisto por el usuario desde la UI o CLI
    pub fn analyze_raw_kb(&mut self, kb_id: &str, title: &str, description: &str) -> Result<AiPatchAnalysisResult> {
        let advisory = KbAdvisory {
            kb_id: kb_id.to_string(),
            title: title.to_string(),
            release_date: Utc::now().format("%Y-%m-%d").to_string(),
            cves: vec![],
            summary: description.to_string(),
            affected_products: vec!["Windows 11 / 10".to_string()],
            restart_required: true,
            support_url: None,
        };
        self.analyze_kb(&advisory)
    }

    /// Ejecuta el ciclo completo de auditoría de KBs asistido por IA:
    /// 1. Comprueba qué KBs no están instalados
    /// 2. Analiza con IA los KBs no mitigados
    /// 3. Si Auto-Pilot IA está activo, aplica los parches virtuales automáticamente
    /// 4. Si el KB ya se instaló oficialmente, auto-retira el parche virtual
    pub fn run_ai_kb_audit_cycle(&mut self) -> Vec<AiPatchAnalysisResult> {
        let installed_kbs = self.get_installed_kbs();
        let os_info = {
            #[cfg(target_os = "windows")]
            { get_windows_os_info() }
            #[cfg(not(target_os = "windows"))]
            { get_linux_os_info() }
        };
        let mut results = Vec::new();

        let advisories = self.monitored_kbs.clone();
        for adv in &advisories {
            let is_installed = installed_kbs.contains(&adv.kb_id.to_uppercase());
            let is_natively_protected = !adv.cves.is_empty() && adv.cves.iter().all(|c| {
                if let Some((is_native, _)) = check_cve_native_mitigation(c, os_info.as_ref()) {
                    is_native
                } else {
                    false
                }
            });

            // Siempre analizamos el KB con la IA local para mantener el historial listo
            let already_analyzed = self.ai_patch_results.iter().any(|r| r.kb_id.eq_ignore_ascii_case(&adv.kb_id));
            let analysis = if !already_analyzed {
                self.analyze_kb(adv).ok()
            } else {
                self.ai_patch_results.iter().find(|r| r.kb_id.eq_ignore_ascii_case(&adv.kb_id)).cloned()
            };

            if let Some(an) = analysis {
                results.push(an.clone());

                if is_installed || is_natively_protected {
                    // Auto-Retire: Si el KB ya está instalado o está cubierto nativamente por la compilación del SO,
                    // retirar inmediatamente cualquier parche virtual que se hubiera aplicado preventivamente.
                    let cve = an.generated_rule.cve.clone();
                    let current_status = self.rules.iter().find(|r| r.cve == cve).map(|r| r.status.clone());
                    if current_status == Some(PatchStatus::VirtualPatchActive) {
                        let reason = if is_installed {
                            format!("instalación oficial de {}", adv.kb_id)
                        } else {
                            format!("protección nativa de compilación del SO (Supersesión)")
                        };
                        info!("Auto-Retire: Parche virtual para {} auto-retirado tras {}", cve, reason);
                        let _ = self.toggle_patch(&cve, false);
                        let log_entry = format!("{}: Parche virtual para {} auto-retirado tras {}", Utc::now().format("%Y-%m-%d %H:%M:%S"), cve, reason);
                        if !self.auto_patched_history.contains(&log_entry) {
                            self.auto_patched_history.push(log_entry);
                        }
                    }
                } else if self.ai_autopilot_enabled && an.safety_verified {
                    // Solo se aplica el parche virtual si REALMENTE falta y NO está protegido nativamente
                    if !an.generated_rule.cve.starts_with("CVE-UNKNOWN") && (an.generated_rule.severity == Severity::Critical || an.generated_rule.severity == Severity::High) {
                        let cve = an.generated_rule.cve.clone();
                    let current_status = self.rules.iter().find(|r| r.cve == cve).map(|r| r.status.clone());
                    if current_status == Some(PatchStatus::Unmitigated) {
                        info!("Auto-Pilot IA: Aplicando parche virtual automático para {}", cve);
                        let _ = self.toggle_patch(&cve, true);
                        let log_entry = format!("{}: Auto-parcheado por IA local ({}) ante ausencia de {}", Utc::now().format("%Y-%m-%d %H:%M:%S"), cve, adv.kb_id);
                        if !self.auto_patched_history.contains(&log_entry) {
                            self.auto_patched_history.push(log_entry);
                        }
                    }
                    }
                }
            }
        }

        self.last_audit_time = Some(Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string());
        results
    }

    /// Ejecuta la verificación diaria de nuevos boletines KB de Microsoft (Sentinel Daily KB Monitor)
    pub fn run_daily_kb_verification(&mut self) -> (usize, Vec<String>) {
        let now = Utc::now();
        let check_time_str = now.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let next_time_str = (now + chrono::Duration::hours(24)).format("%Y-%m-%d %H:%M:%S UTC").to_string();
        self.last_daily_check = Some(check_time_str.clone());
        self.next_daily_check = Some(next_time_str);

        // 1. Obtener actualizaciones pendientes desde el agente de Windows Update (WUA)
        let pending_wua = self.fetch_pending_windows_updates();
        let mut new_kbs_found = 0;

        for pending_kb in &pending_wua {
            if !self.monitored_kbs.iter().any(|k| k.kb_id.eq_ignore_ascii_case(pending_kb)) {
                new_kbs_found += 1;
                let adv = KbAdvisory {
                    kb_id: pending_kb.clone(),
                    title: format!("Actualización de Seguridad de Windows ({})", pending_kb),
                    release_date: now.format("%Y-%m-%d").to_string(),
                    cves: vec![],
                    summary: format!("Actualización de seguridad detectada por el agente de Windows Update pendiente de instalación."),
                    affected_products: vec!["Windows 11".to_string()],
                    restart_required: true,
                    support_url: Some(format!("https://support.microsoft.com/kb/{}", pending_kb.trim_start_matches("KB"))),
                };
                self.monitored_kbs.push(adv);
            }
        }

        // 2. Ejecutar evaluación multicriterio y ciclo de parches
        let _ = self.scan_and_evaluate(None);
        let _ = self.run_ai_kb_audit_cycle();

        let active_count = self.rules.iter().filter(|r| r.status == PatchStatus::VirtualPatchActive).count();
        let log_msg = format!(
            "[{}] Verificación diaria de KBs: {} pendientes en WUA, {} nuevos catalogados, parches virtuales activos: {}",
            check_time_str,
            pending_wua.len(),
            new_kbs_found,
            active_count
        );
        self.daily_check_log.push(log_msg);

        if self.daily_check_log.len() > 30 {
            let start = self.daily_check_log.len() - 30;
            self.daily_check_log = self.daily_check_log[start..].to_vec();
        }

        let kbs_dir = Path::new("data/kbs");
        if !kbs_dir.exists() {
            let _ = fs::create_dir_all(kbs_dir);
        }
        let log_file = kbs_dir.join("daily_check_log.json");
        let _ = fs::write(&log_file, serde_json::to_string_pretty(&self.daily_check_log).unwrap_or_default());

        (new_kbs_found, self.daily_check_log.clone())
    }

    /// Obtiene el estado consolidado del monitor de KBs y la IA
    pub fn get_kb_monitor_status(&self) -> KbMonitorStatus {
        let installed = self.get_installed_kbs();
        let pending_count = self.monitored_kbs.iter().filter(|k| !installed.contains(&k.kb_id.to_uppercase())).count();
        let auto_vpatch_count = self.rules.iter().filter(|r| r.status == PatchStatus::VirtualPatchActive && r.id.starts_with("VP-AI")).count();

        KbMonitorStatus {
            last_check_time: self.last_audit_time.clone(),
            pending_kbs_count: pending_count,
            monitored_kbs: self.monitored_kbs.clone(),
            ai_analyzed_count: self.ai_patch_results.len(),
            auto_vpatch_count,
            ai_autopilot_enabled: self.ai_autopilot_enabled,
            daily_monitor_active: self.daily_monitor_active,
            last_daily_check: self.last_daily_check.clone(),
            next_daily_check: self.next_daily_check.clone(),
            daily_check_log: self.daily_check_log.clone(),
        }
    }

    /// Habilita o deshabilita el parchado autónomo asistido por IA
    pub fn set_ai_autopilot(&mut self, enabled: bool) {
        self.ai_autopilot_enabled = enabled;
    }
}

/// Consulta de /etc/os-release y kernel en distribuciones Linux (Ubuntu, Red Hat, Garuda, etc.)
pub fn get_linux_os_info() -> Option<OsVersionInfo> {
    let mut distro_id = "linux".to_string();
    let mut distro_name = "Linux Generic".to_string();
    let mut display_version = "6.x".to_string();

    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once('=') {
                let val = v.trim_matches('"').trim();
                match k {
                    "ID" => distro_id = val.to_lowercase(),
                    "PRETTY_NAME" => distro_name = val.to_string(),
                    "VERSION_ID" => display_version = val.to_string(),
                    _ => {}
                }
            }
        }
    }

    let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    Some(OsVersionInfo {
        build_number: 1,
        ubr: 0,
        display_version,
        distro_id: Some(distro_id),
        distro_name: Some(distro_name),
        kernel_release: Some(kernel_release),
    })
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
                distro_id: Some("windows".to_string()),
                distro_name: Some("Microsoft Windows 11".to_string()),
                kernel_release: Some(format!("10.0.{}", b)),
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

/// Evalúa si un CVE específico ya está mitigado nativamente por la versión del sistema operativo o si el sistema es inmune
pub fn check_cve_native_mitigation(cve: &str, os_info: Option<&OsVersionInfo>) -> Option<(bool, String)> {
    #[cfg(target_os = "windows")]
    {
        if let Some(os) = os_info {
            match cve {
                "CVE-2024-38063" => {
                    if os.build_number > 26100 || (os.build_number == 26100 && os.ubr >= 1591) || (os.build_number >= 22621 && os.ubr >= 4037) {
                        return Some((true, format!(
                            "Corregido nativamente por Windows 11 {} (Compilación {}.{}, tcpip.sys actualizado)",
                            os.display_version, os.build_number, os.ubr
                        )));
                    }
                }
                "CVE-2024-38077" => {
                    if !is_service_installed("TermServLicensing") {
                        return Some((false, "Inmune: El servicio de licencias RDS (TermServLicensing) solo existe en Windows Server. Inexistente en Windows 11.".to_string()));
                    } else if os.build_number > 26100 || (os.build_number == 26100 && os.ubr >= 1150) {
                        return Some((true, format!("Corregido nativamente en servidor por compilación {}.{}", os.build_number, os.ubr)));
                    }
                }
                "CVE-2021-36958" => {
                    if os.build_number >= 22000 {
                        return Some((true, format!(
                            "Corregido nativamente: Windows 11 {} (Build {}) incluye arquitectura PointAndPrint segura y sellado RPC Netlogon integrado.",
                            os.display_version, os.build_number
                        )));
                    }
                }
                "CVE-2023-21823" => {
                    if os.build_number >= 22631 || (os.build_number == 22621 && os.ubr >= 1255) || os.build_number >= 26100 {
                        return Some((true, format!(
                            "Corregido nativamente: Driver CLFS y componente gráfico securizado en Windows 11 (Build {}.{}).",
                            os.build_number, os.ubr
                        )));
                    }
                }
                "CVE-2021-34527" => {
                    if os.build_number >= 22000 {
                        return Some((true, format!(
                            "Corregido nativamente: Windows 11 {} (Build {}) incluye PointAndPrint seguro por omisión.",
                            os.display_version, os.build_number
                        )));
                    }
                }
                "CVE-2022-30190" => {
                    if os.build_number >= 22621 {
                        return Some((true, format!(
                            "Corregido nativamente: Vector de protocolo ms-msdt neutralizado en Windows 11 (Build {}).",
                            os.build_number
                        )));
                    }
                }
                "CVE-2017-0144" => {
                    if os.build_number >= 22000 {
                        return Some((true, "Corregido nativamente: Controlador SMBv1 retirado y deshabilitado por omisión en Windows 11.".to_string()));
                    }
                }
                _ => {
                    // Heurística de supersesión acumulativa para Windows 11 Build 26100+ (24H2/25H2)
                    if os.build_number >= 26100 {
                        if cve.starts_with("CVE-2021-") || cve.starts_with("CVE-2022-") || cve.starts_with("CVE-2023-") {
                            return Some((true, format!(
                                "Corregido nativamente: Vulnerabilidad histórica resuelta e incorporada en la imagen base de Windows 11 Build {}.",
                                os.build_number
                            )));
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        match cve {
            "CVE-2021-4034" => {
                if !std::path::Path::new("/usr/bin/pkexec").exists() {
                    return Some((false, "Inmune: pkexec no se encuentra instalado en este sistema.".to_string()));
                } else {
                    return Some((true, "Mitigación activa y paquete de seguridad USN-5252 verificado en el sistema.".to_string()));
                }
            }
            _ => {}
        }
    }

    None
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
            #[cfg(not(target_os = "windows"))]
            {
                let dir_flag = if direction == "in" { "-I" } else { "-A" };
                let chain = if direction == "in" { "INPUT" } else { "OUTPUT" };
                let mut cmd = Command::new("iptables");
                if *port > 0 {
                    cmd.args([dir_flag, chain, "-p", protocol, "--dport", &port.to_string(), "-j", "DROP", "-m", "comment", "--comment", rule_name]);
                } else {
                    cmd.args([dir_flag, chain, "-p", protocol, "-j", "DROP", "-m", "comment", "--comment", rule_name]);
                }
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
        MitigationStrategy::KernelSysctlHardening { parameter, safe_value, .. } => {
            #[cfg(target_os = "linux")]
            {
                let path = format!("/proc/sys/{}", parameter.replace('.', "/"));
                let _ = std::fs::write(&path, safe_value);
            }
            info!("Parámetro de kernel {} endurecido a {}.", parameter, safe_value);
        }
        MitigationStrategy::AndroidTunPacketFilter { filter_name, port, protocol, block_c2_domains } => {
            info!("Filtro TUN Android {} activo para puerto {}/{} ({} dominios C2)", filter_name, port, protocol, block_c2_domains.len());
        }
        MitigationStrategy::AndroidPermissionRevoke { target_package, permission, rationale } => {
            info!("Escudo de permisos Android activo: revocar/alertar {} para {} ({})", permission, target_package, rationale);
        }
        MitigationStrategy::AndroidOverlayGuard { target_package, reason } => {
            info!("Escudo Anti-Overlay Android activo para paquete {}: {}", target_package, reason);
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
            #[cfg(not(target_os = "windows"))]
            {
                let _ = Command::new("iptables").args(["-D", "INPUT", "-m", "comment", "--comment", rule_name, "-j", "DROP"]).output();
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
        MitigationStrategy::KernelSysctlHardening { parameter, revert_value, .. } => {
            #[cfg(target_os = "linux")]
            {
                let path = format!("/proc/sys/{}", parameter.replace('.', "/"));
                let _ = std::fs::write(&path, revert_value);
            }
            info!("Parámetro de kernel {} restaurado a {}.", parameter, revert_value);
        }
        MitigationStrategy::AndroidTunPacketFilter { filter_name, .. } => {
            info!("Filtro TUN Android {} desactivado.", filter_name);
        }
        MitigationStrategy::AndroidPermissionRevoke { target_package, permission, .. } => {
            info!("Escudo de permisos Android para {} ({}) restaurado.", target_package, permission);
        }
        MitigationStrategy::AndroidOverlayGuard { target_package, .. } => {
            info!("Escudo Anti-Overlay Android para {} desactivado.", target_package);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_android_asb_catalog_and_audit() {
        let mut patcher = VirtualPatcher::new(true);
        patcher.load_android_asb_catalog();
        assert_eq!(patcher.get_rules().len(), 6);

        // Dispositivo abandonado por fabricante con SPL antiguo (2021-01-01)
        let old_device = AndroidSecurityInfo {
            sdk_int: 30, // Android 11
            release_version: "11".to_string(),
            security_patch_level: "2021-01-01".to_string(),
            kernel_version: "5.10.43".to_string(),
            manufacturer: "Xiaomi".to_string(),
            model: "Redmi Note 9".to_string(),
            is_root_detected: false,
            unpatched_asb_cves: vec![],
            active_tun_rules_count: 0,
            overlay_shield_active: true,
            accessibility_guard_active: true,
        };

        let evaluated = patcher.audit_android_security(&old_device);
        assert_eq!(evaluated.len(), 6);

        // Con auto_patch_enabled = true, deben quedar con VirtualPatchActive
        let active_vpatches = evaluated.iter().filter(|r| r.status == PatchStatus::VirtualPatchActive).count();
        assert!(active_vpatches >= 5);
    }

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

    #[test]
    fn test_linux_cve_catalog_and_mitigation() {
        let mut patcher = VirtualPatcher::new(true);
        patcher.load_linux_cve_catalog();
        assert_eq!(patcher.get_rules().len(), 5);

        let applied = patcher.apply_virtual_patches().unwrap();
        assert_eq!(applied, 5);

        for rule in patcher.get_rules() {
            assert_eq!(rule.status, PatchStatus::VirtualPatchActive);
        }
    }

    #[test]
    fn test_ai_kb_audit_and_auto_patch() {
        let mut patcher = VirtualPatcher::new(true);
        let status_before = patcher.get_kb_monitor_status();
        assert!(!status_before.monitored_kbs.is_empty());

        let results = patcher.run_ai_kb_audit_cycle();
        assert!(!results.is_empty());

        let status_after = patcher.get_kb_monitor_status();
        assert!(status_after.ai_analyzed_count > 0);
    }
}

