use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Severidad de amenaza o vulnerabilidad
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "BAJA"),
            Severity::Medium => write!(f, "MEDIA"),
            Severity::High => write!(f, "ALTA"),
            Severity::Critical => write!(f, "CRÍTICA"),
        }
    }
}

/// Estado del parchado virtual para una vulnerabilidad específica
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PatchStatus {
    /// La vulnerabilidad existe y aún no está mitigada
    Unmitigated,
    /// El parche virtual de SamuLibre está activo y protegiendo el sistema
    VirtualPatchActive,
    /// El SO ya instaló la actualización oficial (KB), parche virtual desactivado
    NativePatchInstalled,
    /// El componente afectado no existe en esta máquina
    NotApplicable,
}

/// Tipo de mecanismo utilizado para el parche virtual
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitigationStrategy {
    /// Bloqueo o filtrado dinámico de red / puerto sospechoso (WFP / Firewall)
    NetworkFirewall {
        rule_name: String,
        port: u16,
        protocol: String,
        direction: String,
    },
    /// Desactivación o aislamiento temporal de servicio vulnerable
    ServiceMitigation {
        service_name: String,
        startup_type: String,
    },
    /// Clave de registro de mitigación / políticas de ejecución
    RegistryHardening {
        key_path: String,
        value_name: String,
        safe_value: String,
        revert_value: String,
    },
    /// Regla heurística / filtrado de memoria
    BehavioralBlock {
        target_process: String,
        forbidden_call: String,
    },
    /// Endurecimiento de parámetros de kernel (sysctl en Linux)
    KernelSysctlHardening {
        parameter: String,
        safe_value: String,
        revert_value: String,
    },
    /// Filtrado dinámico de paquetes en espacio de usuario vía VpnService TUN (Android)
    AndroidTunPacketFilter {
        filter_name: String,
        port: u16,
        protocol: String,
        block_c2_domains: Vec<String>,
    },
    /// Restricción o advertencia de permisos abusivos en Android
    AndroidPermissionRevoke {
        target_package: String,
        permission: String,
        rationale: String,
    },
    /// Blindaje contra ataques de superposición de pantalla (Anti-Overlay / Cloak & Dagger)
    AndroidOverlayGuard {
        target_package: String,
        reason: String,
    },
}

/// Definición de una regla de parchado virtual
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualPatchRule {
    pub id: String,
    pub cve: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub target_component: String,
    pub required_kb: Vec<String>,
    pub strategy: MitigationStrategy,
    pub status: PatchStatus,
    pub detected_at: Option<DateTime<Utc>>,
    pub patched_at: Option<DateTime<Utc>>,
    pub unpatched_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub status_reason: Option<String>,
}

/// Alerta de seguridad generada por el sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub category: ThreatCategory,
    pub title: String,
    pub details: String,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub target_path: Option<String>,
    pub action_taken: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatCategory {
    MalwareFile,
    LsassMemoryAccess,
    BrowserCredentialTheft,
    RansomwareCanaryTrip,
    VirtualPatchApplied,
    VirtualPatchReverted,
    VpnKillswitchEngaged,
    SuspiciousScript,
    LinuxPrivilegeEscalation,
    LinuxRootkitInjection,
    AndroidBankerOverlayAttempt,
    AndroidAccessibilityAbuse,
    AndroidMaliciousApkSideload,
    AndroidAsbVulnerabilityDetected,
}

/// Información multiplataforma del sistema operativo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub os_family: String,
    pub distro_id: String,
    pub distro_name: String,
    pub kernel_version: String,
    pub desktop_env: String,
}

/// Resultado de escaneo de un archivo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: String,
    pub sha256: String,
    pub status: FileScanStatus,
    pub detection_name: Option<String>,
    pub engine: String,
    pub scan_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileScanStatus {
    Clean,
    Infected,
    Suspicious,
    AccessDenied,
}

/// Registro histórico o en tiempo real de una amenaza detectada para toma de decisiones
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRecord {
    pub id: String,
    pub timestamp: String,
    pub file_path: String,
    pub threat_name: String,
    pub engine: String,
    pub sha256: String,
    pub severity: String,
    pub action_taken: String, // "En Cuarentena", "Eliminado", "Excluido", "Ignorado", "Pendiente", "Restaurado"
    pub quarantine_id: Option<String>,
    pub origin_source: Option<String>,
    pub origin_url: Option<String>,
    pub human_explanation: Option<String>,
    pub suggested_action: Option<String>,
}

/// Estado global del suite SamuLibre
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuiteStatus {
    pub core_running: bool,
    pub scanner_active: bool,
    pub shield_active: bool,
    pub virtual_patcher_active: bool,
    pub vpn_active: bool,
    pub active_virtual_patches_count: usize,
    pub native_repaired_cves_count: usize,
    pub threats_blocked_total: u64,
    pub canaries_deployed_count: usize,
    pub last_scan_timestamp: Option<DateTime<Utc>>,
}

/// Información de un boletín o actualización KB de Microsoft Windows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbAdvisory {
    pub kb_id: String,
    pub title: String,
    pub release_date: String,
    pub cves: Vec<String>,
    pub summary: String,
    pub affected_products: Vec<String>,
    pub restart_required: bool,
    pub support_url: Option<String>,
}

/// Resultado de análisis generado por la IA local para un KB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiPatchAnalysisResult {
    pub kb_id: String,
    pub cve: String,
    pub attack_vector: String,
    pub affected_component: String,
    pub risk_assessment: String,
    pub recommended_mitigation: MitigationStrategy,
    pub reasoning: String,
    pub confidence_score: f32,
    pub safety_verified: bool,
    pub generated_rule: VirtualPatchRule,
}

/// Estado del monitor de KBs y orquestador de IA local
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbMonitorStatus {
    pub last_check_time: Option<String>,
    pub pending_kbs_count: usize,
    pub monitored_kbs: Vec<KbAdvisory>,
    pub ai_analyzed_count: usize,
    pub auto_vpatch_count: usize,
    pub ai_autopilot_enabled: bool,
    #[serde(default)]
    pub daily_monitor_active: bool,
    #[serde(default)]
    pub last_daily_check: Option<String>,
    #[serde(default)]
    pub next_daily_check: Option<String>,
    #[serde(default)]
    pub daily_check_log: Vec<String>,
}

/// Tipo de mecanismo de persistencia detectado en el arranque del SO
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PersistenceType {
    RegistryRun,
    RegistryWinlogon,
    ScheduledTask,
    StartupFolder,
    SystemDriverOrService,
}

/// Entrada de auto-inicio o persistencia auditada
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub id: String,
    pub name: String,
    pub target_path: String,
    pub arguments: Option<String>,
    pub entry_type: PersistenceType,
    pub location: String,
    pub is_enabled: bool,
    pub sha256: Option<String>,
    pub status: FileScanStatus,
    pub detection_details: Option<String>,
}

/// Socket o conexión de red inspeccionada en tiempo real
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSocketInfo {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
    pub is_risk_port: bool,
    pub is_isolated: bool,
}

/// Botón o píldora de acción sugerida por el Copiloto IA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotActionPill {
    pub label: String,
    pub action_type: String,
    pub payload: String,
}

/// Respuesta contextual generada por el Copiloto de Ciberseguridad local
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopilotResponse {
    pub answer: String,
    pub confidence: f32,
    pub risk_level: Severity,
    pub suggested_actions: Vec<CopilotActionPill>,
    pub timestamp: String,
}

/// Estado e información de seguridad específica para dispositivos Android
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidSecurityInfo {
    pub sdk_int: u32,
    pub release_version: String,
    pub security_patch_level: String,
    pub kernel_version: String,
    pub manufacturer: String,
    pub model: String,
    pub is_root_detected: bool,
    pub unpatched_asb_cves: Vec<String>,
    pub active_tun_rules_count: usize,
    pub overlay_shield_active: bool,
    pub accessibility_guard_active: bool,
}

/// Información de un Boletín de Seguridad de Android (ASB)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidBulletinAdvisory {
    pub asb_id: String,
    pub title: String,
    pub release_date: String,
    pub cves: Vec<String>,
    pub affected_component: String,
    pub min_patch_level_required: String,
    pub virtual_mitigation_available: bool,
}

/// Acción tomada por el motor TUN de filtrado de paquetes en Android
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TunPacketAction {
    Accept,
    Drop {
        reason: String,
        rule_id: String,
        src_ip: String,
        dst_ip: String,
        port: u16,
    },
}

/// Información de un paquete o aplicación instalada en el dispositivo Android
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidPackageInfo {
    pub package_name: String,
    pub app_name: String,
    pub version_name: String,
    pub is_system_app: bool,
    pub installer_package_name: Option<String>,
    pub requested_permissions: Vec<String>,
    pub has_overlay_permission: bool,
    pub has_accessibility_service: bool,
    pub apk_path: Option<String>,
    pub sha256: Option<String>,
}


