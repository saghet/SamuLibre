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
