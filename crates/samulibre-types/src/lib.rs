use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    RansomwareActivity,
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

/// Clasificación de veredicto en 5 niveles para mitigar y gestionar falsos positivos
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatVerdict {
    /// Amenaza confirmada mediante firma exacta SHA-256 o regla YARA estricta
    ConfirmedMalware,
    /// Alta probabilidad de malware según heurística multicapa y análisis de comportamiento
    LikelyMalware,
    /// Resultado no concluyente (archivo protegido o empaquetado no analizable directamente)
    Inconclusive,
    /// Archivo benigno probablemente empaquetado o herramienta de administración legítima
    LikelyFalsePositive,
    /// Falso positivo confirmado y verificado (exclusión anclada por hash SHA-256)
    ConfirmedFalsePositive,
}

/// Registro de exclusión de análisis anclada criptográficamente por hash SHA-256
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedExclusion {
    pub path: String,
    pub sha256: Option<String>,
    pub reason: String,
    pub added_at: String,
}

/// Categoría técnica del elemento excluido en el módulo avanzado de excepciones
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExceptionType {
    Folder { include_subdirectories: bool },
    File { sha256_pinned: Option<String> },
    Extension { ext: String },
    Sha256Hash { hash: String },
}

/// Alcance granular de la excepción en los motores de protección
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExceptionScope {
    pub manual_scan: bool,
    pub realtime_protection: bool,
    pub heuristic_analysis: bool,
    pub scheduled_scan: bool,
    pub downloaded_files: bool,
}

impl Default for ExceptionScope {
    fn default() -> Self {
        Self {
            manual_scan: true,
            realtime_protection: true,
            heuristic_analysis: true,
            scheduled_scan: true,
            downloaded_files: true,
        }
    }
}

/// Categoría de justificación operativa de la excepción
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReasonCategory {
    LegitimateApplication,
    SoftwareDevelopment,
    AdministrativeTool,
    EnterpriseSoftware,
    InvestigatedFalsePositive,
    Other,
}

/// Nivel de riesgo asignado a la excepción según su amplitud y criticidad
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExceptionRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Registro en bitácora de auditoría para trazabilidad de modificaciones
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExceptionAuditEntry {
    pub timestamp: String,
    pub action: String,
    pub details: String,
}

/// Registro completo de una Excepción de Seguridad en SamuLibre
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityException {
    pub id: String,
    pub name: String,
    pub target: String,
    pub exception_type: ExceptionType,
    pub scope: ExceptionScope,
    pub reason_category: ReasonCategory,
    pub justification: String,
    pub risk_level: ExceptionRiskLevel,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub is_active: bool,
    pub audit_history: Vec<ExceptionAuditEntry>,
}

impl SecurityException {
    /// Determina si una excepción temporal ha caducado
    pub fn is_expired(&self) -> bool {
        if let Some(ref exp_str) = self.expires_at {
            if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp_str) {
                return chrono::Utc::now() > exp_dt.with_timezone(&chrono::Utc);
            }
        }
        false
    }
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

/// Frecuencia configurada para escaneos programados en Windows y Linux
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScheduleFrequency {
    Daily,
    Weekly,
    Hourly,
    IntervalHours(u32),
    Every8Days,
    IntervalDays(u32),
}

/// Objetivo del escaneo programado
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanTargetType {
    Quick,
    Full,
    Custom,
}

/// Configuración persistente del planificador de escaneos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScanConfig {
    pub enabled: bool,
    pub frequency: ScheduleFrequency,
    pub target_type: ScanTargetType,
    pub custom_paths: Vec<String>,
    pub scheduled_time: String,
    pub last_run: Option<String>,
    pub next_run: Option<String>,
    pub last_result_threats: usize,
    pub last_result_scanned: usize,
}

impl Default for ScheduledScanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            frequency: ScheduleFrequency::Daily,
            target_type: ScanTargetType::Quick,
            custom_paths: Vec::new(),
            scheduled_time: "02:00".to_string(),
            last_run: None,
            next_run: None,
            last_result_threats: 0,
            last_result_scanned: 0,
        }
    }
}

/// Configuración de directorios y estado de la protección en tiempo real (Watcher)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatcherSettings {
    pub enabled: bool,
    pub custom_watch_dirs: Vec<String>,
    pub files_inspected_total: usize,
    pub threats_intercepted_total: usize,
}

impl Default for WatcherSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_watch_dirs: Vec::new(),
            files_inspected_total: 0,
            threats_intercepted_total: 0,
        }
    }
}

/// Estados operacionales de la protección en tiempo real
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RealtimeProtectionStatus {
    Active,
    Initializing,
    Partial,
    Disabled,
    Error,
    Unverified,
}

impl std::fmt::Display for RealtimeProtectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "PROTECCIÓN ACTIVA"),
            Self::Initializing => write!(f, "INICIALIZANDO"),
            Self::Partial => write!(f, "PROTECCIÓN PARCIAL"),
            Self::Disabled => write!(f, "PROTECCIÓN DESACTIVADA"),
            Self::Error => write!(f, "ERROR DE PROTECCIÓN"),
            Self::Unverified => write!(f, "NO VERIFICADO"),
        }
    }
}

/// Telemetría y estado en tiempo real del subsistema de monitorización y cola
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeTelemetry {
    pub status: RealtimeProtectionStatus,
    pub status_detail: String,
    pub service_running: bool,
    pub watcher_running: bool,
    pub queue_depth: usize,
    pub events_enqueued_total: usize,
    pub events_processed_total: usize,
    pub events_dropped_total: usize,
    pub files_inspected_total: usize,
    pub threats_intercepted_total: usize,
    pub last_event_path: Option<String>,
    pub last_event_timestamp: Option<String>,
    pub last_error: Option<String>,
    pub uptime_seconds: u64,
    pub monitored_paths: Vec<String>,
}

impl Default for RealtimeTelemetry {
    fn default() -> Self {
        Self {
            status: RealtimeProtectionStatus::Unverified,
            status_detail: "Esperando inicialización del subsistema...".to_string(),
            service_running: false,
            watcher_running: false,
            queue_depth: 0,
            events_enqueued_total: 0,
            events_processed_total: 0,
            events_dropped_total: 0,
            files_inspected_total: 0,
            threats_intercepted_total: 0,
            last_event_path: None,
            last_event_timestamp: None,
            last_error: None,
            uptime_seconds: 0,
            monitored_paths: Vec::new(),
        }
    }
}

/// Informe de autodiagnóstico integral de protección en tiempo real
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeDiagnosticReport {
    pub timestamp: String,
    pub overall_status: RealtimeProtectionStatus,
    pub windows_service_ok: bool,
    pub file_monitor_ok: bool,
    pub event_queue_ok: bool,
    pub scan_engine_ok: bool,
    pub signatures_ok: bool,
    pub yara_ok: bool,
    pub heuristic_ok: bool,
    pub quarantine_ok: bool,
    pub ui_communication_ok: bool,
    pub tests_executed: usize,
    pub tests_passed: usize,
    pub details: Vec<RealtimeDiagnosticTestResult>,
}

/// Resultado de una prueba puntual del autodiagnóstico
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeDiagnosticTestResult {
    pub name: String,
    pub passed: bool,
    pub duration_ms: u64,
    pub correlation_id: Option<String>,
    pub detail: String,
}

/// Estados normalizados para los subsistemas de protección
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubsystemState {
    Running,
    Stopped,
    Starting,
    Degraded,
    Failed,
    NotInstalled,
    NotConfigured,
    NotTested,
    Unknown,
}

impl std::fmt::Display for SubsystemState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "RUNNING"),
            Self::Stopped => write!(f, "STOPPED"),
            Self::Starting => write!(f, "STARTING"),
            Self::Degraded => write!(f, "DEGRADED"),
            Self::Failed => write!(f, "FAILED"),
            Self::NotInstalled => write!(f, "NOT_INSTALLED"),
            Self::NotConfigured => write!(f, "NOT_CONFIGURED"),
            Self::NotTested => write!(f, "NOT_TESTED"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Informe de salud y evidencia de un subsistema individual de protección
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubsystemHealthReport {
    pub name: String,
    pub state: SubsystemState,
    pub checked_at: String,
    pub last_event: Option<String>,
    pub last_error: Option<String>,
    pub version: Option<String>,
    pub metrics: HashMap<String, String>,
    pub evidence: String,
}

/// Instantánea centralizada del estado de salud de todos los subsistemas (Fuente Única de Verdad)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionHealthSnapshot {
    pub overall_status: SubsystemState,
    pub overall_status_label: String,
    pub overall_status_color: String, // "green", "yellow", "red", "gray"
    pub checked_at: String,
    pub subsystems: Vec<SubsystemHealthReport>,
    pub active_watch_dirs: Vec<String>,
    pub telemetry: RealtimeTelemetry,
    pub evidence_summary: String,
}
