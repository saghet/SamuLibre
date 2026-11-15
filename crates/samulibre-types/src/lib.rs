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
    ExploitAttempt,
    CredentialTheft,
    ActiveAttack,
    TorSecurityThreat,
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

/// Niveles de confianza calibrados para clasificación de amenazas
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ConfidenceLevel {
    /// No existen evidencias suficientes para clasificarlo como amenaza
    #[default]
    Bajo,
    /// Presenta características anómalas, pero no existe evidencia suficiente para declararlo malware
    Medio,
    /// Existen evidencias importantes, pero se requiere corroboración adicional
    Alto,
    /// Existe evidencia sólida: firma de malware validada o múltiples indicadores independientes maliciosos
    Critico,
}

impl ConfidenceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critico => "CRÍTICO / MALICIOSO CONFIRMADO",
            Self::Alto => "ALTO / PROBABLEMENTE MALICIOSO",
            Self::Medio => "MEDIO / SOSPECHOSO",
            Self::Bajo => "BAJO / NO CONCLUYENTE",
        }
    }

    pub fn severity_label(&self) -> &'static str {
        match self {
            Self::Critico => "Crítica",
            Self::Alto => "Alta",
            Self::Medio => "Media",
            Self::Bajo => "Baja",
        }
    }
}

/// Categoría independiente de evidencia para evitar doble conteo de rasgos derivados
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EvidenceCategory {
    SignatureHash,
    YaraRule,
    StructuralPe,
    EntropyObfuscation,
    Authenticity,
    OriginContext,
    BehavioralPattern,
    DocumentExploit,
}

/// Evidencia individual recopilada durante el análisis multicapa
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvidence {
    pub category: EvidenceCategory,
    pub rule_id: String,
    pub description: String,
    /// Peso calibrado (positivo = riesgo, negativo = atenuante/legitimidad)
    pub weight: i32,
    /// Indica si la evidencia por sí sola constituye confirmación criptográfica/EICAR
    pub is_definitive: bool,
    pub source_feed: Option<String>,
}

/// Estado de verificación humana / analista sobre una detección
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ValidationStatus {
    #[default]
    Pendiente,
    Confirmada,
    FalsoPositivo,
    EnAnalisis,
}

/// Información resumida de firma Authenticode y fabricante
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthenticodeSummary {
    pub is_signed: bool,
    pub is_valid_chain: bool,
    pub publisher: Option<String>,
    pub status_detail: String,
}

/// Resultado de escaneo de un archivo
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanResult {
    pub file_path: String,
    pub sha256: String,
    pub status: FileScanStatus,
    pub detection_name: Option<String>,
    pub engine: String,
    pub scan_time_ms: u64,
    #[serde(default)]
    pub confidence_level: ConfidenceLevel,
    #[serde(default)]
    pub calibrated_score: i32,
    #[serde(default)]
    pub evidences: Vec<DetectionEvidence>,
    #[serde(default)]
    pub classification: String,
    #[serde(default)]
    pub authenticode: Option<AuthenticodeSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum FileScanStatus {
    #[default]
    Clean,
    Infected,
    Suspicious,
    AccessDenied,
}

/// Registro histórico o en tiempo real de una amenaza detectada para toma de decisiones
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    #[serde(default)]
    pub confidence_level: ConfidenceLevel,
    #[serde(default)]
    pub calibrated_score: i32,
    #[serde(default)]
    pub evidences: Vec<DetectionEvidence>,
    #[serde(default)]
    pub classification: String,
    #[serde(default)]
    pub validation_status: ValidationStatus,
    #[serde(default)]
    pub authenticode: Option<AuthenticodeSummary>,
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
    Paused,
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
            Self::Paused => write!(f, "PROTECCIÓN PAUSADA"),
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
    pub paused_until_timestamp: Option<i64>,
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
            paused_until_timestamp: None,
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

/// Fabricante de GPU detectado
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GpuVendor {
    Nvidia,
    Amd,
    Intel,
    Apple,
    Qualcomm,
    Unknown(String),
}

impl std::fmt::Display for GpuVendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nvidia => write!(f, "NVIDIA"),
            Self::Amd => write!(f, "AMD"),
            Self::Intel => write!(f, "Intel"),
            Self::Apple => write!(f, "Apple Silicon"),
            Self::Qualcomm => write!(f, "Qualcomm Adreno"),
            Self::Unknown(v) => write!(f, "{}", v),
        }
    }
}

/// Tipo de GPU física
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GpuType {
    Integrated,
    Dedicated,
    Virtual,
}

impl std::fmt::Display for GpuType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integrated => write!(f, "Integrada (iGPU)"),
            Self::Dedicated => write!(f, "Dedicada (dGPU)"),
            Self::Virtual => write!(f, "Virtualizada"),
        }
    }
}

/// Descriptor de dispositivo GPU identificado
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuDeviceDescriptor {
    pub name: String,
    pub vendor: GpuVendor,
    pub gpu_type: GpuType,
    pub vram_total_mb: u64,
    pub vram_available_mb: u64,
    pub supports_cuda: bool,
    pub supports_directml: bool,
    pub supports_opencl: bool,
    pub driver_version: Option<String>,
}

/// Topología completa de cómputo del endpoint (CPU, RAM, GPU)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareTopology {
    pub cpu_vendor: String,
    pub cpu_brand: String,
    pub physical_cores: usize,
    pub logical_threads: usize,
    pub total_ram_mb: u64,
    pub available_ram_mb: u64,
    pub gpus: Vec<GpuDeviceDescriptor>,
}

/// Backend de procesamiento computacional seleccionado o disponible
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ComputeBackend {
    CpuOnly,
    Cuda,
    DirectML,
    OpenCL,
    HybridAuto,
}

impl std::fmt::Display for ComputeBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CpuOnly => write!(f, "CPU Only (Multithreaded SIMD)"),
            Self::Cuda => write!(f, "CUDA (NVIDIA Acceleration)"),
            Self::DirectML => write!(f, "DirectML (DirectX 12 Compute)"),
            Self::OpenCL => write!(f, "OpenCL (Heterogeneous Compute)"),
            Self::HybridAuto => write!(f, "Híbrido Inteligente (SHCE Auto)"),
        }
    }
}

/// Estado de selección de backend y fallback
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendSelection {
    pub active_backend: ComputeBackend,
    pub is_gpu_active: bool,
    pub fallback_active: bool,
    pub fallback_reason: Option<String>,
    pub gpu_utilization_limit_pct: u8,
}

/// Resultado de benchmark de aceleración híbrida
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShceBenchmarkResult {
    pub cpu_throughput_mb_s: f64,
    pub gpu_throughput_mb_s: Option<f64>,
    pub speedup_ratio: f64,
    pub recommended_backend: ComputeBackend,
    pub parity_verified: bool,
    pub latency_us_per_item: f64,
    pub timestamp: String,
}

/// Tipo de carga de trabajo analizada por SHCE
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShceWorkloadType {
    /// Inspección on-access en tiempo real (siempre asignada a CPU por baja latencia sin overhead PCIe)
    RealTimeProtection,
    /// Extracción masiva de características de archivos (lotes grandes)
    BatchFeatureExtraction,
    /// Cálculo masivo de entropía e histogramas de bytes
    BatchEntropyCalculation,
    /// Inferencia de modelos de Machine Learning (DirectML / CUDA)
    MlModelInference,
    /// Verificación masiva de firmas y hashes
    BulkHashVerification,
}

/// Tipo de componente empaquetado en una actualización oficial
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PackageComponentType {
    /// Firmas criptográficas SHA-256 e índice Bloom Filter
    MalwareSignatures,
    /// Reglas heurísticas y patrones YARA-X
    YaraRules,
    /// Ponderaciones y modelos de Machine Learning (Inferencia local)
    MachineLearningModel,
    /// Parches y reglas de mitigación virtual del sistema
    VirtualPatches,
    /// Paquete consolidado completo (Full Release Bundle)
    FullBundle,
}

impl std::fmt::Display for PackageComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalwareSignatures => write!(f, "Firmas de Malware (SHA-256)"),
            Self::YaraRules => write!(f, "Reglas YARA-X"),
            Self::MachineLearningModel => write!(f, "Modelos de Machine Learning"),
            Self::VirtualPatches => write!(f, "Parches Virtuales"),
            Self::FullBundle => write!(f, "Paquete Consolidado Completo"),
        }
    }
}

/// Entrada individual de archivo dentro del manifiesto de actualización
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestFileEntry {
    /// Ruta relativa dentro del directorio de instalación
    pub relative_path: String,
    /// Hash criptográfico SHA-256 esperado
    pub sha256: String,
    /// Tamaño exacto en bytes
    pub size_bytes: u64,
}

/// Manifiesto criptográfico de actualización (Cryptographic Update Manifest)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePackageManifest {
    /// Identificador único del paquete (UUID)
    pub package_id: String,
    /// Versión numérica monótona (prevención anti-downgrade: nuevo >= actual)
    pub version_sequence: u64,
    /// Etiqueta de versión semántica (ej: "2.1.14")
    pub semantic_version: String,
    /// Versión mínima del motor requerida para instalar el paquete
    pub min_engine_version: String,
    /// Marca temporal UTC de emisión
    pub timestamp_utc: String,
    /// Tipo de componente
    pub component_type: PackageComponentType,
    /// Si es una actualización incremental o reemplazo completo
    pub is_incremental: bool,
    /// Archivos contenidos y verificables
    pub files: Vec<ManifestFileEntry>,
    /// Registro de cambios estructurado (Changelog)
    pub changelog: Vec<String>,
    /// Firma digital del manifiesto (HMAC-SHA256 / Ed25519)
    pub digital_signature: String,
    /// Clave pública o huella digital del firmante
    pub signer_fingerprint: String,
}

/// Estado de verificación del paquete de actualización
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PackageVerificationStatus {
    Valid,
    InvalidSignature,
    DowngradeDetected { current_seq: u64, incoming_seq: u64 },
    HashMismatch { file: String, expected: String, actual: String },
    PathTraversalDetected { path: String },
    SizeMismatch { file: String, expected: u64, actual: u64 },
    CorruptedManifest { reason: String },
}

/// Configuración de la Protección de Carpetas Controladas (Anti-Ransomware)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlledFolderConfig {
    pub is_enabled: bool,
    pub protected_folders: Vec<String>,
    pub trusted_processes: Vec<String>,
    pub blocked_extensions: Vec<String>,
    pub auto_rotate_canaries: bool,
    pub auto_suspend_malicious_process: bool,
}

impl Default for ControlledFolderConfig {
    fn default() -> Self {
        Self {
            is_enabled: true,
            protected_folders: Vec::new(),
            trusted_processes: vec![
                "explorer.exe".to_string(),
                "winword.exe".to_string(),
                "excel.exe".to_string(),
                "powerpnt.exe".to_string(),
                "onedrive.exe".to_string(),
                "dropbox.exe".to_string(),
                "notepad.exe".to_string(),
                "git.exe".to_string(),
                "code.exe".to_string(),
                "samulibre-watcher.exe".to_string(),
            ],
            blocked_extensions: vec![
                ".locked".to_string(),
                ".crypto".to_string(),
                ".encrypted".to_string(),
                ".lockbit".to_string(),
                ".conti".to_string(),
                ".ryuk".to_string(),
                ".blackcat".to_string(),
                ".wannacry".to_string(),
                ".crypted".to_string(),
            ],
            auto_rotate_canaries: true,
            auto_suspend_malicious_process: true,
        }
    }
}

/// Registro estructurado de un incidente de actividad de Ransomware
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareIncident {
    pub id: String,
    pub timestamp: String,
    pub attacking_pid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
    pub process_sha256: Option<String>,
    pub risk_score: u32,
    pub trigger_reason: String,
    pub affected_files_count: usize,
    pub sample_affected_files: Vec<String>,
    pub action_taken: String,
    pub canary_triggered: bool,
    pub shadow_copy_intact: bool,
    pub mitre_technique: String,
}

/// Evento de seguridad estructurado para exportación empresarial (SIEM / SOC)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsemEvent {
    pub event_id: Uuid,
    pub timestamp_utc: String,
    pub endpoint_id: String,
    pub hostname: String,
    pub samulibre_version: String,
    pub engine_status: String,
    pub severity: Severity,
    pub detection_category: String,
    pub detection_name: String,
    pub file_path: Option<String>,
    pub file_sha256: Option<String>,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub action_taken: String,
    pub outcome: String,
    pub mitre_attack_id: Option<String>,
}

/// Formato de exportación e ingesta para SSEM
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SsemExportFormat {
    /// Formato JSON estructurado (Wazuh, Splunk HEC, Microsoft Sentinel, Graylog GELF)
    Json,
    /// Syslog estándar RFC 5424 con Structured Data
    SyslogRfc5424,
    /// Formato delimitado por comas para análisis forense / auditorías
    Csv,
}

impl std::fmt::Display for SsemExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "JSON Estructurado"),
            Self::SyslogRfc5424 => write!(f, "Syslog RFC 5424"),
            Self::Csv => write!(f, "CSV Forense"),
        }
    }
}

/// Protocolo de transporte remoto para envío a SIEM
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SsemTransportProtocol {
    Tcp,
    Tls,
    Udp,
    LocalFileOnly,
}

/// Configuración empresarial del SamuLibre Security Event Manager (SSEM)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsemConfig {
    pub enabled: bool,
    pub endpoint_id: String,
    pub remote_server: Option<String>,
    pub remote_port: u16,
    pub transport: SsemTransportProtocol,
    pub format: SsemExportFormat,
    pub min_severity: Severity,
    pub offline_buffer_max_events: usize,
    pub log_rotation_max_mb: u64,
    pub anonymize_user_paths: bool,
    pub target_siem: String,
}

impl Default for SsemConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint_id: "SAMU-ENDPOINT-DEFAULT".to_string(),
            remote_server: None,
            remote_port: 514,
            transport: SsemTransportProtocol::LocalFileOnly,
            format: SsemExportFormat::Json,
            min_severity: Severity::Low,
            offline_buffer_max_events: 10_000,
            log_rotation_max_mb: 10,
            anonymize_user_paths: false,
            target_siem: "Wazuh & Splunk Compatible".to_string(),
        }
    }
}

// ─── FASE 7: SISTEMA DE REPUTACIÓN Y MITIGACIÓN DE FALSOS POSITIVOS ─────────

/// Estado de la firma digital Authenticode en ejecutables Windows (PE)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthenticodeStatus {
    /// Firma válida y cadena de certificación intacta
    Valid,
    /// Ejecutable firmado pero con firma inválida o archivo alterado
    InvalidSignature,
    /// Raíz de la autoridad certificadora no es de confianza o certificado auto-firmado
    UntrustedRoot,
    /// Certificado revocado por la entidad emisora (CRL / OCSP)
    Revoked,
    /// Certificado expirado
    Expired,
    /// El archivo no posee firma digital (sin directorio de seguridad)
    NotSigned,
}

impl std::fmt::Display for AuthenticodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "VÁLIDA (Certificado Confiable)"),
            Self::InvalidSignature => write!(f, "INVÁLIDA (Firma corrupta o archivo modificado)"),
            Self::UntrustedRoot => write!(f, "RAÍZ NO CONFIABLE (Auto-firmado)"),
            Self::Revoked => write!(f, "REVOCADO (Revocado por CA)"),
            Self::Expired => write!(f, "EXPIRADO"),
            Self::NotSigned => write!(f, "NO FIRMADO"),
        }
    }
}

/// Nivel de confianza del editor (Publisher Trust Tier)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PublisherTrustTier {
    /// Nivel 1: Fabricantes del sistema operativo y plataformas críticas (Microsoft Corporation, etc.)
    Tier1PlatformCore,
    /// Nivel 2: Proveedores de software comercial verificado (Google, Mozilla, Apple, etc.)
    Tier2VerifiedCommercial,
    /// Nivel 3: Herramientas y cadenas de compilación para desarrolladores (Rust Foundation, Python, etc.)
    Tier3DeveloperToolchain,
    /// No reconocido o no confiable
    Untrusted,
}

/// Clasificación de confianza consolidada para el ejecutable
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReputationTrustLevel {
    /// Confianza Máxima (Score 80-100): Se mitigan falsos positivos heurísticos y se concede paso ágil
    Trusted,
    /// Neutral (Score 40-79): Se aplican los umbrales estándar de escaneo multicapa
    Neutral,
    /// Sospechoso (Score 20-39): Sensibilidad heurística incrementada
    Suspicious,
    /// No confiable (Score 0-19): Escaneo exhaustivo y aislamiento en micro-sandbox
    Untrusted,
}

impl std::fmt::Display for ReputationTrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trusted => write!(f, "CONFIABLE (Whitelist / Firmado Legítimo)"),
            Self::Neutral => write!(f, "NEUTRAL (Escaneo Estándar)"),
            Self::Suspicious => write!(f, "SOSPECHOSO (Alta Sensibilidad Heurística)"),
            Self::Untrusted => write!(f, "NO CONFIABLE (Riesgo Elevado)"),
        }
    }
}

/// Evaluación integral de reputación de un binario o script
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationAssessment {
    pub target_path: String,
    pub sha256: String,
    pub reputation_score: u8,
    pub trust_level: ReputationTrustLevel,
    pub authenticode: AuthenticodeStatus,
    pub publisher: Option<String>,
    pub trust_tier: PublisherTrustTier,
    pub is_windows_os_binary: bool,
    pub is_known_dev_tool: bool,
    pub is_user_excluded: bool,
    pub prevalence_count: u32,
    pub evaluation_reasons: Vec<String>,
}

/// Regla de exclusión o reporte de falso positivo por parte del usuario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserReputationOverride {
    pub id: Uuid,
    pub sha256: Option<String>,
    pub file_path_pattern: Option<String>,
    pub publisher_name: Option<String>,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub report_status: String,
}

// ─── FASE 8: PROTECCIÓN WEB Y DE RED ────────────────────────────────────────

/// Categoría de amenaza en tráfico web, dominios y descargas
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WebThreatCategory {
    MalwareDropSite,
    CommandAndControl,
    Phishing,
    CryptoDrainer,
    DeceptiveAdware,
    DgaDomain,
    DnsExfiltration,
    SuspiciousDownloadOrigin,
    Clean,
}

impl std::fmt::Display for WebThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalwareDropSite => write!(f, "Sitio de Distribución de Malware (Drop Site)"),
            Self::CommandAndControl => write!(f, "Servidor de Comando y Control (C2 / Botnet)"),
            Self::Phishing => write!(f, "Suplantación de Identidad (Phishing Fraudulento)"),
            Self::CryptoDrainer => write!(f, "Drenador de Criptoactivos / Malvertising"),
            Self::DeceptiveAdware => write!(f, "Adware Engañoso / PUP"),
            Self::DgaDomain => write!(f, "Dominio Algorítmico DGA (T1568.002)"),
            Self::DnsExfiltration => write!(f, "Túnel / Exfiltración por DNS (T1071.004)"),
            Self::SuspiciousDownloadOrigin => write!(f, "Origen de Descarga de Alto Riesgo"),
            Self::Clean => write!(f, "Limpio / Confiable"),
        }
    }
}

/// Veredicto de inspección de URL o Dominio web en tiempo real
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebFilterVerdict {
    pub url: String,
    pub domain: String,
    pub is_blocked: bool,
    pub category: WebThreatCategory,
    pub threat_score: u8,
    pub explanation: String,
    pub latency_us: u64,
}

/// Inspección de NTFS Mark-of-the-Web (Zone.Identifier ADS)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MotwInspectionResult {
    pub file_path: String,
    pub has_motw: bool,
    pub zone_id: Option<u32>,
    pub host_url: Option<String>,
    pub referrer_url: Option<String>,
    pub is_internet_zone: bool,
    pub risk_assessment: String,
}

/// Estado y configuración del módulo de Protección Web y Red
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebShieldConfig {
    pub enabled: bool,
    pub block_phishing: bool,
    pub block_c2: bool,
    pub block_dga: bool,
    pub inspect_downloads_motw: bool,
    pub enforce_secure_dns: bool,
    pub secure_dns_provider: String,
    pub custom_blocked_domains: Vec<String>,
}

impl Default for WebShieldConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_phishing: true,
            block_c2: true,
            block_dga: true,
            inspect_downloads_motw: true,
            enforce_secure_dns: true,
            secure_dns_provider: "Quad9 (Malware Blocking DoH)".to_string(),
            custom_blocked_domains: Vec::new(),
        }
    }
}

// ─── FASE 9: PRUEBAS DE RENDIMIENTO Y OPTIMIZACIÓN (AV-TEST / AV-COMPARATIVES)

/// Métricas de consumo de recursos del sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemResourceUsage {
    pub process_id: u32,
    pub process_name: String,
    pub ram_working_set_mb: f64,
    pub ram_private_bytes_mb: f64,
    pub cpu_usage_percent: f32,
    pub threads_count: usize,
    pub handles_count: u32,
}

/// Métricas de impacto en operaciones de I/O de archivos (Copia / Descarga)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoPerformanceMetrics {
    pub files_processed_count: usize,
    pub total_bytes_mb: f64,
    pub raw_io_duration_ms: u64,
    pub monitored_io_duration_ms: u64,
    pub io_throughput_mb_per_sec: f64,
    pub cpu_overhead_percent: f32,
    pub av_test_compliance: bool,
}

/// Métricas de latencia de apertura e inicio de aplicaciones frecuentes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppLaunchPerformanceMetrics {
    pub cold_launch_latency_ms: f64,
    pub warm_launch_latency_ms: f64,
    pub clean_cache_acceleration_ratio: f64,
    pub av_comparatives_compliance: bool,
}

/// Informe consolidado de rendimiento y puntuación de impacto AV-Comparatives
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBenchmarkReport {
    pub timestamp_utc: String,
    pub hardware_summary: String,
    pub resource_usage: SystemResourceUsage,
    pub io_metrics: IoPerformanceMetrics,
    pub app_launch_metrics: AppLaunchPerformanceMetrics,
    pub web_inspection_latency_us: u64,
    pub av_comparatives_impact_score: f64,
    pub av_test_performance_score: f64,
    pub certification_readiness_status: String,
}

// ─── FASE 11: CENTRO DE PREPARACIÓN PARA CERTIFICACIÓN (AMTSO / AV-TEST / AV-COMPARATIVES)

/// Resultado de una prueba estándar AMTSO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmtsoTestResult {
    pub feature_id: String,
    pub name: String,
    pub description: String,
    pub passed: bool,
    pub latency_ms: f64,
    pub detail: String,
}

/// Informe consolidado del conjunto de pruebas estándar AMTSO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmtsoSuiteReport {
    pub timestamp_utc: String,
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub compliance_percentage: f64,
    pub results: Vec<AmtsoTestResult>,
}

/// Informe de simulación de evaluación AV-TEST (Protection, Performance, Usability)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvTestHarnessReport {
    pub timestamp_utc: String,
    pub protection_score: f64,
    pub performance_score: f64,
    pub usability_score: f64,
    pub total_score: f64,
    pub av_test_certified: bool,
    pub protection_notes: String,
    pub performance_notes: String,
    pub usability_notes: String,
}

/// Informe de simulación de evaluación AV-Comparatives (Real-World, Malware Protection, Performance)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvComparativesHarnessReport {
    pub timestamp_utc: String,
    pub real_world_block_rate_percent: f64,
    pub false_positives_count: usize,
    pub performance_impact_score: f64,
    pub award_tier: String,
    pub passes_malware_protection_test: bool,
    pub passes_performance_test: bool,
    pub passes_false_alarm_test: bool,
}

/// Auditoría consolidada de preparación para laboratorios independientes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationAuditReport {
    pub timestamp_utc: String,
    pub engine_version: String,
    pub amtso_suite: AmtsoSuiteReport,
    pub av_test: AvTestHarnessReport,
    pub av_comparatives: AvComparativesHarnessReport,
    pub overall_readiness_verdict: String,
}

// =========================================================================
// WINDOWS DEFENDER HARMONY ENGINE (WDHE) - TIPOS Y MODELOS DE COEXISTENCIA
// =========================================================================

/// Clasificación de compatibilidad e interoperabilidad para auditorías
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CompatibilityStatus {
    Compatible,
    CompatibleWithAdjustments,
    PotentialConflict,
    ConfirmedFalsePositive,
    LegitimateSecurityDetection,
    PendingInvestigation,
}

impl std::fmt::Display for CompatibilityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompatibilityStatus::Compatible => write!(f, "COMPATIBLE"),
            CompatibilityStatus::CompatibleWithAdjustments => write!(f, "COMPATIBLE CON AJUSTES"),
            CompatibilityStatus::PotentialConflict => write!(f, "POSIBLE CONFLICTO"),
            CompatibilityStatus::ConfirmedFalsePositive => write!(f, "FALSO POSITIVO CONFIRMADO"),
            CompatibilityStatus::LegitimateSecurityDetection => write!(f, "DETECCIÓN LEGÍTIMA DE SEGURIDAD"),
            CompatibilityStatus::PendingInvestigation => write!(f, "PENDIENTE DE INVESTIGACIÓN"),
        }
    }
}

/// Registro atómico de auditoría de compatibilidad de un componente
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityAuditItem {
    pub subsystem: String,
    pub component_name: String,
    pub component_type: String,
    pub status: CompatibilityStatus,
    pub potential_conflict: String,
    pub mitigation_strategy: String,
    pub tested_on_windows: bool,
}

/// Informe consolidado de auditoría de compatibilidad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityAuditSummary {
    pub timestamp_utc: String,
    pub total_components: usize,
    pub compatible_count: usize,
    pub compatible_with_adjustments_count: usize,
    pub potential_conflicts_count: usize,
    pub confirmed_false_positives_count: usize,
    pub legitimate_detections_count: usize,
    pub pending_investigation_count: usize,
    pub items: Vec<CompatibilityAuditItem>,
}

/// Modalidades de coexistencia del Windows Defender Harmony Engine
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum WdheMode {
    /// Modo Desarrollo: Defender permanece activo como protección principal.
    /// SamuLibre opera bajo demanda y en entorno controlado para registrar conflictos y medir rendimiento.
    Development,
    /// Modo Complementario: Ambos motores proporcionan protección activa en tiempo real de forma sinérgica,
    /// evitando duplicación innecesaria de análisis y respetando políticas de Windows.
    Complementary,
    /// Modo Antivirus Principal: SamuLibre registrado como proveedor antivirus oficial en Windows Security Center
    /// cuando cumple los requisitos de certificación de Microsoft, permitiendo que Windows gestione el modo pasivo de Defender.
    PrimaryAntivirus,
}

impl std::fmt::Display for WdheMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WdheMode::Development => write!(f, "DESARROLLO (Defender Principal / SamuLibre Bajo Demanda)"),
            WdheMode::Complementary => write!(f, "COMPLEMENTARIO (Coexistencia y Protección Sinérgica)"),
            WdheMode::PrimaryAntivirus => write!(f, "ANTIVIRUS PRINCIPAL (Registrado en Windows Security Center)"),
        }
    }
}

/// Perfiles dinámicos de consumo del Resource Governor (SRG)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum WdheResourceProfile {
    /// Silencioso: Mínimo consumo (<10% CPU, I/O en background/idle)
    Silent,
    /// Equilibrado: Ajuste adaptativo según carga (25-35% CPU máx)
    Balanced,
    /// Rendimiento: Aceleración multihilo y GPU (hasta 70% CPU máx)
    Performance,
    /// Análisis Profundo: Exhaustivo con control estricto de memoria
    DeepAnalysis,
}

impl std::fmt::Display for WdheResourceProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WdheResourceProfile::Silent => write!(f, "SILENCIOSO"),
            WdheResourceProfile::Balanced => write!(f, "EQUILIBRADO"),
            WdheResourceProfile::Performance => write!(f, "RENDIMIENTO"),
            WdheResourceProfile::DeepAnalysis => write!(f, "ANÁLISIS PROFUNDO"),
        }
    }
}

/// Evento de detección extraído de Windows Defender (Operational Log / WMI)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenderThreatEvent {
    pub event_id: u32,
    pub threat_id: String,
    pub threat_name: String,
    pub severity: String,
    pub category: String,
    pub file_path: String,
    pub detection_origin: String,
    pub detection_source: String,
    pub process_name: String,
    pub action_taken: String,
    pub error_code: String,
    pub timestamp_utc: String,
    pub security_intelligence_version: String,
    pub engine_version: String,
}

/// Clasificación forense de una alerta de detección
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FpClassification {
    BenignFalsePositive,
    TestArtifactPayload,
    LegitimateCompromise,
    UnsignedSuspiciousBinary,
    UnknownInvestigationRequired,
}

impl std::fmt::Display for FpClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FpClassification::BenignFalsePositive => write!(f, "FALSO POSITIVO BENIGNO"),
            FpClassification::TestArtifactPayload => write!(f, "ARTEFACTO DE PRUEBA CONTROLADA"),
            FpClassification::LegitimateCompromise => write!(f, "COMPROMISO LEGÍTIMO DE SEGURIDAD"),
            FpClassification::UnsignedSuspiciousBinary => write!(f, "BINARIO NO FIRMADO O SOSPECHOSO"),
            FpClassification::UnknownInvestigationRequired => write!(f, "PENDIENTE DE INVESTIGACIÓN PROFUNDA"),
        }
    }
}

/// Informe forense completo de investigación de falso positivo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpInvestigationRecord {
    pub threat_event: DefenderThreatEvent,
    pub file_sha256: String,
    pub file_size_bytes: u64,
    pub file_version: String,
    pub digital_signature: String,
    pub publisher: String,
    pub compile_date: String,
    pub responsible_process: String,
    pub classification: FpClassification,
    pub justification: String,
    pub is_samulibre_official_binary: bool,
    pub is_quarantined: bool,
    pub recommended_action: String,
}

/// Estado decodificado del producto en Windows Security Center (root\SecurityCenter2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WscProductState {
    pub provider_type: u8,
    pub scanner_state: u8,
    pub signature_state: u8,
    pub is_enabled: bool,
    pub is_up_to_date: bool,
    pub raw_state_hex: String,
}

/// Producto antivirus registrado en Windows Security Center
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WscAntivirusProduct {
    pub display_name: String,
    pub instance_guid: String,
    pub exe_path: String,
    pub product_state: u32,
    pub decoded_state: WscProductState,
}

/// Prioridad de análisis en la cola coordinada de Smart Scan
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SmartScanPriority {
    Background = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
}

/// Entrada verificable en la Clean Result Cache con invalidación por mtime/size/hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanCacheRecord {
    pub sha256: String,
    pub size_bytes: u64,
    pub mtime_secs: u64,
    pub scan_timestamp: String,
    pub engine_version: String,
}

/// Estado dinámico de telemetría del Resource Governor (SRG)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGovernorTelemetry {
    pub active_profile: WdheResourceProfile,
    pub cpu_usage_pct: f32,
    pub ram_usage_mb: u64,
    pub disk_read_mbs: f32,
    pub disk_write_mbs: f32,
    pub gpu_usage_pct: Option<u8>,
    pub vram_usage_mb: Option<u64>,
    pub user_activity_heavy: bool,
    pub throttling_active: bool,
}

/// Propuesta auditada y aprobada de exclusión de seguridad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeExclusionProposal {
    pub id: String,
    pub rule_type: String,
    pub target_path: String,
    pub sha256_pinned: Option<String>,
    pub justification: String,
    pub conflict_id: String,
    pub risk_assessment: String,
    pub is_approved_by_admin: bool,
    pub created_at: String,
}

/// Resultado de escenario en el Laboratorio de Benchmarks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WdheBenchmarkScenario {
    pub scenario_name: String,
    pub scenario_code: String,
    pub files_scanned: usize,
    pub duration_ms: u64,
    pub throughput_files_per_sec: f64,
    pub cpu_peak_pct: f32,
    pub ram_peak_mb: u64,
    pub disk_latency_ms: f64,
    pub conflicts_detected: usize,
    pub false_positives_detected: usize,
    pub events_lost: usize,
}

// ============================================================================
// SAMULIBRE SECURITY CENTER: ENTERPRISE EXTENSIONS
// ============================================================================

/// Metadatos enriquecidos de una regla de Virtual Patching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualPatchMetadata {
    pub rule_id: String,
    pub cve: String,
    pub affected_component: String,
    pub vulnerable_version_range: String,
    pub description: String,
    pub severity: Severity,
    pub protection_method: String,
    pub application_conditions: String,
    pub limitations: String,
    pub published_date: String,
    pub updated_date: String,
    pub rule_version: String,
    pub compatibility_verified: bool,
    pub requires_admin: bool,
    pub cisa_kev_active: bool,
    pub cvss_score: Option<f32>,
}

/// Registro de incidente en el motor de Parcheado Virtual
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualPatchIncident {
    pub timestamp: String,
    pub cve: String,
    pub rule_id: String,
    pub action: String,
    pub result: String,
    pub details: String,
}

/// Inventario detallado del sistema operativo Windows
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WindowsSystemInventory {
    pub os_name: String,
    pub display_version: String,
    pub current_build: u32,
    pub ubr: u32,
    pub full_build_string: String,
    pub architecture: String,
    pub install_type: String,
    pub is_server: bool,
    pub edition_id: String,
    pub system_language: String,
    pub last_inventory_time: String,
    pub installed_products: Vec<String>,
    pub optional_components_active: Vec<String>,
}

/// Registro de una actualización (KB) instalada en el sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledKbRecord {
    pub kb_id: String,
    pub title: String,
    pub install_date: String,
    pub product: String,
    pub classification: String,
    pub version: String,
    pub state: String,
    pub detection_source: String,
    pub related_cves: Vec<String>,
    pub related_kbs: Vec<String>,
}

/// Estado de aplicabilidad y ciclo de vida de una actualización pendiente
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PendingKbStatus {
    Published,
    Applicable,
    PendingDownload,
    Downloaded,
    PendingInstall,
    PendingReboot,
    Failed,
    Superseded,
    NotApplicable,
}

/// Registro de una actualización (KB) pendiente o aplicable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingKbRecord {
    pub kb_id: String,
    pub update_id: String,
    pub title: String,
    pub description: String,
    pub release_date: String,
    pub product_affected: String,
    pub architecture: String,
    pub update_type: String,
    pub severity: Severity,
    pub status: PendingKbStatus,
    pub download_size_bytes: u64,
    pub requires_reboot: bool,
    pub supersedes_kbs: Vec<String>,
    pub superseded_by_kb: Option<String>,
    pub prerequisites: Vec<String>,
    pub fixed_cves: Vec<String>,
    pub cisa_kev_active: bool,
    pub cvss_max_score: f32,
    pub failure_reason: Option<String>,
}

/// Registro de inteligencia y correlación CVE <-> KB <-> Virtual Patching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveKbCorrelation {
    pub cve: String,
    pub title: String,
    pub affected_product: String,
    pub vulnerable_component: String,
    pub vulnerable_version_range: String,
    pub cvss_score: f32,
    pub severity: Severity,
    pub cisa_kev: bool,
    pub public_exploit_available: bool,
    pub corrective_kb: String,
    pub kb_installation_status: String,
    pub virtual_patch_rule_id: Option<String>,
    pub virtual_patch_status: PatchStatus,
    pub recommended_action: String,
    pub days_since_disclosure: u32,
}

/// Prioridad de alerta inteligente de seguridad
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertPriority {
    Critical,
    High,
    Warning,
    Info,
}

/// Alerta inteligente de seguridad
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: String,
    pub timestamp: String,
    pub priority: AlertPriority,
    pub category: String,
    pub title: String,
    pub description: String,
    pub recommended_action: String,
    pub related_cve: Option<String>,
    pub related_kb: Option<String>,
    pub is_resolved: bool,
}

/// Resumen global del servicio de inteligencia de parches de Windows
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WindowsPatchIntelligenceSummary {
    pub service_active: bool,
    pub last_sync_time: Option<String>,
    pub sync_source: String,
    pub is_offline_cache: bool,
    pub inventory: WindowsSystemInventory,
    pub installed_kbs_count: usize,
    pub pending_kbs_count: usize,
    pub critical_kbs_count: usize,
    pub cisa_kev_count: usize,
    pub pending_reboot_detected: bool,
    pub pending_reboot_reasons: Vec<String>,
    pub installed_kbs: Vec<InstalledKbRecord>,
    pub pending_kbs: Vec<PendingKbRecord>,
    pub correlations: Vec<CveKbCorrelation>,
    pub active_alerts: Vec<SecurityAlert>,
}

/// Entrada en el historial de conexiones VPN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnHistoryEntry {
    pub timestamp: String,
    pub country_id: String,
    pub country_name: String,
    pub public_ip: String,
    pub protocol: String,
    pub duration_seconds: u64,
    pub bytes_sent_mb: f64,
    pub bytes_received_mb: f64,
    pub kill_switch_triggered: bool,
    pub status: String,
}

/// Resultado de diagnóstico completo de la VPN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnDiagnosticResult {
    pub timestamp: String,
    pub is_connected: bool,
    pub public_ip: String,
    pub tunnel_interface_ip: String,
    pub ping_latency_ms: u32,
    pub dns_leak_detected: bool,
    pub dns_servers_responding: Vec<String>,
    pub ipv6_leak_detected: bool,
    pub kill_switch_active: bool,
    pub tunnel_integrity_verified: bool,
    pub proxy_clean: bool,
    pub diagnostic_verdict: String,
    pub recommendations: Vec<String>,
}

// =========================================================================
// MÓDULO AVANZADO: DARK WEB & TOR PROTECTION TYPES
// =========================================================================

/// Perfiles de protección para Dark Web y Tor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TorProtectionProfile {
    /// Protección antivirus estándar de SamuLibre
    Normal,
    /// Protección reforzada durante la navegación en Tor (por defecto al navegar con Tor)
    #[default]
    TorProtection,
    /// Aislamiento máximo con bloqueo preventivo de binarios y contención reforzada
    MaximumIsolation,
}

impl std::fmt::Display for TorProtectionProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TorProtectionProfile::Normal => write!(f, "PROTECCIÓN NORMAL"),
            TorProtectionProfile::TorProtection => write!(f, "TOR PROTECTION"),
            TorProtectionProfile::MaximumIsolation => write!(f, "MAXIMUM ISOLATION"),
        }
    }
}

/// Estado en vivo del proceso de Tor Browser y Tor daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorProcessState {
    pub is_running: bool,
    pub tor_browser_pid: Option<u32>,
    pub tor_daemon_pid: Option<u32>,
    pub binary_path: Option<String>,
    pub binary_hash_sha256: Option<String>,
    pub binary_integrity_verified: bool,
    pub version: Option<String>,
    pub socks_port: u16,
    pub control_port: u16,
    pub circuits_established: usize,
    pub status_text: String,
}

impl Default for TorProcessState {
    fn default() -> Self {
        Self {
            is_running: false,
            tor_browser_pid: None,
            tor_daemon_pid: None,
            binary_path: None,
            binary_hash_sha256: None,
            binary_integrity_verified: true,
            version: None,
            socks_port: 9150,
            control_port: 9151,
            circuits_established: 0,
            status_text: "Tor Browser no detectado en ejecución".to_string(),
        }
    }
}

/// Información de un proceso sospechoso detectado cerca de Tor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorSuspiciousProcess {
    pub pid: u32,
    pub name: String,
    pub command_line: String,
    pub parent_pid: Option<u32>,
    pub violation_reason: String,
    pub severity: Severity,
    pub is_isolated: bool,
    pub detected_at: DateTime<Utc>,
}

/// Alerta de fuga de privacidad o uso no autorizado de la red Tor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorPrivacyLeakAlert {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub alert_type: String, // "DnsLeak", "ProxyBypass", "UnauthorizedTorUse", "SuspiciousSocket", "ClipboardHijack"
    pub process_name: String,
    pub pid: u32,
    pub destination: String,
    pub severity: Severity,
    pub details: String,
    pub action_taken: String,
}

/// Veredicto de descarga originada en sesión Tor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TorDownloadVerdict {
    #[default]
    Analyzing,
    Authorized,
    Suspicious,
    Quarantined,
    Blocked,
}

/// Análisis especializado para documentos potencialmente armados (PDF, Office)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TorDocumentRiskAnalysis {
    pub is_document: bool,
    pub doc_type: String, // "PDF", "Word", "Excel", "Script", "None"
    pub has_active_script: bool,
    pub has_embedded_macros: bool,
    pub has_launch_actions: bool,
    pub has_embedded_executables: bool,
    pub has_obfuscated_streams: bool,
    pub risk_score: u8, // 0 - 100
    pub risk_indicators: Vec<String>,
}

/// Informe detallado de una descarga bajo custodia de Tor Shield
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorDownloadReport {
    pub id: Uuid,
    pub file_name: String,
    pub source_origin: String,
    pub target_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub quarantine_path: Option<String>,
    pub signature_threat: Option<String>,
    pub heuristic_score: f64,
    pub document_analysis: TorDocumentRiskAnalysis,
    pub sandbox_verdict: String,
    pub reputation_verdict: String,
    pub final_verdict: TorDownloadVerdict,
    pub reasoning: String,
    pub analyzed_at: DateTime<Utc>,
}

/// Indicador de Compromiso (IoC) de la Dark Web (Threat Intelligence)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DarkWebIoC {
    pub indicator: String, // Dominio, host .onion, hash o URL maliciosa
    pub ioc_type: String,  // "RansomwarePortal", "MalwareDropSite", "C2Server", "PhishingGateway"
    pub campaign: String,  // "LockBit 3.0", "BlackCat", "RedLine Stealer", "PhishGate", etc.
    pub source: String,    // "ThreatFox", "URLhaus", "MalwareBazaar", "CISA-KEV"
    pub severity: Severity,
    pub description: String,
    pub added_at: String,
}

/// Asesoría de vulnerabilidad para Tor Browser / Firefox ESR
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorVulnerabilityAdvisory {
    pub cve_id: String,
    pub affected_component: String,
    pub severity: Severity,
    pub cvss_score: f32,
    pub title: String,
    pub is_actively_exploited: bool,
    pub fixed_in_version: String,
    pub current_installed_version: Option<String>,
    pub is_vulnerable: bool,
    pub mitigation_notes: String,
}

/// Registro histórico de sesión protegida en Tor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorSessionLog {
    pub session_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub profile: TorProtectionProfile,
    pub downloads_analyzed: usize,
    pub exploits_blocked: usize,
    pub threats_quarantined: usize,
    pub privacy_leaks_prevented: usize,
    pub status: String,
}

/// Snapshot integral de estado para el panel DARK WEB & TOR PROTECTION
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorShieldDashboardSnapshot {
    pub active_profile: TorProtectionProfile,
    pub process_state: TorProcessState,
    pub web_shield_active: bool,
    pub exploit_shield_active: bool,
    pub sandbox_isolation_active: bool,
    pub ransomware_tripwire_active: bool,
    pub stealer_protection_active: bool,
    pub kill_switch_armed: bool,
    pub downloads_scanned_count: usize,
    pub threats_blocked_count: usize,
    pub privacy_leaks_count: usize,
    pub recent_alerts: Vec<ThreatAlert>,
    pub suspicious_processes: Vec<TorSuspiciousProcess>,
    pub privacy_alerts: Vec<TorPrivacyLeakAlert>,
    pub vulnerabilities: Vec<TorVulnerabilityAdvisory>,
    pub recent_downloads: Vec<TorDownloadReport>,
    pub session_history: Vec<TorSessionLog>,
    pub threat_feed_count: usize,
    pub threat_feed_last_update: String,
}










