use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrafficDirection {
    Outbound,
    Inbound,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Block,
    TorOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleScope {
    Permanent,
    Temporary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: Uuid,
    pub name: String,
    pub app_path: Option<String>,
    pub app_hash_sha256: Option<String>,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub local_port: Option<u16>,
    pub protocol: NetProtocol,
    pub direction: TrafficDirection,
    pub action: RuleAction,
    pub scope: RuleScope,
    pub expires_at: Option<DateTime<Utc>>,
    pub interface_alias: Option<String>,
    pub ipv4: bool,
    pub ipv6: bool,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub hit_count: u64,
    pub wfp_filter_ids: Vec<u64>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppTrustState {
    Trusted,
    Restricted,
    Ask,
    Blocked,
    TorOnly,
    ModifiedNeedsReeval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPolicy {
    pub id: Uuid,
    pub app_name: String,
    pub executable_path: String,
    pub expected_sha256: String,
    pub last_verified_sha256: String,
    pub trust_state: AppTrustState,
    pub allow_internet: bool,
    pub allow_lan: bool,
    pub allow_dns: bool,
    pub tor_only: bool,
    pub allowed_ports: Vec<u16>,
    pub blocked_ports: Vec<u16>,
    pub updated_at: DateTime<Utc>,
    pub notes: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskRecommendation {
    RecommendedBlock,
    Review,
    SafeLearned,
}

impl Default for RiskRecommendation {
    fn default() -> Self {
        Self::SafeLearned
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskFactorCategory {
    LolbinOutbound,
    VolatileDirectoryExecution,
    UnsignedOrUntrustedBinary,
    KnownC2Port,
    ThreatIntelHit,
    AvCorrelationIncident,
    AnomalousExternalPort,
    SensitiveExposedService,
    BinaryTamperedMismatch,
    PolicyRestrictedApp,
    BenignContextDampener,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub category: RiskFactorCategory,
    pub severity: String,
    pub score_impact: i16,
    pub title: String,
    pub description: String,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRiskEvaluation {
    pub recommendation: RiskRecommendation,
    pub total_risk_score: u8,
    pub primary_reason: String,
    pub factors: Vec<RiskFactor>,
    pub suggested_action: String,
    pub should_isolate_pid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionEntry {
    pub id: String,
    pub pid: u32,
    pub app_name: String,
    pub app_path: Option<String>,
    pub protocol: String,
    pub ip_version: u8,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub domain: Option<String>,
    pub country_code: Option<String>,
    pub state: String,
    pub action_taken: String,
    pub timestamp: DateTime<Utc>,
    pub bytes_sent: Option<u64>,
    pub bytes_recv: Option<u64>,
    pub is_risky: bool,
    pub risk_reason: Option<String>,
    pub recommendation: RiskRecommendation,
    pub risk_score: u8,
    pub primary_reason: String,
    pub risk_factors: Vec<RiskFactor>,
    pub suggested_action: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsTransport {
    DoH,
    DoT,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsProviderPreset {
    Cloudflare,
    Quad9,
    Mullvad,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub transport: DnsTransport,
    pub provider: DnsProviderPreset,
    pub doh_url: String,
    pub dot_host: String,
    pub dot_port: u16,
    pub listen_addr: String,
    pub block_malware: bool,
    pub block_phishing: bool,
    pub block_trackers: bool,
    pub rebinding_protection: bool,
    pub prevent_dns_leak: bool,
    pub corporate_bypass_suffixes: Vec<String>,
    pub custom_blocked_domains: Vec<String>,
    pub custom_allowed_domains: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            transport: DnsTransport::DoH,
            provider: DnsProviderPreset::Quad9,
            doh_url: "https://dns.quad9.net/dns-query".to_string(),
            dot_host: "dns.quad9.net".to_string(),
            dot_port: 853,
            listen_addr: "127.0.0.1:53".to_string(),
            block_malware: true,
            block_phishing: true,
            block_trackers: true,
            rebinding_protection: true,
            prevent_dns_leak: true,
            corporate_bypass_suffixes: vec![
                ".local".to_string(),
                ".lan".to_string(),
                ".internal".to_string(),
                ".corp".to_string(),
                ".home.arpa".to_string(),
            ],
            custom_blocked_domains: Vec::new(),
            custom_allowed_domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryLog {
    pub timestamp: DateTime<Utc>,
    pub domain: String,
    pub qtype: String,
    pub action: String,
    pub reason: String,
    pub upstream: String,
    pub latency_ms: u64,
    pub resolved_ips: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsStats {
    pub running: bool,
    pub listen_addr: String,
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub rebinding_blocked: u64,
    pub cache_hits: u64,
    pub upstream_errors: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TorProtectionHealth {
    Protected,
    TorDownKillSwitchActive,
    Degraded,
    Inactive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorSecureModeConfig {
    pub enabled: bool,
    pub kill_switch_fail_closed: bool,
    pub block_ipv6_for_protected_apps: bool,
    pub restrict_udp_for_protected_apps: bool,
    pub block_external_dns: bool,
    pub socks_port: u16,
    pub control_port: u16,
    pub protected_app_paths: Vec<String>,
    pub allow_pluggable_transports: bool,
}

impl Default for TorSecureModeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kill_switch_fail_closed: true,
            block_ipv6_for_protected_apps: true,
            restrict_udp_for_protected_apps: true,
            block_external_dns: true,
            socks_port: 9150,
            control_port: 9151,
            protected_app_paths: Vec::new(),
            allow_pluggable_transports: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorSecureModeState {
    pub health: TorProtectionHealth,
    pub enabled: bool,
    pub tor_browser_detected: bool,
    pub tor_browser_pids: Vec<u32>,
    pub tor_browser_paths: Vec<String>,
    pub tor_daemon_detected: bool,
    pub tor_daemon_pid: Option<u32>,
    pub socks_port: u16,
    pub socks_reachable: bool,
    pub bridges_configured: bool,
    pub pluggable_transports: Vec<String>,
    pub kill_switch_active: bool,
    pub wfp_filters_applied: usize,
    pub direct_leak_attempts_blocked: u64,
    pub status_message: String,
    pub limitations_notice: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IndicatorType {
    Domain,
    IpAddress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatIntelCategory {
    Malware,
    Phishing,
    CommandAndControl,
    Tracker,
    Botnet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub value: String,
    pub indicator_type: IndicatorType,
    pub category: ThreatIntelCategory,
    pub source_name: String,
    pub confidence: u8,
    pub first_seen: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedMetadata {
    pub id: String,
    pub name: String,
    pub url: String,
    pub license: String,
    pub format: String,
    pub enabled: bool,
    pub last_updated: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub sha256_integrity: Option<String>,
    pub indicator_count: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCorrelationEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub pid: Option<u32>,
    pub process_name: String,
    pub executable_path: Option<String>,
    pub remote_target: String,
    pub av_alert_title: String,
    pub intel_match: Option<String>,
    pub action_taken: String,
    pub severity: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WfpEngineStatus {
    pub available: bool,
    pub initialized: bool,
    pub elevated: bool,
    pub provider_registered: bool,
    pub sublayer_registered: bool,
    pub active_filter_count: usize,
    pub net_events_subscribed: bool,
    pub last_error: Option<String>,
    pub mode_description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthColor {
    Green,
    Yellow,
    Red,
    Gray,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetDefenseEventLog {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub subsystem: String,
    pub severity: String,
    pub event_type: String,
    pub summary: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetDefenseDashboardSnapshot {
    pub firewall_enabled: bool,
    pub firewall_color: HealthColor,
    pub wfp_status: WfpEngineStatus,
    pub wfp_color: HealthColor,
    pub active_connections_count: usize,
    pub blocked_connections_count: u64,
    pub connected_apps_count: usize,
    pub blocked_domains_count: u64,
    pub threats_detected_count: usize,
    pub dns_stats: DnsStats,
    pub dns_color: HealthColor,
    pub tor_state: TorSecureModeState,
    pub tor_color: HealthColor,
    pub rules_count: usize,
    pub app_policies_count: usize,
    pub feeds_count: usize,
    pub total_indicators_count: usize,
}
