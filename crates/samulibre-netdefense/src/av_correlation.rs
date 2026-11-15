use crate::types::{
    AppPolicy, AppTrustState, FirewallRule, NetProtocol, RuleAction, RuleScope,
    ThreatCorrelationEvent, TrafficDirection,
};
use chrono::Utc;
use uuid::Uuid;

/// Correlaciona detecciones del Antivirus / EDR de SamuLibre con conexiones de red activas y políticas WFP.
/// Nunca elimina ni pone en cuarentena archivos por su cuenta: delega esa acción al motor antivirus.
pub fn correlate_av_detection_with_network(
    pid: Option<u32>,
    process_name: &str,
    exe_path: Option<&str>,
    av_alert_title: &str,
    remote_target: &str,
    intel_match: Option<&str>,
) -> (ThreatCorrelationEvent, Option<FirewallRule>, Option<AppPolicy>) {
    let now = Utc::now();

    let rule = exe_path.map(|path| FirewallRule {
        id: Uuid::new_v4(),
        name: format!("AV_Containment_{}", process_name),
        app_path: Some(path.to_string()),
        app_hash_sha256: None,
        remote_ip: None,
        remote_port: None,
        local_port: None,
        protocol: NetProtocol::Any,
        direction: TrafficDirection::Both,
        action: RuleAction::Block,
        scope: RuleScope::Permanent,
        expires_at: None,
        interface_alias: None,
        ipv4: true,
        ipv6: true,
        enabled: true,
        created_at: now,
        hit_count: 1,
        wfp_filter_ids: Vec::new(),
        reason: format!("Bloqueo automático por correlación Antivirus: {}", av_alert_title),
    });

    let policy = exe_path.map(|path| AppPolicy {
        id: Uuid::new_v4(),
        app_name: process_name.to_string(),
        executable_path: path.to_string(),
        expected_sha256: String::new(),
        last_verified_sha256: String::new(),
        trust_state: AppTrustState::Blocked,
        allow_internet: false,
        allow_lan: false,
        allow_dns: false,
        tor_only: false,
        allowed_ports: Vec::new(),
        blocked_ports: Vec::new(),
        updated_at: now,
        notes: format!("Bloqueada por correlación AV ({})", av_alert_title),
    });

    let event = ThreatCorrelationEvent {
        id: Uuid::new_v4(),
        timestamp: now,
        pid,
        process_name: process_name.to_string(),
        executable_path: exe_path.map(|s| s.to_string()),
        remote_target: remote_target.to_string(),
        av_alert_title: av_alert_title.to_string(),
        intel_match: intel_match.map(|s| s.to_string()),
        action_taken: if rule.is_some() {
            "Conexiones bloqueadas en WFP y proceso marcado para análisis forense/cuarentena AV".to_string()
        } else {
            "Evento correlacionado y registrado (sin ruta de ejecutable para regla AppID)".to_string()
        },
        severity: "Crítica".to_string(),
    };

    (event, rule, policy)
}
