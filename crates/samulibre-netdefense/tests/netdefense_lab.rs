use chrono::{Duration, Utc};
use samulibre_netdefense::{
    build_nxdomain_response, is_private_or_rebinding_ip, parse_dns_question, parse_torrc,
    AppTrustState, DnsConfig, FirewallRule, NetProtocol, NetworkConnectionEntry,
    NetworkDefenseEngine, ProgramLearningEngine, RiskRecommendation, RiskRecommender, RuleAction,
    RuleScope, SecureDnsProxy, ThreatIntelManager, TorSecureModeConfig, TrafficDirection,
    AUTO_BLOCK_CONFIDENCE_THRESHOLD,
};
use std::fs;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = vec![
        0x12, 0x34, // TxID
        0x01, 0x00, // Standard query, RD=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
    pkt
}

#[test]
fn test_socket_monitor_and_benchmark() {
    let temp = std::env::temp_dir().join(format!("sl_nd_test_{}", Uuid::new_v4()));
    let mut engine = NetworkDefenseEngine::new(&temp);
    let t0 = std::time::Instant::now();
    let conns = engine.refresh_live_connections();
    let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
    println!("Conexiones enumeradas: {} en {:.2} ms", conns.len(), elapsed_ms);
    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn test_app_policy_sha256_tamper_reevaluation() {
    let temp = std::env::temp_dir().join(format!("sl_nd_tamper_{}", Uuid::new_v4()));
    let _ = fs::create_dir_all(&temp);
    let fake_exe = temp.join("sample_app.exe");
    fs::write(&fake_exe, b"ORIGINAL_BINARY_V1").unwrap();

    let mut engine = NetworkDefenseEngine::new(&temp);
    let exe_str = fake_exe.to_string_lossy().to_string();
    let pol = engine
        .set_app_policy("sample_app.exe", &exe_str, AppTrustState::Trusted, "Test")
        .unwrap();
    assert!(!pol.expected_sha256.is_empty());
    assert_eq!(
        engine.verify_app_policy_integrity(&exe_str),
        Some(AppTrustState::Trusted)
    );

    // Modificar binario en disco: debe invalidar la confianza automáticamente
    fs::write(&fake_exe, b"TAMPERED_BINARY_V2").unwrap();
    // Invalidar caché forzando re-lectura o usando nueva instancia persistida
    let mut engine2 = NetworkDefenseEngine::new(&temp);
    let state = engine2.verify_app_policy_integrity(&exe_str);
    assert_eq!(state, Some(AppTrustState::ModifiedNeedsReeval));

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn test_dns_wire_parser_block_and_corporate_bypass() {
    let temp = std::env::temp_dir().join(format!("sl_nd_dns_{}", Uuid::new_v4()));
    let intel = Arc::new(Mutex::new(ThreatIntelManager::new(&temp)));
    let proxy = SecureDnsProxy::new(DnsConfig::default(), intel);

    let q_mal = build_dns_query("evil-c2-server.com", 1);
    let parsed = parse_dns_question(&q_mal).unwrap();
    assert_eq!(parsed.qname, "evil-c2-server.com");
    assert_eq!(parsed.qtype, 1);

    let resp = proxy.resolve_query_wire(&q_mal);
    assert!(!resp.is_empty());
    assert_eq!(resp[3] & 0x0F, 3); // NXDOMAIN

    let nx = build_nxdomain_response(&q_mal);
    assert_eq!(nx[3] & 0x0F, 3);

    // Verificar detección de DNS Rebinding
    assert!(is_private_or_rebinding_ip(&"127.0.0.1".parse().unwrap()));
    assert!(is_private_or_rebinding_ip(&"192.168.1.10".parse().unwrap()));
    assert!(!is_private_or_rebinding_ip(&"93.184.216.34".parse().unwrap()));

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn test_threat_intel_stix_hostfile_and_rollback() {
    let temp = std::env::temp_dir().join(format!("sl_nd_intel_{}", Uuid::new_v4()));
    let mut mgr = ThreatIntelManager::new(&temp);
    mgr.save().unwrap();

    let count = mgr.ingest_hostfile("urlhaus-domains", "127.0.0.1 bad-malware-host.top\n# comment\n");
    assert_eq!(count, 1);
    assert!(mgr.check_domain("bad-malware-host.top", true, true, true).is_some());

    let stix = r#"{
        "type": "bundle",
        "objects": [
            {"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.77']", "confidence": 90}
        ]
    }"#;
    let stix_count = mgr.ingest_stix_bundle("stix-test", stix).unwrap();
    assert_eq!(stix_count, 1);
    assert!(mgr.check_ip("198.51.100.77", AUTO_BLOCK_CONFIDENCE_THRESHOLD).is_some());

    mgr.rollback().unwrap();
    assert!(mgr.check_ip("198.51.100.77", AUTO_BLOCK_CONFIDENCE_THRESHOLD).is_none());

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn test_tor_secure_mode_kill_switch_and_torrc() {
    let temp = std::env::temp_dir().join(format!("sl_nd_tor_{}", Uuid::new_v4()));
    let mut engine = NetworkDefenseEngine::new(&temp);

    let (sp, cp, br) = parse_torrc("SocksPort 9150\nControlPort 9151\nUseBridges 1\n");
    assert_eq!(sp, Some(9150));
    assert_eq!(cp, Some(9151));
    assert!(br);

    let mut cfg = TorSecureModeConfig::default();
    cfg.enabled = true;
    cfg.socks_port = 59999; // Puerto sin daemon escuchando
    cfg.kill_switch_fail_closed = true;
    let state = engine.set_tor_secure_mode(cfg);
    assert!(state.enabled);
    assert!(state.kill_switch_active);
    assert!(!state.socks_reachable);

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn test_av_correlation_and_rule_expiration() {
    let temp = std::env::temp_dir().join(format!("sl_nd_av_{}", Uuid::new_v4()));
    let _ = fs::create_dir_all(&temp);
    let sample = temp.join("malware.exe");
    fs::write(&sample, b"MZ_TEST").unwrap();

    let mut engine = NetworkDefenseEngine::new(&temp);
    let ev = engine.handle_av_threat_correlation(
        Some(4242),
        "malware.exe",
        Some(&sample.to_string_lossy()),
        "Trojan.Generic.C2",
        "203.0.113.50",
    );
    assert_eq!(ev.process_name, "malware.exe");
    assert!(sample.exists()); // El firewall NO elimina el archivo; lo delega al AV
    assert_eq!(engine.rules.len(), 1);

    // Regla temporal expirada debe podarse
    let expired_rule = FirewallRule {
        id: Uuid::new_v4(),
        name: "TempExpired".to_string(),
        app_path: None,
        app_hash_sha256: None,
        remote_ip: Some("203.0.113.99".to_string()),
        remote_port: Some(8080),
        local_port: None,
        protocol: NetProtocol::Tcp,
        direction: TrafficDirection::Outbound,
        action: RuleAction::Block,
        scope: RuleScope::Temporary,
        expires_at: Some(Utc::now() - Duration::minutes(5)),
        interface_alias: None,
        ipv4: true,
        ipv6: false,
        enabled: true,
        created_at: Utc::now() - Duration::minutes(10),
        hit_count: 0,
        wfp_filter_ids: Vec::new(),
        reason: "Test".to_string(),
    };
    engine.add_rule(expired_rule).unwrap();
    let pruned = engine.prune_expired_rules();
    assert_eq!(pruned, 1);

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn test_program_learning_and_protected_system_guard() {
    let temp = std::env::temp_dir().join(format!("samulibre_nd_learn_{}", Uuid::new_v4()));
    let _ = fs::create_dir_all(&temp);

    let mut engine = NetworkDefenseEngine::new(temp.clone());

    // 1. Intentar bloquear svchost.exe en System32 debe ser rechazado por ProtectedSystemGuard
    let block_svchost = FirewallRule {
        id: Uuid::new_v4(),
        name: "Block_svchost".to_string(),
        app_path: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
        app_hash_sha256: None,
        remote_ip: Some("8.8.8.8".to_string()),
        remote_port: Some(443),
        local_port: None,
        protocol: NetProtocol::Tcp,
        direction: TrafficDirection::Outbound,
        action: RuleAction::Block,
        scope: RuleScope::Permanent,
        expires_at: None,
        interface_alias: None,
        ipv4: true,
        ipv6: true,
        enabled: true,
        created_at: Utc::now(),
        hit_count: 0,
        wfp_filter_ids: Vec::new(),
        reason: "Test accidental block".to_string(),
    };
    assert!(
        engine.add_rule(block_svchost).is_err(),
        "No debe permitirse bloquear svchost.exe en System32"
    );

    // 2. Intentar bloquear loopback 127.0.0.1 debe ser rechazado
    let block_loopback = FirewallRule {
        id: Uuid::new_v4(),
        name: "Block_loopback".to_string(),
        app_path: Some("C:\\Program Files\\ASUS\\asus_framework.exe".to_string()),
        app_hash_sha256: None,
        remote_ip: Some("127.0.0.1".to_string()),
        remote_port: Some(49714),
        local_port: None,
        protocol: NetProtocol::Tcp,
        direction: TrafficDirection::Outbound,
        action: RuleAction::Block,
        scope: RuleScope::Permanent,
        expires_at: None,
        interface_alias: None,
        ipv4: true,
        ipv6: true,
        enabled: true,
        created_at: Utc::now(),
        hit_count: 0,
        wfp_filter_ids: Vec::new(),
        reason: "Test loopback block".to_string(),
    };
    assert!(
        engine.add_rule(block_loopback).is_err(),
        "No debe permitirse bloquear tráfico loopback 127.0.0.1"
    );

    // 3. El motor de aprendizaje debe aprender aplicaciones esenciales y persistirlas
    let loopback_conn = NetworkConnectionEntry {
        id: "c1".to_string(),
        pid: 23668,
        app_name: "asus_framework.exe".to_string(),
        app_path: Some("C:\\Program Files (x86)\\ASUS\\ArmouryDevice\\asus_framework.exe".to_string()),
        protocol: "TCP".to_string(),
        ip_version: 4,
        local_addr: "127.0.0.1".to_string(),
        local_port: 51000,
        remote_addr: "127.0.0.1".to_string(),
        remote_port: 49714,
        domain: None,
        country_code: None,
        state: "ESTABLISHED".to_string(),
        action_taken: "Monitoreada".to_string(),
        timestamp: Utc::now(),
        bytes_sent: None,
        bytes_recv: None,
        is_risky: false,
        risk_reason: None,
        recommendation: RiskRecommendation::Review,
        risk_score: 0,
        primary_reason: String::new(),
        risk_factors: Vec::new(),
        suggested_action: String::new(),
    };
    engine.learning_engine.observe_connection(&loopback_conn, "dummy_sha256_asus");
    engine.learning_engine.save_database().unwrap();
    assert!(temp.join("netdefense").join("learned_apps.json").exists());

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn test_risk_recommender_detects_dangerous_and_safe_connections() {
    let temp = std::env::temp_dir().join(format!("samulibre_nd_risk_{}", Uuid::new_v4()));
    let _ = fs::create_dir_all(&temp);

    let learning = ProgramLearningEngine::new(temp.join("netdefense"));
    let policies = std::collections::HashMap::new();
    let av_events = std::collections::VecDeque::new();

    // 1. PowerShell desde Temp hacia IP pública en puerto C2 4444 -> RecommendedBlock
    let dangerous_conn = NetworkConnectionEntry {
        id: "danger1".to_string(),
        pid: 9999,
        app_name: "powershell.exe".to_string(),
        app_path: Some("C:\\Users\\user\\AppData\\Local\\Temp\\powershell.exe".to_string()),
        protocol: "TCP".to_string(),
        ip_version: 4,
        local_addr: "192.168.1.50".to_string(),
        local_port: 55123,
        remote_addr: "185.220.101.1".to_string(),
        remote_port: 4444,
        domain: None,
        country_code: None,
        state: "ESTABLISHED".to_string(),
        action_taken: "Monitoreada".to_string(),
        timestamp: Utc::now(),
        bytes_sent: None,
        bytes_recv: None,
        is_risky: false,
        risk_reason: None,
        recommendation: RiskRecommendation::Review,
        risk_score: 0,
        primary_reason: String::new(),
        risk_factors: Vec::new(),
        suggested_action: String::new(),
    };
    let eval_danger = RiskRecommender::evaluate(&dangerous_conn, None, &policies, &av_events, &learning);
    assert_eq!(eval_danger.recommendation, RiskRecommendation::RecommendedBlock);
    assert!(eval_danger.total_risk_score >= 70);

    // 2. Loopback local 127.0.0.1 -> SafeLearned
    let safe_conn = NetworkConnectionEntry {
        id: "safe1".to_string(),
        pid: 24404,
        app_name: "Antigravity.exe".to_string(),
        app_path: Some("C:\\Program Files\\Antigravity\\Antigravity.exe".to_string()),
        protocol: "TCP".to_string(),
        ip_version: 4,
        local_addr: "127.0.0.1".to_string(),
        local_port: 50001,
        remote_addr: "127.0.0.1".to_string(),
        remote_port: 4718,
        domain: None,
        country_code: None,
        state: "ESTABLISHED".to_string(),
        action_taken: "Monitoreada".to_string(),
        timestamp: Utc::now(),
        bytes_sent: None,
        bytes_recv: None,
        is_risky: false,
        risk_reason: None,
        recommendation: RiskRecommendation::Review,
        risk_score: 0,
        primary_reason: String::new(),
        risk_factors: Vec::new(),
        suggested_action: String::new(),
    };
    let eval_safe = RiskRecommender::evaluate(&safe_conn, None, &policies, &av_events, &learning);
    assert_eq!(eval_safe.recommendation, RiskRecommendation::SafeLearned);

    let _ = fs::remove_dir_all(&temp);
}
