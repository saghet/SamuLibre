use samulibre_intel::db::UpsertOutcome;
use samulibre_intel::{
    CompiledYaraRuntime, IndicatorType, IntelDatabase, ThreatIndicatorRecord, ValidationStatus,
    YaraRuleValidator,
};

#[test]
fn test_yara_validator_approves_valid_and_rejects_invalid_or_general() {
    let valid_yar = r#"
rule Eicar_Test_Real {
    meta:
        author = "SamuLibre Lab"
        description = "Detects EICAR test string"
        license = "GPL-3.0"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar
}

rule Broken_Syntax_Rule {
    meta:
        author = "Tester"
    strings:
        $a = "something"
    condition:
        $nonexistent_var
}

rule Overly_General_Rule {
    meta:
        author = "BadAuthor"
    strings:
        $a = "unused"
    condition:
        true
}
"#;

    let rules = YaraRuleValidator::split_yara_file(valid_yar, "GPL-3.0");
    assert_eq!(rules.len(), 3, "Debe extraer las 3 reglas individuales");

    let r0 = YaraRuleValidator::validate_rule(&rules[0], false);
    assert_eq!(r0.status, ValidationStatus::Aprobada);
    assert!(r0.score >= 85);

    let r1 = YaraRuleValidator::validate_rule(&rules[1], false);
    assert_eq!(r1.status, ValidationStatus::Rechazada);

    let r2 = YaraRuleValidator::validate_rule(&rules[2], false);
    assert_eq!(r2.status, ValidationStatus::Rechazada);
}

#[test]
fn test_compiled_yara_runtime_detects_hex_and_external_vars() {
    let hex_rule = r#"
rule Win_PE_Hex_Pattern {
    meta:
        author = "SamuLibre"
        description = "Detects synthetic hex marker in PE"
    strings:
        $mz = { 4D 5A }
        $marker = { DE AD BE EF CA FE BA BE }
    condition:
        $mz at 0 and $marker and filename != "ignored.txt"
}
"#;
    let parsed = YaraRuleValidator::split_yara_file(hex_rule, "GPL-3.0");
    assert_eq!(parsed.len(), 1);
    assert!(parsed[0].external_vars.contains(&"filename".to_string()));

    let val = YaraRuleValidator::validate_rule(&parsed[0], false);
    assert!(val.status.is_production_active());

    let runtime = CompiledYaraRuntime::compile_rules([("test_ns", parsed[0].raw_source.as_str())])
        .expect("Debe compilar en yara-x");
    assert_eq!(runtime.compiled_count(), 1);

    let mut pe_sample = vec![0u8; 64];
    pe_sample[0..2].copy_from_slice(&[0x4D, 0x5A]);
    pe_sample[16..24].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);

    let hits = runtime
        .scan_bytes(&pe_sample, "payload.exe", "C:\\temp\\payload.exe", "exe", "PE")
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].rule_name, "Win_PE_Hex_Pattern");

    // Archivo limpio no debe coincidir
    let clean = b"Just a normal benign text file.";
    let clean_hits = runtime
        .scan_bytes(clean, "notes.txt", "C:\\temp\\notes.txt", "txt", "TXT")
        .unwrap();
    assert!(clean_hits.is_empty());
}

#[test]
fn test_intel_db_upsert_history_dedup_and_obsolete() {
    let db = IntelDatabase::open_in_memory().unwrap();
    let id = IntelDatabase::compute_indicator_id(IndicatorType::YaraRule, "RepoA", "file.yar::R1");
    let mut rec = ThreatIndicatorRecord {
        id: id.clone(),
        indicator_type: IndicatorType::YaraRule,
        value: "R1".to_string(),
        payload: "rule R1 { strings: $a = \"malicious_payload_123\" condition: $a }".to_string(),
        content_hash: "hash_v1".to_string(),
        malware_family: "TestFam".to_string(),
        threat_name: "R1".to_string(),
        category: "Malware".to_string(),
        source_name: "RepoA".to_string(),
        repo_origin: "RepoA".to_string(),
        rule_author: "Alice".to_string(),
        license: "GPL-2.0".to_string(),
        source_url: "https://example.com/file.yar".to_string(),
        first_seen: "2026-11-15T00:00:00Z".to_string(),
        last_modified: "2026-11-15T00:00:00Z".to_string(),
        expires_at: None,
        confidence: 95,
        validation_status: ValidationStatus::Aprobada,
        validation_score: 95,
        validation_notes: "OK".to_string(),
        version: 1,
        external_vars: vec![],
        required_modules: vec![],
    };

    assert_eq!(db.upsert_indicator(&rec).unwrap(), UpsertOutcome::Inserted);
    assert_eq!(db.upsert_indicator(&rec).unwrap(), UpsertOutcome::Unchanged);

    // Detección de duplicado en otro ID
    let dup = db
        .find_duplicate_by_content_hash(IndicatorType::YaraRule, "hash_v1", "other_id")
        .unwrap();
    assert_eq!(dup, Some(id.clone()));

    // Modificación
    rec.content_hash = "hash_v2".to_string();
    assert_eq!(db.upsert_indicator(&rec).unwrap(), UpsertOutcome::Updated);

    // Retiro / Obsoleta
    let retired = db
        .mark_source_url_obsolete("RepoA", "https://example.com/file.yar")
        .unwrap();
    assert_eq!(retired, 1);

    let history = db.get_history_for_indicator(&id).unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].action, "RETIRED");
    assert_eq!(history[1].action, "MODIFIED");
    assert_eq!(history[2].action, "INSERTED");

    let stats = db.get_stats().unwrap();
    assert_eq!(stats.yara_obsolete, 1);
    assert_eq!(stats.yara_approved, 0);
}

#[test]
fn test_behavior_adapter_sigma_and_elastic_compatibility() {
    use samulibre_intel::{BehaviorRuleAdapter, SamuBehaviorCategory};

    let sigma_win_ps = r#"
title: Suspicious PowerShell Encoded Command
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Detects encoded PowerShell execution
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
"#;
    let r1 = BehaviorRuleAdapter::parse_sigma_yaml(sigma_win_ps, "rules/windows/ps.yml").unwrap();
    assert!(r1.compatible_with_samulibre);
    assert_eq!(r1.category, SamuBehaviorCategory::ProcessCreation);
    assert!(r1.mitre_techniques.contains(&"T1059.001".to_string()));

    let sigma_cloud = r#"
title: AWS CloudTrail IAM Change
id: 66666666-7777-8888-9999-000000000000
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: CreateUser
    condition: selection
"#;
    let r2 = BehaviorRuleAdapter::parse_sigma_yaml(sigma_cloud, "rules/cloud/aws.yml").unwrap();
    assert!(!r2.compatible_with_samulibre);
    assert_eq!(r2.category, SamuBehaviorCategory::UnsupportedReference);
    assert!(r2.incompatibility_reason.is_some());

    let elastic_eql = r#"
name = "EQL Process Sequence"
rule_id = "elastic-eql-1"
description = "Sequence rule"
severity = "high"
type = "eql"
query = '''
sequence by process.entity_id
  [process where os.type == "windows"]
'''
"#;
    let r3 = BehaviorRuleAdapter::parse_elastic_toml(elastic_eql, "rules/windows/seq.toml").unwrap();
    assert!(!r3.compatible_with_samulibre);
    assert_eq!(r3.category, SamuBehaviorCategory::UnsupportedReference);
}

#[test]
fn test_licensing_classification_and_anti_fp_decision_levels() {
    use samulibre_intel::{
        AntiFalsePositiveEngine, FpEvaluationInput, LicenseCompatibility,
        LicensingAndManifestManager, ThreatDecisionLevel,
    };

    let (c_mit, _) = LicensingAndManifestManager::classify_license("MIT");
    assert_eq!(c_mit, LicenseCompatibility::PermissiveCommercialSafe);

    let (c_gpl, _) = LicensingAndManifestManager::classify_license("GPL-2.0");
    assert_eq!(c_gpl, LicenseCompatibility::CopyleftAttribution);

    let (c_elastic, _) = LicensingAndManifestManager::classify_license("Elastic License v2");
    assert_eq!(c_elastic, LicenseCompatibility::RestrictedReviewRequired);

    // Herramienta administrativa firmada con solo 1 heurística débil NO debe cuarentenarse
    let fp_safe = AntiFalsePositiveEngine::evaluate(&FpEvaluationInput {
        file_path: "C:\\Windows\\SysWOW64\\shsvcs.dll".to_string(),
        has_definitive_hash_match: false,
        yara_match_count: 0,
        heuristic_match_count: 1,
        independent_sources_count: 1,
        max_source_reputation: 70,
        has_valid_authenticode: true,
        publisher: Some("Microsoft Windows".to_string()),
        is_admin_or_dev_tool: true,
        has_active_behavior_alert: false,
    });
    assert!(!fp_safe.allow_auto_quarantine);
    assert_eq!(fp_safe.level, ThreatDecisionLevel::Informativo);

    // Hash malicioso confirmado sí debe confirmar aunque esté firmado
    let confirmed = AntiFalsePositiveEngine::evaluate(&FpEvaluationInput {
        file_path: "C:\\Temp\\evil.exe".to_string(),
        has_definitive_hash_match: true,
        yara_match_count: 1,
        heuristic_match_count: 0,
        independent_sources_count: 2,
        max_source_reputation: 96,
        has_valid_authenticode: true,
        publisher: Some("Stolen Cert".to_string()),
        is_admin_or_dev_tool: false,
        has_active_behavior_alert: false,
    });
    assert!(confirmed.allow_auto_quarantine);
    assert_eq!(confirmed.level, ThreatDecisionLevel::Confirmado);
}

#[test]
fn test_promotion_gate_lab_to_production_and_regression() {
    use samulibre_intel::{
        IndicatorType, IntelDatabase, ThreatIndicatorRecord, ValidationStatus, YaraPromotionGate,
    };

    let tmp_dir = std::env::temp_dir().join("samulibre_promo_gate_test");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let db = IntelDatabase::open(tmp_dir.join("intel.db")).unwrap();

    let good_rule = r#"
rule promo_malware_sample {
    meta:
        author = "SamuLibre QA"
        description = "Detects unique synthetic marker"
    strings:
        $a = "SAMULIBRE_UNIQUE_MALWARE_MARKER_998877" ascii
    condition:
        $a
}
"#;
    let id_good = IntelDatabase::compute_indicator_id(IndicatorType::YaraRule, "QA", "promo_malware_sample");
    db.upsert_indicator(&ThreatIndicatorRecord {
        id: id_good.clone(),
        indicator_type: IndicatorType::YaraRule,
        value: "promo_malware_sample".to_string(),
        payload: good_rule.to_string(),
        content_hash: "h_good".to_string(),
        malware_family: "QA".to_string(),
        threat_name: "promo_malware_sample".to_string(),
        category: "QA".to_string(),
        source_name: "QA".to_string(),
        repo_origin: "QA".to_string(),
        rule_author: "QA".to_string(),
        license: "MIT".to_string(),
        source_url: "https://example.invalid".to_string(),
        first_seen: "2026-11-15T00:00:00Z".to_string(),
        last_modified: "2026-11-15T00:00:00Z".to_string(),
        expires_at: None,
        confidence: 80,
        validation_status: ValidationStatus::Laboratorio,
        validation_score: 80,
        validation_notes: "Ingresada en Laboratorio".to_string(),
        version: 1,
        external_vars: vec![],
        required_modules: vec![],
    })
    .unwrap();

    let st1 = YaraPromotionGate::evaluate_and_promote(
        &db,
        &id_good,
        good_rule,
        "MIT",
        ValidationStatus::EnObservacion,
    )
    .unwrap();
    assert_eq!(st1, ValidationStatus::EnObservacion);

    let st2 = YaraPromotionGate::evaluate_and_promote(
        &db,
        &id_good,
        good_rule,
        "MIT",
        ValidationStatus::Aprobada,
    )
    .unwrap();
    assert_eq!(st2, ValidationStatus::Aprobada);

    // Regla con licencia CC BY-NC debe ser rechazada automáticamente
    let st_nc = YaraPromotionGate::evaluate_and_promote(
        &db,
        &id_good,
        good_rule,
        "CC BY-NC 4.0",
        ValidationStatus::Aprobada,
    )
    .unwrap();
    assert_eq!(st_nc, ValidationStatus::Rechazada);

    let history = db.get_history_for_indicator(&id_good).unwrap();
    assert!(history.len() >= 3);

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_driver_security_intel_real_and_synthetic() {
    use samulibre_intel::{
        DriverSecurityIntel, IndicatorType, IntelDatabase, ThreatIndicatorRecord, ValidationStatus,
    };
    use sha2::{Digest, Sha256};

    let tmp_dir = std::env::temp_dir().join("samulibre_driver_intel_test");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let db = IntelDatabase::open(tmp_dir.join("intel.db")).unwrap();

    let fake_driver_bytes = b"MZ_SYNTHETIC_VULN_DRIVER_TEST_PAYLOAD";
    let driver_path = tmp_dir.join("vuln_test_drv.sys");
    std::fs::write(&driver_path, fake_driver_bytes).unwrap();
    let sha = format!("{:x}", Sha256::digest(fake_driver_bytes));

    db.upsert_indicator(&ThreatIndicatorRecord {
        id: IntelDatabase::compute_indicator_id(IndicatorType::Sha256, "LOLDrivers", &sha),
        indicator_type: IndicatorType::Sha256,
        value: sha.clone(),
        payload: sha.clone(),
        content_hash: sha.clone(),
        malware_family: "BYOVD".to_string(),
        threat_name: "VulnTestDriver.sys".to_string(),
        category: "LOLDrivers".to_string(),
        source_name: "magicsword-io/LOLDrivers".to_string(),
        repo_origin: "magicsword-io/LOLDrivers".to_string(),
        rule_author: "LOLDrivers".to_string(),
        license: "MIT".to_string(),
        source_url: "https://www.loldrivers.io/".to_string(),
        first_seen: "2026-11-15T00:00:00Z".to_string(),
        last_modified: "2026-11-15T00:00:00Z".to_string(),
        expires_at: None,
        confidence: 90,
        validation_status: ValidationStatus::Aprobada,
        validation_score: 90,
        validation_notes: "QA test".to_string(),
        version: 1,
        external_vars: vec![],
        required_modules: vec![],
    })
    .unwrap();

    let report = DriverSecurityIntel::audit_directory(&db, &tmp_dir).unwrap();
    assert_eq!(report.scanned_drivers_count, 1);
    assert_eq!(report.vulnerable_findings.len(), 1);
    assert!(report.vulnerable_findings[0].is_vulnerable_byovd);
    assert!(driver_path.exists(), "No debe eliminar drivers automáticamente");

    // Auditoría real sobre C:\Windows\System32\drivers si existe la DB real
    let real_db_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("data/intel/samulibre_intel.db");
    if real_db_path.exists() {
        let real_db = IntelDatabase::open(&real_db_path).unwrap();
        let win_rep = DriverSecurityIntel::audit_windows_drivers(&real_db).unwrap();
        println!(
            "[QA][DriverIntel] windows_drivers_scanned={} loldrivers_hashes={} findings={} duration_ms={}",
            win_rep.scanned_drivers_count,
            win_rep.loldrivers_db_hashes,
            win_rep.vulnerable_findings.len(),
            win_rep.duration_ms
        );
        assert!(win_rep.scanned_drivers_count > 0);
        assert!(win_rep.loldrivers_db_hashes >= 3700);
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_manifest_corruption_detection() {
    use samulibre_intel::{IntelDatabase, LicensingAndManifestManager};

    let tmp_dir = std::env::temp_dir().join("samulibre_manifest_corrupt_test");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let db_path = tmp_dir.join("intel.db");
    let _db = IntelDatabase::open(&db_path).unwrap();
    let secret = b"samulibre-qa-secret";

    let mut manifest =
        LicensingAndManifestManager::create_signed_manifest(&db_path, None, 100, secret).unwrap();
    assert!(LicensingAndManifestManager::verify_manifest(&manifest, secret));

    // Simular corrupción/manipulación del manifiesto
    manifest.total_active_indicators += 999;
    assert!(!LicensingAndManifestManager::verify_manifest(&manifest, secret));

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_intel_keys_vault_save_and_masking() {
    use samulibre_intel::ThreatFeedConnectors;

    let tmp_dir = std::env::temp_dir().join("samulibre_intel_keys_vault_test");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let key_file = tmp_dir.join("secure").join("intel_keys.json");

    let st1 = ThreatFeedConnectors::save_intel_keys(
        &key_file,
        Some("abusech_secret_token_9876"),
        Some("otx_secret_token_4321"),
    )
    .unwrap();
    assert!(st1.abusech_configured);
    assert_eq!(st1.abusech_masked, "****9876");
    assert_eq!(st1.abusech_source, "vault");
    assert!(st1.otx_configured);
    assert_eq!(st1.otx_masked, "****4321");
    assert_eq!(st1.otx_source, "vault");

    // Guardar vacío NO debe sobrescribir una llave ya existente
    let st2 = ThreatFeedConnectors::save_intel_keys(&key_file, Some(""), None).unwrap();
    assert!(st2.abusech_configured);
    assert_eq!(st2.abusech_masked, "****9876");
    assert!(st2.otx_configured);
    assert_eq!(st2.otx_masked, "****4321");

    let resolved_abuse = ThreatFeedConnectors::resolve_api_key_at(
        None,
        "abusech-malwarebazaar",
        &key_file,
    );
    assert_eq!(resolved_abuse.as_deref(), Some("abusech_secret_token_9876"));

    let resolved_otx = ThreatFeedConnectors::resolve_api_key_at(
        None,
        "alienvault-otx",
        &key_file,
    );
    assert_eq!(resolved_otx.as_deref(), Some("otx_secret_token_4321"));

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
