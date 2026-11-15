use chrono::Utc;
use samulibre_scanner::{
    MultiEngineScanner, VirusTotalVerifier, VtCacheStore, VtEngineCategory, VtErrorKind,
    VtQuotaState, VtSecureKeyBackend, VtVerificationPolicy,
};
use samulibre_types::{ConfidenceLevel, ThreatRecord, ValidationStatus};
use std::fs;
use std::path::PathBuf;

fn make_temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "samulibre_vt_lab_{}_{}",
        name,
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_sample_threat(path: &str, sha256: &str, rule: &str, confidence: ConfidenceLevel) -> ThreatRecord {
    ThreatRecord {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        file_path: path.to_string(),
        threat_name: rule.to_string(),
        engine: "MultiEvidenceClassifier".to_string(),
        sha256: sha256.to_string(),
        severity: "Alto".to_string(),
        action_taken: "Pendiente".to_string(),
        quarantine_id: None,
        origin_source: None,
        origin_url: None,
        human_explanation: Some("Detección local multi-evidencia para verificación VT".to_string()),
        suggested_action: Some("Verificar en VirusTotal API v3".to_string()),
        confidence_level: confidence,
        calibrated_score: 65,
        evidences: Vec::new(),
        classification: "Sospechoso".to_string(),
        validation_status: ValidationStatus::default(),
        authenticode: None,
    }
}

#[test]
fn test_eicar_and_clean_sha256_and_live_virustotal_http() {
    let tmp = make_temp_dir("live_http");
    // Nota: en Windows con Defender activo, escribir el texto EICAR literal en disco dispara os error 225 al leerlo.
    // Calculamos el hash SHA-256 estándar de EICAR sin disparar bloqueo de lectura en disco, y probamos compute_sha256_file con archivo real limpio.
    let eicar_sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string();

    let clean_path = tmp.join("legit_readme.txt");
    fs::write(&clean_path, b"SamuLibre legitimate telemetry test file\n").unwrap();

    let clean_sha = VirusTotalVerifier::compute_sha256_file(&clean_path).unwrap();
    assert_ne!(clean_sha, eicar_sha);
    assert_eq!(clean_sha.len(), 64);

    let verifier = VirusTotalVerifier::new(
        &tmp,
        VtVerificationPolicy {
            hash_only_mode: true,
            auto_upload_suspicious_non_docs: false,
        },
    );

    let threat = make_sample_threat(
        "C:\\samples\\eicar_sample.com",
        &eicar_sha,
        "EICAR-Test-File",
        ConfidenceLevel::Critico,
    );

    if let Some(real_key) = VtSecureKeyBackend::resolve_api_key(&tmp) {
        // Prueba real autenticada contra VirusTotal API v3 con muestra EICAR
        let mut quota = VtQuotaState::default();
        let report = verifier
            .fetch_file_report_by_hash(&real_key, &eicar_sha, &mut quota)
            .expect("La consulta real a VirusTotal API v3 para EICAR debe responder 200 OK");
        assert!(report.stats.malicious > 0, "EICAR debe tener detecciones malicious en VT");
        let corr = verifier.verify_threat_record(&threat, false);
        assert!(corr.found_in_vt);
        assert!(!corr.vt_engines.is_empty());
    } else {
        // Sin API key en entorno: validar que falta clave en backend seguro y probar HTTP 401 real
        let report_no_key = verifier.verify_threat_record(&threat, false);
        assert!(!report_no_key.found_in_vt);
        assert!(
            report_no_key
                .error_detail
                .as_deref()
                .unwrap_or("")
                .contains("API Key"),
            "Debe reportar ausencia de API Key sin simular resultados: {:?}",
            report_no_key.error_detail
        );

        let mut quota = VtQuotaState::default();
        let err = verifier
            .fetch_file_report_by_hash("invalid-samulibre-test-key", &eicar_sha, &mut quota)
            .expect_err("Una API key inválida debe fallar contra virustotal.com");
        assert!(
            matches!(err.kind, VtErrorKind::AuthError | VtErrorKind::Connectivity | VtErrorKind::Timeout),
            "Se esperaba AuthError (HTTP 401 real) o error de red real, recibido: {:?}",
            err
        );
    }

    // Verificar registro de auditoría JSONL
    let ledger_path = tmp.join("audit").join("detection_ledger.jsonl");
    assert!(ledger_path.exists(), "Debe existir ledger de auditoría VT");
    let ledger_text = fs::read_to_string(&ledger_path).unwrap();
    assert!(ledger_text.contains("VirusTotal"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_vt_schema_parsing_categories_and_zero_detections_never_safe() {
    let tmp = make_temp_dir("schema_parse");
    let sha = "a".repeat(64);
    let sample_json = serde_json::json!({
        "data": {
            "id": sha,
            "attributes": {
                "last_analysis_date": 1700000000_i64,
                "reputation": -10,
                "meaningful_name": "dropper.exe",
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "undetected": 1,
                    "harmless": 1,
                    "timeout": 1,
                    "failure": 1
                },
                "last_analysis_results": {
                    "EngineA": { "category": "malicious", "result": "Trojan.Generic", "method": "blacklist", "engine_version": "1.0" },
                    "EngineB": { "category": "suspicious", "result": "Heur.Suspicious", "method": "heur", "engine_version": "2.0" },
                    "EngineC": { "category": "undetected", "result": null, "method": "blacklist", "engine_version": "3.0" },
                    "EngineD": { "category": "harmless", "result": null, "method": "whitelist", "engine_version": "4.0" },
                    "EngineE": { "category": "timeout", "result": null, "method": "blacklist", "engine_version": "5.0" }
                }
            }
        }
    });

    let parsed = VirusTotalVerifier::parse_vt_file_report(&sha, &sample_json).unwrap();
    assert_eq!(parsed.stats.malicious, 1);
    assert_eq!(parsed.stats.suspicious, 1);
    assert_eq!(parsed.stats.undetected, 1);
    assert_eq!(parsed.stats.harmless, 1);
    assert_eq!(parsed.stats.timeout_or_error, 1);
    assert_eq!(parsed.stats.total_engines, 5);
    assert!(parsed.last_analysis_date_utc.is_some());

    let find_cat = |name: &str| {
        parsed
            .engines
            .iter()
            .find(|e| e.engine_name == name)
            .unwrap()
            .category
    };
    assert_eq!(find_cat("EngineA"), VtEngineCategory::Malicious);
    assert_eq!(find_cat("EngineB"), VtEngineCategory::Suspicious);
    assert_eq!(find_cat("EngineC"), VtEngineCategory::Undetected);
    assert_eq!(find_cat("EngineD"), VtEngineCategory::Harmless);
    assert_eq!(find_cat("EngineE"), VtEngineCategory::TimeoutOrError);

    // Ahora probar informe con 0 detecciones en caché: NUNCA declarar seguro
    let zero_sha = "b".repeat(64);
    let zero_json = serde_json::json!({
        "data": {
            "id": zero_sha,
            "attributes": {
                "last_analysis_date": Utc::now().timestamp(),
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 65,
                    "harmless": 0,
                    "timeout": 0
                },
                "last_analysis_results": {
                    "Microsoft": { "category": "undetected", "result": null, "method": "blacklist", "engine_version": "1.1" }
                }
            }
        }
    });
    let zero_report = VirusTotalVerifier::parse_vt_file_report(&zero_sha, &zero_json).unwrap();
    let mut cache = VtCacheStore::default();
    let cache_path = tmp.join("vt_cache.json");
    cache.insert_and_save(zero_report, &cache_path);

    let zero_file = tmp.join("unknown_script.ps1");
    fs::write(&zero_file, b"Write-Host 'test'").unwrap();
    VtSecureKeyBackend::save_backend_key(&tmp, "dummy-key-cached-lookup").unwrap();

    let verifier = VirusTotalVerifier::new(&tmp, VtVerificationPolicy::default());
    let threat = make_sample_threat(
        zero_file.to_str().unwrap(),
        &zero_sha,
        "Heur.LocalScript",
        ConfidenceLevel::Medio,
    );
    let corr = verifier.verify_threat_record(&threat, false);
    assert!(corr.found_in_vt);
    assert!(corr.from_cache);
    let rec_lower = corr.samulibre_recommendation.to_lowercase();
    assert!(
        rec_lower.contains("no garantiza") || rec_lower.contains("no declara seguro"),
        "0 detecciones en VT jamás debe declarar el archivo seguro: {}",
        corr.samulibre_recommendation
    );

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_privacy_office_pdf_consent_and_hash_only_enforcement() {
    let tmp = make_temp_dir("privacy_consent");
    let pdf_path = tmp.join("contrato_confidencial.pdf");
    fs::write(&pdf_path, b"%PDF-1.7\nContenido privado de prueba").unwrap();
    let docx_path = tmp.join("nomina_2026.docx");
    fs::write(&docx_path, b"PK\x03\x04documento office").unwrap();
    let exe_path = tmp.join("sample_tool.exe");
    fs::write(&exe_path, b"MZfake_binary").unwrap();

    assert!(VirusTotalVerifier::is_sensitive_document(&pdf_path));
    assert!(VirusTotalVerifier::is_sensitive_document(&docx_path));
    assert!(!VirusTotalVerifier::is_sensitive_document(&exe_path));

    // Aunque auto_upload_suspicious_non_docs esté activo y hash_only_mode en false,
    // Office y PDF SIEMPRE exigen advertencia de privacidad y consentimiento explícito.
    let verifier_auto = VirusTotalVerifier::new(
        &tmp,
        VtVerificationPolicy {
            hash_only_mode: false,
            auto_upload_suspicious_non_docs: true,
        },
    );

    let pdf_sha = VirusTotalVerifier::compute_sha256_file(&pdf_path).unwrap();
    let pdf_threat = make_sample_threat(
        pdf_path.to_str().unwrap(),
        &pdf_sha,
        "PDF.Suspicious.Heuristic",
        ConfidenceLevel::Medio,
    );

    let corr_pdf = verifier_auto.verify_threat_record(&pdf_threat, false);
    assert!(corr_pdf.is_sensitive_document);
    assert!(corr_pdf.requires_explicit_consent);
    assert!(corr_pdf.privacy_warning.is_some());
    assert!(corr_pdf.uploaded_analysis_id.is_none());

    // Con hash_only_mode = true, tampoco se permite subir ejecutables
    let verifier_hash_only = VirusTotalVerifier::new(
        &tmp,
        VtVerificationPolicy {
            hash_only_mode: true,
            auto_upload_suspicious_non_docs: true,
        },
    );
    let exe_sha = VirusTotalVerifier::compute_sha256_file(&exe_path).unwrap();
    let exe_threat = make_sample_threat(
        exe_path.to_str().unwrap(),
        &exe_sha,
        "PE.Suspicious",
        ConfidenceLevel::Medio,
    );
    let corr_exe = verifier_hash_only.verify_threat_record(&exe_threat, true);
    assert!(corr_exe.uploaded_analysis_id.is_none());

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn test_quota_http_errors_and_non_mutation_of_local_engine() {
    let tmp = make_temp_dir("quota_and_errors");
    let quota_path = tmp.join("vt_quota.json");
    let mut quota = VtQuotaState::load(&quota_path);

    // Límite API pública gratuita: 4 solicitudes/minuto
    for _ in 0..4 {
        quota.check_and_consume(&quota_path).unwrap();
    }
    let err_min = quota.check_and_consume(&quota_path).unwrap_err();
    assert_eq!(err_min.kind, VtErrorKind::RateLimit429);

    // Mapeo explícito de HTTP 429 y 401/403
    assert_eq!(VirusTotalVerifier::map_http_status_error(429).kind, VtErrorKind::RateLimit429);
    assert_eq!(VirusTotalVerifier::map_http_status_error(401).kind, VtErrorKind::AuthError);
    assert_eq!(VirusTotalVerifier::map_http_status_error(403).kind, VtErrorKind::AuthError);
    assert_eq!(VirusTotalVerifier::map_http_status_error(404).kind, VtErrorKind::NotFound);

    // Verificar que VT NO modifica reglas YARA ni firmas locales de SamuLibre
    let scanner_before = MultiEngineScanner::new();
    let sig_count_before = scanner_before.signature_count();
    let rule_count_before = scanner_before.rule_count();

    let verifier = VirusTotalVerifier::new(&tmp, VtVerificationPolicy::default());
    let sample_file = tmp.join("benign.txt");
    fs::write(&sample_file, b"hello").unwrap();
    let sha = VirusTotalVerifier::compute_sha256_file(&sample_file).unwrap();
    let threat = make_sample_threat(
        sample_file.to_str().unwrap(),
        &sha,
        "LocalTestRule",
        ConfidenceLevel::Bajo,
    );
    let _ = verifier.verify_threat_record(&threat, false);

    let scanner_after = MultiEngineScanner::new();
    assert_eq!(sig_count_before, scanner_after.signature_count());
    assert_eq!(rule_count_before, scanner_after.rule_count());

    let _ = fs::remove_dir_all(&tmp);
}
