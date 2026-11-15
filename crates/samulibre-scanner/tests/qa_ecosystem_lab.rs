use samulibre_intel::{AntiFalsePositiveEngine, CompiledYaraRuntime, FpEvaluationInput, IntelDatabase, ThreatDecisionLevel};
use samulibre_scanner::MultiEngineScanner;
use samulibre_types::FileScanStatus;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn qa_yara_and_scanner_end_to_end() {
    let root = workspace_root();
    let db_path = root.join("data/intel/samulibre_intel.db");
    let bin_path = root.join("data/intel/compiled_yara.bin");

    if db_path.exists() {
        let t_db = Instant::now();
        let db = IntelDatabase::open(&db_path).expect("open intel db");
        let stats = db.get_stats().expect("get_stats");
        let c2_ips = db.load_production_c2_ips().expect("load_production_c2_ips");
        let db_ms = t_db.elapsed().as_secs_f64() * 1000.0;
        println!(
            "[QA][IntelDB] total={} sha256={} yara_prod={} behavior_prod={} c2_ips={} sources={} query_ms={:.2}",
            stats.total_indicators,
            stats.sha256_approved,
            stats.yara_approved,
            stats.behavior_rules_approved,
            stats.c2_ips_approved,
            stats.connected_sources,
            db_ms
        );
        assert!(stats.total_indicators > 0);
        assert!(
            c2_ips.iter().any(|ip| ip == "162.243.103.246"),
            "Se esperaba IP C2 de Feodo Tracker en producción"
        );

        let page_resp = samulibre_scanner::query_signatures_from_intel_db(
            &root.join("data/signatures"),
            "ALL",
            "PRODUCCION",
            "",
            0,
            50,
        )
        .expect("query_signatures_from_intel_db");
        println!(
            "[QA][CatalogPagination] total_protections={} total_filtered={} page_len={}",
            page_resp.summary.total_protections,
            page_resp.total_filtered,
            page_resp.entries.len()
        );
        assert_eq!(
            page_resp.total_filtered, page_resp.summary.total_protections,
            "El total paginado de la tabla debe coincidir exactamente con el encabezado"
        );
        assert_eq!(page_resp.entries.len(), 50);
    }

    if bin_path.exists() {
        let t_load = Instant::now();
        let rt = CompiledYaraRuntime::load_from_file(&bin_path).expect("load compiled_yara.bin");
        let load_ms = t_load.elapsed().as_secs_f64() * 1000.0;
        let eicar_hits = rt
            .scan_bytes(
                b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                "eicar.com",
                "eicar.com",
                "com",
                "text",
            )
            .expect("scan_bytes eicar");
        println!(
            "[QA][YARA-X] rules={} load_ms={:.2} eicar_hits={:?}",
            rt.compiled_count(),
            load_ms,
            eicar_hits.iter().map(|h| &h.rule_name).collect::<Vec<_>>()
        );
        assert!(rt.compiled_count() > 0);
        assert!(!eicar_hits.is_empty(), "EICAR debe disparar al menos 1 regla YARA-X");
    }

    let _ = std::env::set_current_dir(&root);
    let scanner = MultiEngineScanner::new();

    // Crear archivos de prueba inmediatamente después de inicializar el escáner
    let temp_dir = std::env::temp_dir().join("samulibre_qa_lab");
    let _ = fs::create_dir_all(&temp_dir);

    let eicar_file = temp_dir.join("qa_eicar_test.txt");
    fs::write(
        &eicar_file,
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    .unwrap();

    let clean_txt = temp_dir.join("qa_clean_notes.txt");
    fs::write(&clean_txt, b"Informe tecnico de auditoria SamuLibre v2.0.20 - contenido benigno.").unwrap();

    let clean_json = temp_dir.join("qa_clean_config.json");
    fs::write(&clean_json, br#"{"app":"samulibre","mode":"qa","safe":true}"#).unwrap();

    let clean_ps1 = temp_dir.join("qa_clean_script.ps1");
    fs::write(&clean_ps1, b"Write-Output 'System health check completed successfully.'\n").unwrap();

    let ps_policy_probe = temp_dir.join("__PSScriptPolicyTest_qa_probe.ps1");
    fs::write(&ps_policy_probe, b"# PowerShell policy test\nWrite-Output 'powershell'\n").unwrap();

    let t_eicar = Instant::now();
    let res_eicar = scanner.scan_file(&eicar_file).expect("scan eicar");
    let eicar_ms = t_eicar.elapsed().as_secs_f64() * 1000.0;
    println!(
        "[QA][Scanner][EICAR] status={:?} detection={:?} engine={} latency_ms={:.2}",
        res_eicar.status, res_eicar.detection_name, res_eicar.engine, eicar_ms
    );
    assert!(
        matches!(res_eicar.status, FileScanStatus::Infected | FileScanStatus::AccessDenied),
        "EICAR debe ser detectado como Infected (o bloqueado por Defender con AccessDenied/225), obtuvo {:?}",
        res_eicar.status
    );

    let mut clean_corpus = vec![
        clean_txt.clone(),
        clean_json.clone(),
        clean_ps1.clone(),
        ps_policy_probe.clone(),
    ];
    let repo_clean = root.join("data/test_samples/documento_seguro.txt");
    if repo_clean.exists() {
        clean_corpus.push(repo_clean);
    }

    let mut fp_count = 0usize;
    let t_clean = Instant::now();
    for path in &clean_corpus {
        let res = scanner.scan_file(path).expect("scan clean file");
        if res.status != FileScanStatus::Clean {
            fp_count += 1;
            println!("[QA][FP] {:?} -> {:?} ({:?})", path, res.status, res.detection_name);
        }
    }
    let clean_ms = t_clean.elapsed().as_secs_f64() * 1000.0;
    let fp_rate = (fp_count as f64 / clean_corpus.len() as f64) * 100.0;
    println!(
        "[QA][Scanner][CleanCorpus] files={} fp_count={} fp_rate={:.2}% total_ms={:.2}",
        clean_corpus.len(),
        fp_count,
        fp_rate,
        clean_ms
    );
    assert_eq!(fp_count, 0, "La tasa de falsos positivos en corpus limpio debe ser 0%");

    // Verificación Anti-FP en ruta protegida del sistema con heurística débil
    let fp_decision = AntiFalsePositiveEngine::evaluate(&FpEvaluationInput {
        file_path: r"C:\Windows\System32\svchost.exe".to_string(),
        has_definitive_hash_match: false,
        yara_match_count: 0,
        heuristic_match_count: 1,
        independent_sources_count: 1,
        max_source_reputation: 60,
        has_valid_authenticode: true,
        publisher: Some("Microsoft Windows".to_string()),
        is_admin_or_dev_tool: AntiFalsePositiveEngine::is_protected_context_path(
            r"C:\Windows\System32\svchost.exe",
        ),
        has_active_behavior_alert: false,
    });
    println!(
        "[QA][Anti-FP] level={:?} allow_auto_quarantine={} confidence={}",
        fp_decision.level, fp_decision.allow_auto_quarantine, fp_decision.final_confidence
    );
    assert_eq!(fp_decision.level, ThreatDecisionLevel::Informativo);
    assert!(!fp_decision.allow_auto_quarantine);

    let _ = fs::remove_dir_all(&temp_dir);
}
