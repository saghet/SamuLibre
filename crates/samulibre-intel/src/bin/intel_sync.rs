use samulibre_intel::{
    CompiledYaraRuntime, GitSyncService, IntelDatabase, LicensingAndManifestManager,
    ThreatFeedConnectors,
};
use std::path::Path;
use std::time::Instant;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let run_phase3 = args.iter().any(|a| a == "--phase3" || a == "--all");
    let run_phase45 = args.iter().any(|a| a == "--phase4" || a == "--phase5" || a == "--phase45" || a == "--all");
    let run_loldrivers = args.iter().any(|a| a == "--loldrivers");
    let run_phase2 = (!run_phase3 && !run_phase45 && !run_loldrivers) || args.iter().any(|a| a == "--phase2" || a == "--all");

    let db_path = Path::new("data/intel/samulibre_intel.db");
    let repos_dir = Path::new("data/intel/repos");
    let db = IntelDatabase::open(db_path)?;
    let sync = GitSyncService::new(repos_dir);

    if run_phase2 {
        for repo in GitSyncService::phase2_repos() {
            println!("=== [FASE 2] Sincronizando {} ===", repo.name);
            let report = sync.sync_repo(&db, &repo, false);
            print_report(&report);
        }
    }

    if run_phase3 {
        for repo in GitSyncService::phase3_yara_repos() {
            println!("=== [FASE 3 - Grupo A] Sincronizando {} ===", repo.name);
            let report = sync.sync_repo(&db, &repo, false);
            print_report(&report);
        }

        println!("=== [FASE 3 - Grupo A] Sincronizando YARAHQ/yara-forge (Core) ===");
        let forge_rep = sync.sync_yara_forge(&db);
        print_report(&forge_rep);

        println!("=== [FASE 3 - Grupo A] Verificando Malpedia Signator Rules ===");
        let malpedia_rep = sync.sync_malpedia_signator(&db);
        print_report(&malpedia_rep);

        for repo in GitSyncService::phase3_behavior_repos() {
            println!("=== [FASE 3 - Grupo B] Sincronizando {} ===", repo.name);
            let report = sync.sync_behavior_repo(&db, &repo, 5000);
            print_report(&report);
        }
    }

    if run_loldrivers {
        for repo in GitSyncService::phase3_behavior_repos()
            .into_iter()
            .filter(|r| r.source_id == "loldrivers")
        {
            println!("=== [FASE 3 - Grupo B] Sincronizando {} (GIT_LFS_SKIP_SMUDGE=1) ===", repo.name);
            let report = sync.sync_behavior_repo(&db, &repo, 5000);
            print_report(&report);
        }
    }

    if run_phase45 {
        for cfg in ThreatFeedConnectors::all_connectors() {
            println!("=== [FASE 4/5] Conectando {} ===", cfg.name);
            let rep = ThreatFeedConnectors::sync_connector(&db, &cfg, true);
            println!(
                "Resultado: success={}, status={}, received={}, accepted={}, rejected={}, time={}ms, error={:?}",
                rep.success, rep.status, rep.received, rep.accepted, rep.rejected, rep.response_time_ms, rep.error
            );
        }
    }

    let stats = db.get_stats()?;
    println!("\n=== Estadísticas Reales en SQLite ({:?}) ===", db_path);
    println!("{:#?}", stats);

    let sbom = LicensingAndManifestManager::generate_sbom(&db)?;
    let sbom_path = Path::new("data/intel/sbom_provenance.json");
    std::fs::write(sbom_path, serde_json::to_string_pretty(&sbom)?)?;
    println!("SBOM de licencias y procedencia guardado en {:?}", sbom_path);

    let bin_path = Path::new("data/intel/compiled_yara.bin");
    if (!run_phase45 && !run_loldrivers) || args.iter().any(|a| a == "--compile") || !bin_path.exists() {
        let t0 = Instant::now();
        let yara_records = db.load_production_yara_rules()?;
        let refs: Vec<(&str, &str)> = yara_records
            .iter()
            .map(|r| (r.repo_origin.as_str(), r.payload.as_str()))
            .collect();
        let runtime = CompiledYaraRuntime::compile_rules(refs)?;
        println!(
            "\nCompilación YARA-X en producción: {} reglas compiladas, {} fallidas en {} ms",
            runtime.compiled_count(),
            runtime.failed_count(),
            t0.elapsed().as_millis()
        );
        runtime.save_to_file(bin_path)?;
        println!("Snapshot compilado guardado en {:?}", bin_path);

        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let hits = runtime.scan_bytes(eicar, "eicar.com", "C:\\temp\\eicar.com", "com", "")?;
        println!(
            "Prueba EICAR en runtime YARA-X: {} coincidencias -> {:?}",
            hits.len(),
            hits.iter().map(|h| &h.rule_name).collect::<Vec<_>>()
        );
    }

    let manifest = LicensingAndManifestManager::create_signed_manifest(
        db_path,
        Some(bin_path),
        stats.total_indicators,
        b"SamuLibre-Community-Intel-Manifest-v1",
    )?;
    let manifest_path = Path::new("data/intel/manifest.json");
    std::fs::write(manifest_path, serde_json::to_string_pretty(&manifest)?)?;
    println!("Manifiesto firmado guardado en {:?}", manifest_path);

    Ok(())
}

fn print_report(report: &samulibre_intel::GitSyncReport) {
    println!(
        "Resultado: success={}, incremental={}, commit={:?}, files={}, deleted={}, received={}, approved={}, restricted={}, observation={}, rejected={}, duplicates={}, retired={}, hashes={}, duration={}ms, error={:?}",
        report.success,
        report.incremental,
        report.commit_after,
        report.files_processed,
        report.files_deleted,
        report.rules_received,
        report.rules_approved,
        report.rules_restricted,
        report.rules_observation,
        report.rules_rejected,
        report.rules_duplicates,
        report.rules_retired,
        report.hashes_imported,
        report.duration_ms,
        report.error
    );
}
