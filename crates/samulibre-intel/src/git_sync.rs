use crate::behavior_adapter::BehaviorRuleAdapter;
use crate::db::{IntelDatabase, UpsertOutcome};
use crate::models::{IndicatorType, IntelSource, ThreatIndicatorRecord, ValidationStatus};
use crate::yara_engine::YaraRuleValidator;
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Paquetes oficiales de YARA Forge y su entorno de destino
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum YaraForgePackage {
    Core,
    Extended,
    Full,
}

/// Configuración de un repositorio Git de inteligencia de amenazas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRepoConfig {
    pub source_id: String,
    pub name: String,
    pub url: String,
    pub default_license: String,
    pub ingest_yara: bool,
    pub ingest_hash_iocs: bool,
}

/// Reporte detallado de una sincronización incremental de repositorio
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GitSyncReport {
    pub source_id: String,
    pub name: String,
    pub success: bool,
    pub incremental: bool,
    pub commit_before: Option<String>,
    pub commit_after: Option<String>,
    pub files_processed: usize,
    pub files_deleted: usize,
    pub rules_received: usize,
    pub rules_approved: usize,
    pub rules_restricted: usize,
    pub rules_observation: usize,
    pub rules_rejected: usize,
    pub rules_duplicates: usize,
    pub rules_retired: usize,
    pub hashes_imported: usize,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// Servicio de adquisición continua e incremental de repositorios Git
pub struct GitSyncService {
    repos_root: PathBuf,
}

impl GitSyncService {
    pub fn new(repos_root: impl AsRef<Path>) -> Self {
        Self {
            repos_root: repos_root.as_ref().to_path_buf(),
        }
    }

    /// Repositorios prioritarios de Fase 2 (Grupo A)
    pub fn phase2_repos() -> Vec<GitRepoConfig> {
        vec![
            GitRepoConfig {
                source_id: "yara-rules-official".to_string(),
                name: "Yara-Rules/rules".to_string(),
                url: "https://github.com/Yara-Rules/rules.git".to_string(),
                default_license: "GPL-2.0".to_string(),
                ingest_yara: true,
                ingest_hash_iocs: false,
            },
            GitRepoConfig {
                source_id: "neo23x0-signature-base".to_string(),
                name: "Neo23x0/signature-base".to_string(),
                url: "https://github.com/Neo23x0/signature-base.git".to_string(),
                default_license: "Detection Rule License (DRL) 1.1".to_string(),
                ingest_yara: true,
                ingest_hash_iocs: true,
            },
        ]
    }

    /// Repositorios YARA adicionales de Fase 3 (Grupo A)
    pub fn phase3_yara_repos() -> Vec<GitRepoConfig> {
        vec![
            GitRepoConfig {
                source_id: "atr-yara-rules".to_string(),
                name: "advanced-threat-research/Yara-Rules".to_string(),
                url: "https://github.com/advanced-threat-research/Yara-Rules.git".to_string(),
                default_license: "Apache-2.0".to_string(),
                ingest_yara: true,
                ingest_hash_iocs: false,
            },
            GitRepoConfig {
                source_id: "ditekshen-detection".to_string(),
                name: "ditekshen/detection".to_string(),
                url: "https://github.com/ditekshen/detection.git".to_string(),
                default_license: "MIT".to_string(),
                ingest_yara: true,
                ingest_hash_iocs: false,
            },
            GitRepoConfig {
                source_id: "reversinglabs-yara".to_string(),
                name: "reversinglabs/reversinglabs-yara-rules".to_string(),
                url: "https://github.com/reversinglabs/reversinglabs-yara-rules.git".to_string(),
                default_license: "MIT".to_string(),
                ingest_yara: true,
                ingest_hash_iocs: false,
            },
        ]
    }

    /// Repositorios de detección de comportamiento de Fase 3 (Grupo B)
    pub fn phase3_behavior_repos() -> Vec<GitRepoConfig> {
        vec![
            GitRepoConfig {
                source_id: "sigmahq-sigma".to_string(),
                name: "SigmaHQ/sigma".to_string(),
                url: "https://github.com/SigmaHQ/sigma.git".to_string(),
                default_license: "Detection Rule License (DRL) 1.1".to_string(),
                ingest_yara: false,
                ingest_hash_iocs: false,
            },
            GitRepoConfig {
                source_id: "elastic-detection-rules".to_string(),
                name: "elastic/detection-rules".to_string(),
                url: "https://github.com/elastic/detection-rules.git".to_string(),
                default_license: "Elastic License v2".to_string(),
                ingest_yara: false,
                ingest_hash_iocs: false,
            },
            GitRepoConfig {
                source_id: "loldrivers".to_string(),
                name: "magicsword-io/LOLDrivers".to_string(),
                url: "https://github.com/magicsword-io/LOLDrivers.git".to_string(),
                default_license: "MIT".to_string(),
                ingest_yara: false,
                ingest_hash_iocs: false,
            },
        ]
    }

    /// Sincroniza un repositorio de forma incremental y valida sus reglas antes de activarlas
    pub fn sync_repo(
        &self,
        db: &IntelDatabase,
        cfg: &GitRepoConfig,
        force_full_reimport: bool,
    ) -> GitSyncReport {
        let t0 = Instant::now();
        let mut report = GitSyncReport {
            source_id: cfg.source_id.clone(),
            name: cfg.name.clone(),
            ..Default::default()
        };

        let repo_dir = self.repos_root.join(&cfg.source_id);
        let _ = fs::create_dir_all(&self.repos_root);

        let sync_res = self.sync_repo_inner(db, cfg, &repo_dir, force_full_reimport, &mut report);
        report.duration_ms = t0.elapsed().as_millis() as u64;

        let now = Utc::now().to_rfc3339();
        match sync_res {
            Ok(_) => {
                report.success = true;
                let _ = db.upsert_source(&IntelSource {
                    source_id: cfg.source_id.clone(),
                    name: cfg.name.clone(),
                    source_kind: "git_yara".to_string(),
                    url: cfg.url.clone(),
                    last_sync_at: Some(now),
                    last_commit: report.commit_after.clone(),
                    status: "OK".to_string(),
                    received_count: report.rules_received + report.hashes_imported,
                    accepted_count: report.rules_approved
                        + report.rules_restricted
                        + report.hashes_imported,
                    rejected_count: report.rules_rejected,
                    last_error: None,
                    response_time_ms: report.duration_ms,
                    license_default: cfg.default_license.clone(),
                });
            }
            Err(e) => {
                let err_msg = e.to_string();
                warn!("Error sincronizando repositorio {}: {}", cfg.name, err_msg);
                report.success = false;
                report.error = Some(err_msg.clone());
                let _ = db.upsert_source(&IntelSource {
                    source_id: cfg.source_id.clone(),
                    name: cfg.name.clone(),
                    source_kind: "git_yara".to_string(),
                    url: cfg.url.clone(),
                    last_sync_at: Some(now),
                    last_commit: report.commit_after.clone(),
                    status: "ERROR".to_string(),
                    received_count: report.rules_received + report.hashes_imported,
                    accepted_count: report.rules_approved
                        + report.rules_restricted
                        + report.hashes_imported,
                    rejected_count: report.rules_rejected,
                    last_error: Some(err_msg),
                    response_time_ms: report.duration_ms,
                    license_default: cfg.default_license.clone(),
                });
            }
        }

        report
    }

    fn sync_repo_inner(
        &self,
        db: &IntelDatabase,
        cfg: &GitRepoConfig,
        repo_dir: &Path,
        force_full_reimport: bool,
        report: &mut GitSyncReport,
    ) -> Result<()> {
        let is_existing = repo_dir.join(".git").exists();
        let prev_db_commit = db
            .get_source(&cfg.source_id)?
            .and_then(|s| s.last_commit);

        if !is_existing {
            info!("Clonando repositorio {} en {:?}...", cfg.url, repo_dir);
            Self::run_git(
                self.repos_root.as_path(),
                &["clone", "--depth", "1", &cfg.url, &cfg.source_id],
            )?;
            let head = Self::git_rev_parse_head(repo_dir)?;
            report.commit_after = Some(head);
            report.incremental = false;

            let all_files = Self::collect_repo_files(repo_dir);
            self.ingest_files(db, cfg, repo_dir, &all_files, report)?;
            return Ok(());
        }

        // Repositorio existente: actualización incremental
        let old_head = Self::git_rev_parse_head(repo_dir).ok();
        report.commit_before = old_head.clone().or(prev_db_commit.clone());

        Self::run_git(repo_dir, &["fetch", "--depth", "1", "origin"])?;
        // Detectar rama por defecto remota (origin/HEAD o origin/master o origin/main)
        let target_ref = Self::resolve_remote_head(repo_dir);
        Self::run_git(repo_dir, &["reset", "--hard", &target_ref])?;
        let new_head = Self::git_rev_parse_head(repo_dir)?;
        report.commit_after = Some(new_head.clone());

        if !force_full_reimport {
            if let Some(ref before) = report.commit_before {
                if before == &new_head {
                    report.incremental = true;
                    info!("Repositorio {} sin cambios en commit {}", cfg.name, new_head);
                    return Ok(());
                }

                // Intentar diff incremental entre before y new_head
                if let Ok(diff_out) = Self::run_git_capture(
                    repo_dir,
                    &["diff", "--name-status", before, &new_head],
                ) {
                    report.incremental = true;
                    let mut changed_files = Vec::new();
                    for line in diff_out.lines() {
                        let parts: Vec<&str> = line.split('\t').collect();
                        if parts.len() >= 2 {
                            let status = parts[0].trim();
                            let rel_path = parts[parts.len() - 1].trim();
                            if status.starts_with('D') {
                                let source_url =
                                    format!("{}/blob/HEAD/{}", cfg.url.trim_end_matches(".git"), rel_path);
                                let retired = db.mark_source_url_obsolete(&cfg.name, &source_url)?;
                                report.rules_retired += retired;
                                report.files_deleted += 1;
                            } else {
                                changed_files.push(repo_dir.join(rel_path));
                            }
                        }
                    }
                    self.ingest_files(db, cfg, repo_dir, &changed_files, report)?;
                    return Ok(());
                }
            }
        }

        // Fallback o reimportación completa
        report.incremental = false;
        let all_files = Self::collect_repo_files(repo_dir);
        self.ingest_files(db, cfg, repo_dir, &all_files, report)?;
        Ok(())
    }

    fn ingest_files(
        &self,
        db: &IntelDatabase,
        cfg: &GitRepoConfig,
        repo_dir: &Path,
        files: &[PathBuf],
        report: &mut GitSyncReport,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let base_url = cfg.url.trim_end_matches(".git");
        let mut seen_hashes_in_run: HashSet<String> = HashSet::new();

        for path in files {
            if !path.is_file() {
                continue;
            }
            let rel = path
                .strip_prefix(repo_dir)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            if rel.starts_with(".git/") || rel.contains("/.git/") {
                continue;
            }

            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();

            if cfg.ingest_yara && (ext == "yar" || ext == "yara") {
                // Evitar archivos de índice que solo contienen `include "..."`
                let Ok(content) = fs::read_to_string(path) else {
                    continue;
                };
                report.files_processed += 1;

                let category = Self::classify_category_from_path(&rel);
                let source_url = format!("{}/blob/HEAD/{}", base_url, rel);
                let parsed_rules = YaraRuleValidator::split_yara_file(&content, &cfg.default_license);

                for rule in parsed_rules {
                    report.rules_received += 1;
                    let id = IntelDatabase::compute_indicator_id(
                        IndicatorType::YaraRule,
                        &cfg.name,
                        &format!("{}::{}", rel, rule.rule_name),
                    );

                    let is_dup = db
                        .find_duplicate_by_content_hash(
                            IndicatorType::YaraRule,
                            &rule.content_hash,
                            &id,
                        )?
                        .is_some();

                    if is_dup {
                        report.rules_duplicates += 1;
                    }

                    let mut val = YaraRuleValidator::validate_rule(&rule, is_dup);
                    if !crate::licensing::LicensingAndManifestManager::is_commercial_production_allowed(&rule.license) {
                        val.status = ValidationStatus::Rechazada;
                        val.score = val.score.min(20);
                        val.notes = format!("{} | Licencia no comercial (CC BY-NC) bloqueada en producción", val.notes);
                    }
                    match val.status {
                        ValidationStatus::Laboratorio => report.rules_observation += 1,
                        ValidationStatus::Aprobada => report.rules_approved += 1,
                        ValidationStatus::AprobadaConRestricciones => report.rules_restricted += 1,
                        ValidationStatus::EnObservacion => report.rules_observation += 1,
                        ValidationStatus::Rechazada => report.rules_rejected += 1,
                        ValidationStatus::Obsoleta => report.rules_retired += 1,
                    }

                    let rec = ThreatIndicatorRecord {
                        id,
                        indicator_type: IndicatorType::YaraRule,
                        value: rule.rule_name.clone(),
                        payload: rule.raw_source,
                        content_hash: rule.content_hash,
                        malware_family: rule.malware_family,
                        threat_name: rule.threat_name,
                        category: category.clone(),
                        source_name: cfg.name.clone(),
                        repo_origin: cfg.name.clone(),
                        rule_author: rule.author,
                        license: rule.license,
                        source_url: source_url.clone(),
                        first_seen: now.clone(),
                        last_modified: now.clone(),
                        expires_at: None,
                        confidence: val.score,
                        validation_status: val.status,
                        validation_score: val.score,
                        validation_notes: val.notes,
                        version: 1,
                        external_vars: val.external_vars,
                        required_modules: val.required_modules,
                    };
                    let _ = db.upsert_indicator(&rec)?;
                }
            } else if cfg.ingest_hash_iocs && rel.starts_with("iocs/") && ext == "txt" {
                let Ok(content) = fs::read_to_string(path) else {
                    continue;
                };
                report.files_processed += 1;
                let source_url = format!("{}/blob/HEAD/{}", base_url, rel);

                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    let split = trimmed.split_once(';').or_else(|| trimmed.split_once(':'));
                    if let Some((hash_raw, desc_raw)) = split {
                        let hash = hash_raw.trim().to_ascii_lowercase();
                        let desc = desc_raw.trim();
                        if hash.len() == 64
                            && hash.bytes().all(|b| b.is_ascii_hexdigit())
                            && !desc.is_empty()
                            && seen_hashes_in_run.insert(hash.clone())
                        {
                            let id = IntelDatabase::compute_indicator_id(
                                IndicatorType::Sha256,
                                &cfg.name,
                                &hash,
                            );
                            let content_hash =
                                hex::encode(Sha256::digest(format!("{}:{}", hash, desc).as_bytes()));
                            let rec = ThreatIndicatorRecord {
                                id,
                                indicator_type: IndicatorType::Sha256,
                                value: hash,
                                payload: desc.to_string(),
                                content_hash,
                                malware_family: "MalwareIOC".to_string(),
                                threat_name: desc.to_string(),
                                category: "HashIOC".to_string(),
                                source_name: cfg.name.clone(),
                                repo_origin: cfg.name.clone(),
                                rule_author: "Neo23x0 / Community".to_string(),
                                license: cfg.default_license.clone(),
                                source_url: source_url.clone(),
                                first_seen: now.clone(),
                                last_modified: now.clone(),
                                expires_at: None,
                                confidence: 90,
                                validation_status: ValidationStatus::Aprobada,
                                validation_score: 90,
                                validation_notes: "Hash SHA-256 validado desde repositorio IOC".to_string(),
                                version: 1,
                                external_vars: Vec::new(),
                                required_modules: Vec::new(),
                            };
                            if db.upsert_indicator(&rec)? != UpsertOutcome::Unchanged {
                                report.hashes_imported += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Paquetes oficiales de YARA Forge y su entorno de destino
    pub fn sync_yara_forge(&self, db: &IntelDatabase) -> GitSyncReport {
        self.sync_yara_forge_package(db, YaraForgePackage::Core)
    }

    /// Descarga, extrae y valida un paquete específico de YARA Forge (`Core`, `Extended`, `Full`)
    pub fn sync_yara_forge_package(
        &self,
        db: &IntelDatabase,
        package: YaraForgePackage,
    ) -> GitSyncReport {
        let t0 = Instant::now();
        let (source_id, name, url) = match package {
            YaraForgePackage::Core => (
                "yara-forge-core",
                "YARAHQ/yara-forge (Core)",
                "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
            ),
            YaraForgePackage::Extended => (
                "yara-forge-extended",
                "YARAHQ/yara-forge (Extended)",
                "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip",
            ),
            YaraForgePackage::Full => (
                "yara-forge-full",
                "YARAHQ/yara-forge (Full)",
                "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip",
            ),
        };
        let mut report = GitSyncReport {
            source_id: source_id.to_string(),
            name: name.to_string(),
            ..Default::default()
        };

        let res = (|| -> Result<()> {
            let resp = ureq::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("SamuLibre-ThreatIntel/2.0")
                .build()
                .get(url)
                .call()
                .map_err(|e| anyhow!("Error descargando YARA Forge: {}", e))?;

            let mut bytes = Vec::new();
            resp.into_reader().read_to_end(&mut bytes)?;
            let mut archive = zip::ZipArchive::new(Cursor::new(bytes))?;
            let now = Utc::now().to_rfc3339();

            for idx in 0..archive.len() {
                let mut entry = archive.by_index(idx)?;
                let entry_name = entry.name()?.to_string();
                if !entry_name.ends_with(".yar") && !entry_name.ends_with(".yara") {
                    continue;
                }
                let mut content = String::new();
                entry.read_to_string(&mut content)?;
                report.files_processed += 1;

                let parsed_rules =
                    YaraRuleValidator::split_yara_file(&content, "Detection Rule License / Mixed");
                for rule in parsed_rules {
                    report.rules_received += 1;
                    let id = IntelDatabase::compute_indicator_id(
                        IndicatorType::YaraRule,
                        name,
                        &format!("{}::{}", entry_name, rule.rule_name),
                    );
                    let is_dup = db
                        .find_duplicate_by_content_hash(
                            IndicatorType::YaraRule,
                            &rule.content_hash,
                            &id,
                        )?
                        .is_some();
                    if is_dup {
                        report.rules_duplicates += 1;
                    }
                    let mut val = YaraRuleValidator::validate_rule(&rule, is_dup);
                    if !crate::licensing::LicensingAndManifestManager::is_commercial_production_allowed(&rule.license) {
                        val.status = ValidationStatus::Rechazada;
                        val.score = val.score.min(20);
                        val.notes = format!("{} | Licencia no comercial (CC BY-NC) bloqueada en producción", val.notes);
                    } else if matches!(val.status, ValidationStatus::Aprobada | ValidationStatus::AprobadaConRestricciones) {
                        match package {
                            YaraForgePackage::Core => {}
                            YaraForgePackage::Extended => {
                                val.status = ValidationStatus::EnObservacion;
                                val.notes = format!("{} | YARA Forge Extended: en evaluación antes de producción", val.notes);
                            }
                            YaraForgePackage::Full => {
                                val.status = ValidationStatus::Laboratorio;
                                val.notes = format!("{} | YARA Forge Full: retenida en laboratorio hasta superar pruebas de rendimiento y FP", val.notes);
                            }
                        }
                    }
                    match val.status {
                        ValidationStatus::Laboratorio => report.rules_observation += 1,
                        ValidationStatus::Aprobada => report.rules_approved += 1,
                        ValidationStatus::AprobadaConRestricciones => report.rules_restricted += 1,
                        ValidationStatus::EnObservacion => report.rules_observation += 1,
                        ValidationStatus::Rechazada => report.rules_rejected += 1,
                        ValidationStatus::Obsoleta => report.rules_retired += 1,
                    }
                    let rec = ThreatIndicatorRecord {
                        id,
                        indicator_type: IndicatorType::YaraRule,
                        value: rule.rule_name.clone(),
                        payload: rule.raw_source,
                        content_hash: rule.content_hash,
                        malware_family: rule.malware_family,
                        threat_name: rule.threat_name,
                        category: "YARA-Forge".to_string(),
                        source_name: name.to_string(),
                        repo_origin: name.to_string(),
                        rule_author: rule.author,
                        license: rule.license,
                        source_url: url.to_string(),
                        first_seen: now.clone(),
                        last_modified: now.clone(),
                        expires_at: None,
                        confidence: val.score,
                        validation_status: val.status,
                        validation_score: val.score,
                        validation_notes: val.notes,
                        version: 1,
                        external_vars: val.external_vars,
                        required_modules: val.required_modules,
                    };
                    let _ = db.upsert_indicator(&rec)?;
                }
            }
            Ok(())
        })();

        report.duration_ms = t0.elapsed().as_millis() as u64;
        let now = Utc::now().to_rfc3339();
        match res {
            Ok(_) => {
                report.success = true;
                let _ = db.upsert_source(&IntelSource {
                    source_id: source_id.to_string(),
                    name: name.to_string(),
                    source_kind: "release_yara".to_string(),
                    url: url.to_string(),
                    last_sync_at: Some(now),
                    last_commit: None,
                    status: "OK".to_string(),
                    received_count: report.rules_received,
                    accepted_count: report.rules_approved + report.rules_restricted,
                    rejected_count: report.rules_rejected,
                    last_error: None,
                    response_time_ms: report.duration_ms,
                    license_default: "Mixed (DRL/GPL/MIT per rule)".to_string(),
                });
            }
            Err(e) => {
                report.success = false;
                report.error = Some(e.to_string());
                let _ = db.upsert_source(&IntelSource {
                    source_id: source_id.to_string(),
                    name: name.to_string(),
                    source_kind: "release_yara".to_string(),
                    url: url.to_string(),
                    last_sync_at: Some(now),
                    last_commit: None,
                    status: "ERROR".to_string(),
                    received_count: 0,
                    accepted_count: 0,
                    rejected_count: 0,
                    last_error: report.error.clone(),
                    response_time_ms: report.duration_ms,
                    license_default: "Mixed".to_string(),
                });
            }
        }
        report
    }

    /// Verifica e ingiere reglas públicas de Malpedia Signator (TLP:WHITE / TLP:GREEN si disponible sin auth)
    pub fn sync_malpedia_signator(&self, db: &IntelDatabase) -> GitSyncReport {
        let t0 = Instant::now();
        let source_id = "malpedia-signator";
        let name = "Malpedia Signator Rules";
        let url = "https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/tlp_white";
        let mut report = GitSyncReport {
            source_id: source_id.to_string(),
            name: name.to_string(),
            ..Default::default()
        };

        let res = (|| -> Result<()> {
            let resp = ureq::builder()
                .timeout(Duration::from_secs(15))
                .user_agent("SamuLibre-ThreatIntel/2.0")
                .build()
                .get(url)
                .call()
                .map_err(|e| anyhow!("Malpedia requiere autenticación o no está disponible: {}", e))?;

            let body = resp.into_string()?;
            let now = Utc::now().to_rfc3339();
            let parsed_rules = YaraRuleValidator::split_yara_file(&body, "TLP:WHITE / Malpedia");
            report.files_processed = 1;

            for rule in parsed_rules {
                report.rules_received += 1;
                let id = IntelDatabase::compute_indicator_id(
                    IndicatorType::YaraRule,
                    name,
                    &rule.rule_name,
                );
                let is_dup = db
                    .find_duplicate_by_content_hash(
                        IndicatorType::YaraRule,
                        &rule.content_hash,
                        &id,
                    )?
                    .is_some();
                if is_dup {
                    report.rules_duplicates += 1;
                }
                let val = YaraRuleValidator::validate_rule(&rule, is_dup);
                match val.status {
                    ValidationStatus::Laboratorio => report.rules_observation += 1,
                    ValidationStatus::Aprobada => report.rules_approved += 1,
                    ValidationStatus::AprobadaConRestricciones => report.rules_restricted += 1,
                    ValidationStatus::EnObservacion => report.rules_observation += 1,
                    ValidationStatus::Rechazada => report.rules_rejected += 1,
                    ValidationStatus::Obsoleta => report.rules_retired += 1,
                }
                let rec = ThreatIndicatorRecord {
                    id,
                    indicator_type: IndicatorType::YaraRule,
                    value: rule.rule_name.clone(),
                    payload: rule.raw_source,
                    content_hash: rule.content_hash,
                    malware_family: rule.malware_family,
                    threat_name: rule.threat_name,
                    category: "Malpedia".to_string(),
                    source_name: name.to_string(),
                    repo_origin: name.to_string(),
                    rule_author: rule.author,
                    license: rule.license,
                    source_url: url.to_string(),
                    first_seen: now.clone(),
                    last_modified: now.clone(),
                    expires_at: None,
                    confidence: val.score,
                    validation_status: val.status,
                    validation_score: val.score,
                    validation_notes: val.notes,
                    version: 1,
                    external_vars: val.external_vars,
                    required_modules: val.required_modules,
                };
                let _ = db.upsert_indicator(&rec)?;
            }
            Ok(())
        })();

        report.duration_ms = t0.elapsed().as_millis() as u64;
        let now = Utc::now().to_rfc3339();
        match res {
            Ok(_) => {
                report.success = true;
                let _ = db.upsert_source(&IntelSource {
                    source_id: source_id.to_string(),
                    name: name.to_string(),
                    source_kind: "api_yara".to_string(),
                    url: url.to_string(),
                    last_sync_at: Some(now),
                    last_commit: None,
                    status: "OK".to_string(),
                    received_count: report.rules_received,
                    accepted_count: report.rules_approved + report.rules_restricted,
                    rejected_count: report.rules_rejected,
                    last_error: None,
                    response_time_ms: report.duration_ms,
                    license_default: "TLP:WHITE / Malpedia Terms".to_string(),
                });
            }
            Err(e) => {
                report.success = false;
                report.error = Some(e.to_string());
                let _ = db.upsert_source(&IntelSource {
                    source_id: source_id.to_string(),
                    name: name.to_string(),
                    source_kind: "api_yara".to_string(),
                    url: url.to_string(),
                    last_sync_at: Some(now),
                    last_commit: None,
                    status: "ERROR".to_string(),
                    received_count: 0,
                    accepted_count: 0,
                    rejected_count: 0,
                    last_error: report.error.clone(),
                    response_time_ms: report.duration_ms,
                    license_default: "Malpedia Restricted".to_string(),
                });
            }
        }
        report
    }

    /// Sincroniza un repositorio de comportamiento (Sigma / Elastic / LOLDrivers) sin convertir a YARA
    pub fn sync_behavior_repo(
        &self,
        db: &IntelDatabase,
        cfg: &GitRepoConfig,
        max_files: usize,
    ) -> GitSyncReport {
        let t0 = Instant::now();
        let mut report = GitSyncReport {
            source_id: cfg.source_id.clone(),
            name: cfg.name.clone(),
            ..Default::default()
        };
        let repo_dir = self.repos_root.join(&cfg.source_id);
        let _ = fs::create_dir_all(&self.repos_root);

        let res = (|| -> Result<()> {
            if !repo_dir.join(".git").exists() {
                Self::run_git(
                    self.repos_root.as_path(),
                    &["clone", "--depth", "1", &cfg.url, &cfg.source_id],
                )?;
            } else {
                Self::run_git(&repo_dir, &["fetch", "--depth", "1", "origin"])?;
                let target_ref = Self::resolve_remote_head(&repo_dir);
                Self::run_git(&repo_dir, &["reset", "--hard", &target_ref])?;
                report.incremental = true;
            }
            report.commit_after = Self::git_rev_parse_head(&repo_dir).ok();

            let adapter_rep = BehaviorRuleAdapter::ingest_behavior_repo(
                db,
                &cfg.name,
                &cfg.url,
                &cfg.default_license,
                &repo_dir,
                max_files,
            )?;
            report.rules_received = adapter_rep.total_parsed;
            report.rules_approved = adapter_rep.compatible_approved;
            report.rules_observation = adapter_rep.reference_incompatible;
            report.rules_rejected = adapter_rep.rejected_parse_error;
            Ok(())
        })();

        report.duration_ms = t0.elapsed().as_millis() as u64;
        let now = Utc::now().to_rfc3339();
        match res {
            Ok(_) => {
                report.success = true;
                let _ = db.upsert_source(&IntelSource {
                    source_id: cfg.source_id.clone(),
                    name: cfg.name.clone(),
                    source_kind: "git_behavior".to_string(),
                    url: cfg.url.clone(),
                    last_sync_at: Some(now),
                    last_commit: report.commit_after.clone(),
                    status: "OK".to_string(),
                    received_count: report.rules_received,
                    accepted_count: report.rules_approved,
                    rejected_count: report.rules_rejected,
                    last_error: None,
                    response_time_ms: report.duration_ms,
                    license_default: cfg.default_license.clone(),
                });
            }
            Err(e) => {
                report.success = false;
                report.error = Some(e.to_string());
                let _ = db.upsert_source(&IntelSource {
                    source_id: cfg.source_id.clone(),
                    name: cfg.name.clone(),
                    source_kind: "git_behavior".to_string(),
                    url: cfg.url.clone(),
                    last_sync_at: Some(now),
                    last_commit: report.commit_after.clone(),
                    status: "ERROR".to_string(),
                    received_count: 0,
                    accepted_count: 0,
                    rejected_count: 0,
                    last_error: report.error.clone(),
                    response_time_ms: report.duration_ms,
                    license_default: cfg.default_license.clone(),
                });
            }
        }
        report
    }

    fn classify_category_from_path(rel: &str) -> String {
        let lower = rel.to_ascii_lowercase();
        if lower.contains("ransom") {
            "Ransomware"
        } else if lower.contains("webshell") {
            "Webshell"
        } else if lower.contains("exploit") || lower.contains("cve") {
            "Exploit"
        } else if lower.contains("apt") {
            "APT"
        } else if lower.contains("packer") {
            "Packer"
        } else if lower.contains("rat") {
            "RAT"
        } else if lower.contains("malware") || lower.contains("malw_") {
            "Malware"
        } else if lower.contains("hacktool") || lower.contains("gen_") {
            "HackTool/Generic"
        } else {
            "Detection"
        }
        .to_string()
    }

    fn collect_repo_files(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(curr) = stack.pop() {
            if let Ok(entries) = fs::read_dir(&curr) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.file_name().and_then(|s| s.to_str()) == Some(".git") {
                        continue;
                    }
                    if p.is_dir() {
                        stack.push(p);
                    } else {
                        out.push(p);
                    }
                }
            }
        }
        out
    }

    fn run_git(cwd: &Path, args: &[&str]) -> Result<()> {
        let output = Command::new("git")
            .current_dir(cwd)
            .env("GIT_LFS_SKIP_SMUDGE", "1")
            .args(args)
            .output()
            .with_context(|| format!("Error ejecutando git {:?}", args))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git {:?} falló: {}", args, stderr.trim()));
        }
        Ok(())
    }

    fn run_git_capture(cwd: &Path, args: &[&str]) -> Result<String> {
        let output = Command::new("git")
            .current_dir(cwd)
            .env("GIT_LFS_SKIP_SMUDGE", "1")
            .args(args)
            .output()
            .with_context(|| format!("Error ejecutando git {:?}", args))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git {:?} falló: {}", args, stderr.trim()));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn git_rev_parse_head(repo_dir: &Path) -> Result<String> {
        let out = Self::run_git_capture(repo_dir, &["rev-parse", "HEAD"])?;
        Ok(out.trim().to_string())
    }

    fn resolve_remote_head(repo_dir: &Path) -> String {
        for candidate in ["origin/HEAD", "origin/master", "origin/main"] {
            if Self::run_git_capture(repo_dir, &["rev-parse", "--verify", candidate]).is_ok() {
                return candidate.to_string();
            }
        }
        "HEAD".to_string()
    }
}
