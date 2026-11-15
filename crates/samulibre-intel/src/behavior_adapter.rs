use crate::db::IntelDatabase;
use crate::models::{IndicatorType, ThreatIndicatorRecord, ValidationStatus};
use anyhow::Result;
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Categoría interna de detección de comportamiento de SamuLibre
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamuBehaviorCategory {
    ProcessCreation,
    PowerShellScript,
    RegistryPersistence,
    RansomwareBehavior,
    LolbinAbuse,
    DriverLoad,
    NetworkActivity,
    DefenseEvasion,
    UnsupportedReference,
}

/// Representación interna normalizada de una regla de comportamiento (Sigma / Elastic / LOLDrivers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamuBehaviorRule {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub source_format: String, // "sigma" | "elastic_toml" | "loldrivers"
    pub category: SamuBehaviorCategory,
    pub level: String,
    pub mitre_techniques: Vec<String>,
    pub compatible_with_samulibre: bool,
    pub incompatibility_reason: Option<String>,
    pub image_patterns: Vec<String>,
    pub cmdline_patterns: Vec<String>,
    pub registry_patterns: Vec<String>,
    pub script_patterns: Vec<String>,
    pub driver_sha256: Vec<String>,
}

/// Estadísticas de conversión del adaptador de comportamiento
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BehaviorAdapterReport {
    pub total_parsed: usize,
    pub compatible_approved: usize,
    pub reference_incompatible: usize,
    pub rejected_parse_error: usize,
}

/// Adaptador independiente para SigmaHQ, Elastic Detection Rules y LOLDrivers
/// (NO convierte reglas Sigma/Elastic a YARA; traduce a SamuBehaviorRule y documenta incompatibilidades)
pub struct BehaviorRuleAdapter;

impl BehaviorRuleAdapter {
    /// Parsea una regla Sigma (`.yml` / `.yaml`) y la adapta a `SamuBehaviorRule`
    pub fn parse_sigma_yaml(content: &str, file_rel_path: &str) -> Option<SamuBehaviorRule> {
        let title = Self::extract_yaml_scalar(content, "title")?;
        let id = Self::extract_yaml_scalar(content, "id")
            .unwrap_or_else(|| format!("sigma:{}", file_rel_path));
        let description = Self::extract_yaml_scalar(content, "description")
            .unwrap_or_else(|| title.clone());
        let level = Self::extract_yaml_scalar(content, "level")
            .unwrap_or_else(|| "medium".to_string());

        let product = Self::extract_yaml_scalar(content, "product")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let log_cat = Self::extract_yaml_scalar(content, "category")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let service = Self::extract_yaml_scalar(content, "service")
            .unwrap_or_default()
            .to_ascii_lowercase();

        let mitre_re = Regex::new(r"(?i)attack\.(t\d{4}(?:\.\d{3})?)").unwrap();
        let mut mitre_techniques = Vec::new();
        for cap in mitre_re.captures_iter(content) {
            let t = cap[1].to_ascii_uppercase();
            if !mitre_techniques.contains(&t) {
                mitre_techniques.push(t);
            }
        }

        let lower = content.to_ascii_lowercase();
        let has_unsupported_condition = lower.contains("| count(")
            || lower.contains("| near ")
            || lower.contains("timeframe:");

        let (category, compatible, incomp_reason) = if !product.is_empty() && product != "windows" {
            (
                SamuBehaviorCategory::UnsupportedReference,
                false,
                Some(format!("Producto '{}' fuera del alcance Windows EDR de SamuLibre", product)),
            )
        } else if has_unsupported_condition {
            (
                SamuBehaviorCategory::UnsupportedReference,
                false,
                Some("Condición Sigma temporal/agregación (timeframe/count/near) no soportada aún en motor local".to_string()),
            )
        } else {
            match log_cat.as_str() {
                "process_creation" => {
                    let cat = if lower.contains("vssadmin")
                        || lower.contains("ransom")
                        || lower.contains("shadowcopy")
                    {
                        SamuBehaviorCategory::RansomwareBehavior
                    } else if lower.contains("certutil")
                        || lower.contains("mshta")
                        || lower.contains("regsvr32")
                        || lower.contains("rundll32")
                    {
                        SamuBehaviorCategory::LolbinAbuse
                    } else if lower.contains("amsi") || lower.contains("etw") || lower.contains("evasion") {
                        SamuBehaviorCategory::DefenseEvasion
                    } else {
                        SamuBehaviorCategory::ProcessCreation
                    };
                    (cat, true, None)
                }
                "ps_script" | "ps_classic_start" | "ps_module" => {
                    (SamuBehaviorCategory::PowerShellScript, true, None)
                }
                "registry_set" | "registry_event" | "registry_add" => {
                    (SamuBehaviorCategory::RegistryPersistence, true, None)
                }
                "driver_load" => (SamuBehaviorCategory::DriverLoad, true, None),
                "network_connection" | "dns_query" => {
                    (SamuBehaviorCategory::NetworkActivity, true, None)
                }
                _ if service == "powershell" || service == "powershell-classic" => {
                    (SamuBehaviorCategory::PowerShellScript, true, None)
                }
                _ => (
                    SamuBehaviorCategory::UnsupportedReference,
                    false,
                    Some(format!(
                        "Logsource Sigma (category='{}', service='{}') no soportado por sensores actuales de SamuLibre",
                        log_cat, service
                    )),
                ),
            }
        };

        let image_patterns = Self::extract_yaml_field_values(content, &["Image", "OriginalFileName"]);
        let cmdline_patterns = Self::extract_yaml_field_values(content, &["CommandLine", "ParentCommandLine"]);
        let registry_patterns = Self::extract_yaml_field_values(content, &["TargetObject", "Details"]);
        let script_patterns = Self::extract_yaml_field_values(content, &["ScriptBlockText"]);

        Some(SamuBehaviorRule {
            rule_id: id,
            title,
            description,
            source_format: "sigma".to_string(),
            category,
            level,
            mitre_techniques,
            compatible_with_samulibre: compatible,
            incompatibility_reason: incomp_reason,
            image_patterns,
            cmdline_patterns,
            registry_patterns,
            script_patterns,
            driver_sha256: Vec::new(),
        })
    }

    /// Parsea una regla de detección de Elastic (`.toml`)
    pub fn parse_elastic_toml(content: &str, file_rel_path: &str) -> Option<SamuBehaviorRule> {
        let title = Self::extract_toml_scalar(content, "name")?;
        let rule_id = Self::extract_toml_scalar(content, "rule_id")
            .unwrap_or_else(|| format!("elastic:{}", file_rel_path));
        let description = Self::extract_toml_scalar(content, "description")
            .unwrap_or_else(|| title.clone());
        let level = Self::extract_toml_scalar(content, "severity")
            .unwrap_or_else(|| "medium".to_string());
        let rule_type = Self::extract_toml_scalar(content, "type")
            .unwrap_or_else(|| "query".to_string())
            .to_ascii_lowercase();
        let query = Self::extract_toml_scalar(content, "query").unwrap_or_default();

        let mitre_re = Regex::new(r#"\b(T\d{4}(?:\.\d{3})?)\b"#).unwrap();
        let mut mitre_techniques = Vec::new();
        for cap in mitre_re.captures_iter(content) {
            let t = cap[1].to_string();
            if !mitre_techniques.contains(&t) {
                mitre_techniques.push(t);
            }
        }

        let lower = content.to_ascii_lowercase();
        let is_windows = lower.contains("windows") || file_rel_path.to_ascii_lowercase().contains("windows");

        let (category, compatible, incomp_reason) = if !is_windows {
            (
                SamuBehaviorCategory::UnsupportedReference,
                false,
                Some("Regla Elastic no orientada a Windows".to_string()),
            )
        } else if rule_type == "eql" || rule_type == "threshold" || rule_type == "machine_learning" {
            (
                SamuBehaviorCategory::UnsupportedReference,
                false,
                Some(format!(
                    "Tipo de regla Elastic '{}' (secuencias EQL/ML/umbral) conservado solo como referencia",
                    rule_type
                )),
            )
        } else if query.to_ascii_lowercase().contains("process.") {
            (SamuBehaviorCategory::ProcessCreation, true, None)
        } else if query.to_ascii_lowercase().contains("registry.") {
            (SamuBehaviorCategory::RegistryPersistence, true, None)
        } else if query.to_ascii_lowercase().contains("powershell.") {
            (SamuBehaviorCategory::PowerShellScript, true, None)
        } else {
            (
                SamuBehaviorCategory::UnsupportedReference,
                false,
                Some("Consulta KQL/Lucene Elastic depende de campos de telemetría no mapeados aún".to_string()),
            )
        };

        Some(SamuBehaviorRule {
            rule_id,
            title,
            description,
            source_format: "elastic_toml".to_string(),
            category,
            level,
            mitre_techniques,
            compatible_with_samulibre: compatible,
            incompatibility_reason: incomp_reason,
            image_patterns: Vec::new(),
            cmdline_patterns: if compatible && !query.is_empty() {
                vec![query]
            } else {
                Vec::new()
            },
            registry_patterns: Vec::new(),
            script_patterns: Vec::new(),
            driver_sha256: Vec::new(),
        })
    }

    /// Ingesta reglas desde repositorios Sigma / Elastic / LOLDrivers hacia SQLite
    pub fn ingest_behavior_repo(
        db: &IntelDatabase,
        repo_name: &str,
        repo_url: &str,
        default_license: &str,
        repo_dir: &Path,
        max_files: usize,
    ) -> Result<BehaviorAdapterReport> {
        let mut report = BehaviorAdapterReport::default();
        let now = Utc::now().to_rfc3339();
        let base_url = repo_url.trim_end_matches(".git");
        let is_loldrivers = repo_name.to_ascii_lowercase().contains("loldrivers");

        let mut files = Vec::new();
        Self::collect_files(repo_dir, &mut files);

        for path in files.into_iter().take(max_files) {
            let rel = path
                .strip_prefix(repo_dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let ext = path
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();

            if is_loldrivers && ext == "yaml" && rel.starts_with("yaml/") {
                if let Ok(content) = fs::read_to_string(&path) {
                    Self::ingest_loldriver_yaml(db, repo_name, base_url, default_license, &rel, &content, &now, &mut report)?;
                }
                continue;
            }

            let parsed = if ext == "yml" || ext == "yaml" {
                fs::read_to_string(&path)
                    .ok()
                    .and_then(|c| Self::parse_sigma_yaml(&c, &rel))
            } else if ext == "toml" {
                fs::read_to_string(&path)
                    .ok()
                    .and_then(|c| Self::parse_elastic_toml(&c, &rel))
            } else {
                None
            };

            let Some(rule) = parsed else {
                continue;
            };
            report.total_parsed += 1;

            let (status, score, notes) = if rule.compatible_with_samulibre {
                report.compatible_approved += 1;
                if default_license.contains("Elastic") {
                    (
                        ValidationStatus::AprobadaConRestricciones,
                        75u8,
                        "Compatible; sujeta a revisión de licencia Elastic v2 para distribución comercial".to_string(),
                    )
                } else {
                    (
                        ValidationStatus::Aprobada,
                        88u8,
                        "Regla de comportamiento adaptada y compatible con SamuLibre Windows EDR".to_string(),
                    )
                }
            } else {
                report.reference_incompatible += 1;
                (
                    ValidationStatus::EnObservacion,
                    40u8,
                    rule.incompatibility_reason
                        .clone()
                        .unwrap_or_else(|| "Conservada como referencia".to_string()),
                )
            };

            let payload = serde_json::to_string(&rule)?;
            let content_hash = hex::encode(Sha256::digest(payload.as_bytes()));
            let id = IntelDatabase::compute_indicator_id(
                IndicatorType::BehaviorRule,
                repo_name,
                &rule.rule_id,
            );
            let rec = ThreatIndicatorRecord {
                id,
                indicator_type: IndicatorType::BehaviorRule,
                value: rule.title.clone(),
                payload,
                content_hash,
                malware_family: rule.mitre_techniques.join(","),
                threat_name: rule.title,
                category: format!("{:?}", rule.category),
                source_name: repo_name.to_string(),
                repo_origin: repo_name.to_string(),
                rule_author: "Community".to_string(),
                license: default_license.to_string(),
                source_url: format!("{}/blob/HEAD/{}", base_url, rel),
                first_seen: now.clone(),
                last_modified: now.clone(),
                expires_at: None,
                confidence: score,
                validation_status: status,
                validation_score: score,
                validation_notes: notes,
                version: 1,
                external_vars: Vec::new(),
                required_modules: Vec::new(),
            };
            let _ = db.upsert_indicator(&rec)?;
        }

        Ok(report)
    }

    fn ingest_loldriver_yaml(
        db: &IntelDatabase,
        repo_name: &str,
        base_url: &str,
        default_license: &str,
        rel: &str,
        content: &str,
        now: &str,
        report: &mut BehaviorAdapterReport,
    ) -> Result<()> {
        let sha_re = Regex::new(r"(?i)\bSHA256\s*:\s*([0-9a-f]{64})\b").unwrap();
        let category = Self::extract_yaml_scalar(content, "Category")
            .unwrap_or_else(|| "vulnerable driver".to_string());
        let id_str = Self::extract_yaml_scalar(content, "Id").unwrap_or_else(|| rel.to_string());

        for cap in sha_re.captures_iter(content) {
            let hash = cap[1].to_ascii_lowercase();
            report.total_parsed += 1;
            report.compatible_approved += 1;
            let id = IntelDatabase::compute_indicator_id(IndicatorType::Sha256, repo_name, &hash);
            let content_hash = hex::encode(Sha256::digest(format!("loldriver:{}", hash).as_bytes()));
            let rec = ThreatIndicatorRecord {
                id,
                indicator_type: IndicatorType::Sha256,
                value: hash,
                payload: format!("LOLDriver {} ({})", id_str, category),
                content_hash,
                malware_family: "BYOVD/VulnerableDriver".to_string(),
                threat_name: format!("Driver.{} ({})", category, rel),
                category: "DriverLoad".to_string(),
                source_name: repo_name.to_string(),
                repo_origin: repo_name.to_string(),
                rule_author: "LOLDrivers Community".to_string(),
                license: default_license.to_string(),
                source_url: format!("{}/blob/HEAD/{}", base_url, rel),
                first_seen: now.to_string(),
                last_modified: now.to_string(),
                expires_at: None,
                confidence: 92,
                validation_status: ValidationStatus::Aprobada,
                validation_score: 92,
                validation_notes: "Hash SHA-256 de driver vulnerable/malicioso (LOLDrivers)".to_string(),
                version: 1,
                external_vars: Vec::new(),
                required_modules: Vec::new(),
            };
            let _ = db.upsert_indicator(&rec)?;
        }
        Ok(())
    }

    fn extract_yaml_scalar(content: &str, key: &str) -> Option<String> {
        let pat = format!(r#"(?m)^\s*{}\s*:\s*['"]?([^'"\r\n]+)['"]?"#, regex::escape(key));
        let re = Regex::new(&pat).ok()?;
        re.captures(content).map(|c| c[1].trim().to_string())
    }

    fn extract_toml_scalar(content: &str, key: &str) -> Option<String> {
        let pat = format!(r#"(?m)^\s*{}\s*=\s*"([^"]*)""#, regex::escape(key));
        let re = Regex::new(&pat).ok()?;
        re.captures(content).map(|c| c[1].trim().to_string())
    }

    fn extract_yaml_field_values(content: &str, keys: &[&str]) -> Vec<String> {
        let mut out = Vec::new();
        for key in keys {
            let pat = format!(r#"(?m)^\s*{}(?:\|[a-zA-Z0-9_]+)*\s*:\s*['"]?([^'"\r\n]+)['"]?"#, regex::escape(key));
            if let Ok(re) = Regex::new(&pat) {
                for cap in re.captures_iter(content) {
                    let val = cap[1].trim().to_string();
                    if !val.is_empty() && val != "|" && !out.contains(&val) {
                        out.push(val);
                    }
                }
            }
        }
        out
    }

    fn collect_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.file_name().and_then(|s| s.to_str()) == Some(".git") {
                    continue;
                }
                if p.is_dir() {
                    Self::collect_files(&p, out);
                } else {
                    out.push(p);
                }
            }
        }
    }
}
