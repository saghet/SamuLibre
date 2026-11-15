use crate::db::{IntelDatabase, UpsertOutcome};
use crate::models::{IndicatorType, IntelSource, ThreatIndicatorRecord, ValidationStatus};
use crate::yara_engine::YaraRuleValidator;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

/// Configuración de un conector independiente de Threat Intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConnectorConfig {
    pub source_id: String,
    pub name: String,
    pub url: String,
    pub license: String,
    pub requires_api_key: bool,
    pub api_key_env_var: Option<String>,
    pub rate_limit_seconds: u64,
}

/// Reporte de ejecución de un conector API/Feed
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedSyncReport {
    pub source_id: String,
    pub name: String,
    pub success: bool,
    pub status: String,
    pub received: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub response_time_ms: u64,
    pub error: Option<String>,
}

/// Estado enmascarado de las API Keys de Threat Intelligence (nunca expone claves en texto plano)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntelKeysStatus {
    pub abusech_configured: bool,
    pub abusech_masked: String,
    pub abusech_source: String,
    pub otx_configured: bool,
    pub otx_masked: String,
    pub otx_source: String,
}

/// Conectores independientes de Threat Intelligence (Abuse.ch, AlienVault OTX, ClamAV)
pub struct ThreatFeedConnectors;

impl ThreatFeedConnectors {
    pub fn all_connectors() -> Vec<FeedConnectorConfig> {
        vec![
            FeedConnectorConfig {
                source_id: "abusech-malwarebazaar".to_string(),
                name: "Abuse.ch MalwareBazaar (Recent SHA-256)".to_string(),
                url: "https://mb-api.abuse.ch/api/v1/".to_string(),
                license: "CC0 1.0 Universal".to_string(),
                requires_api_key: true,
                api_key_env_var: Some("SAMULIBRE_ABUSECH_AUTH_KEY".to_string()),
                rate_limit_seconds: 900,
            },
            FeedConnectorConfig {
                source_id: "abusech-threatfox".to_string(),
                name: "Abuse.ch ThreatFox (Recent IOCs)".to_string(),
                url: "https://threatfox-api.abuse.ch/api/v1/".to_string(),
                license: "CC0 1.0 Universal".to_string(),
                requires_api_key: true,
                api_key_env_var: Some("SAMULIBRE_ABUSECH_AUTH_KEY".to_string()),
                rate_limit_seconds: 900,
            },
            FeedConnectorConfig {
                source_id: "abusech-urlhaus".to_string(),
                name: "Abuse.ch URLhaus (Recent Malware URLs)".to_string(),
                url: "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/500/".to_string(),
                license: "CC0 1.0 Universal".to_string(),
                requires_api_key: true,
                api_key_env_var: Some("SAMULIBRE_ABUSECH_AUTH_KEY".to_string()),
                rate_limit_seconds: 900,
            },
            FeedConnectorConfig {
                source_id: "abusech-feodotracker".to_string(),
                name: "Abuse.ch Feodo Tracker (Botnet C2 IPs)".to_string(),
                url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".to_string(),
                license: "CC0 1.0 Universal".to_string(),
                requires_api_key: false,
                api_key_env_var: None,
                rate_limit_seconds: 1800,
            },
            FeedConnectorConfig {
                source_id: "abusech-yaraify".to_string(),
                name: "Abuse.ch YARAify (YARAHub Public Rules)".to_string(),
                url: "https://yaraify-api.abuse.ch/api/v1/".to_string(),
                license: "CC0 1.0 / YARAHub".to_string(),
                requires_api_key: false,
                api_key_env_var: Some("SAMULIBRE_ABUSECH_AUTH_KEY".to_string()),
                rate_limit_seconds: 3600,
            },
            FeedConnectorConfig {
                source_id: "alienvault-otx".to_string(),
                name: "AlienVault OTX (Subscribed Pulses)".to_string(),
                url: "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50".to_string(),
                license: "OTX Terms / Open Threat Exchange".to_string(),
                requires_api_key: true,
                api_key_env_var: Some("SAMULIBRE_OTX_API_KEY".to_string()),
                rate_limit_seconds: 1800,
            },
            FeedConnectorConfig {
                source_id: "clamav-community".to_string(),
                name: "ClamAV Hash Signatures (.hdb/.hsb)".to_string(),
                url: "local://data/signatures/clamav/".to_string(),
                license: "GPL-2.0".to_string(),
                requires_api_key: false,
                api_key_env_var: None,
                rate_limit_seconds: 3600,
            },
        ]
    }

    /// Enmascara una API Key dejando solo los últimos 4 caracteres visibles
    pub fn mask_api_key(key: &str) -> String {
        let trimmed = key.trim();
        let chars: Vec<char> = trimmed.chars().collect();
        if chars.len() >= 8 {
            let tail: String = chars[chars.len() - 4..].iter().collect();
            format!("****{}", tail)
        } else if !chars.is_empty() {
            "****".to_string()
        } else {
            String::new()
        }
    }

    /// Lee la API Key de forma segura (variable de entorno o archivo seguro), sin exponerla en logs
    pub fn resolve_api_key(env_var: Option<&str>, source_id: &str) -> Option<String> {
        Self::resolve_api_key_at(
            env_var,
            source_id,
            &Path::new("data").join("secure").join("intel_keys.json"),
        )
    }

    /// Lee la API Key desde variable de entorno o ruta explícita de `intel_keys.json`
    pub fn resolve_api_key_at(
        env_var: Option<&str>,
        source_id: &str,
        key_file: &Path,
    ) -> Option<String> {
        if let Some(var) = env_var {
            if let Ok(val) = std::env::var(var) {
                let trimmed = val.trim().to_string();
                if !trimmed.is_empty() {
                    return Some(trimmed);
                }
            }
        }
        if key_file.exists() {
            if let Ok(content) = fs::read_to_string(key_file) {
                let clean = content.trim_start_matches('\u{FEFF}');
                if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(clean) {
                    if let Some(k) = map.get(source_id) {
                        let trimmed = k.trim().to_string();
                        if !trimmed.is_empty() {
                            return Some(trimmed);
                        }
                    }
                    if let Some(var) = env_var {
                        if let Some(k) = map.get(var) {
                            let trimmed = k.trim().to_string();
                            if !trimmed.is_empty() {
                                return Some(trimmed);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Devuelve el estado enmascarado de las API Keys configuradas (sin exponer secretos)
    pub fn get_intel_keys_status(key_file: &Path) -> IntelKeysStatus {
        let mut status = IntelKeysStatus {
            abusech_source: "none".to_string(),
            otx_source: "none".to_string(),
            ..Default::default()
        };

        if let Ok(v) = std::env::var("SAMULIBRE_ABUSECH_AUTH_KEY") {
            let t = v.trim();
            if !t.is_empty() {
                status.abusech_configured = true;
                status.abusech_masked = Self::mask_api_key(t);
                status.abusech_source = "env".to_string();
            }
        }
        if !status.abusech_configured {
            if let Some(k) = Self::resolve_api_key_at(
                Some("SAMULIBRE_ABUSECH_AUTH_KEY"),
                "abusech-malwarebazaar",
                key_file,
            ) {
                status.abusech_configured = true;
                status.abusech_masked = Self::mask_api_key(&k);
                status.abusech_source = "vault".to_string();
            }
        }

        if let Ok(v) = std::env::var("SAMULIBRE_OTX_API_KEY") {
            let t = v.trim();
            if !t.is_empty() {
                status.otx_configured = true;
                status.otx_masked = Self::mask_api_key(t);
                status.otx_source = "env".to_string();
            }
        }
        if !status.otx_configured {
            if let Some(k) = Self::resolve_api_key_at(
                Some("SAMULIBRE_OTX_API_KEY"),
                "alienvault-otx",
                key_file,
            ) {
                status.otx_configured = true;
                status.otx_masked = Self::mask_api_key(&k);
                status.otx_source = "vault".to_string();
            }
        }

        status
    }

    /// Guarda de forma segura las API Keys en `data/secure/intel_keys.json` sin sobrescribir claves existentes si se envía vacío
    pub fn save_intel_keys(
        key_file: &Path,
        abusech_key: Option<&str>,
        otx_key: Option<&str>,
    ) -> Result<IntelKeysStatus> {
        if let Some(parent) = key_file.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut map: HashMap<String, String> = if key_file.exists() {
            fs::read_to_string(key_file)
                .ok()
                .and_then(|c| serde_json::from_str::<HashMap<String, String>>(c.trim_start_matches('\u{FEFF}')).ok())
                .unwrap_or_default()
        } else {
            HashMap::new()
        };

        if let Some(k) = abusech_key.map(str::trim).filter(|s| !s.is_empty()) {
            map.insert("SAMULIBRE_ABUSECH_AUTH_KEY".to_string(), k.to_string());
            for id in [
                "abusech-malwarebazaar",
                "abusech-threatfox",
                "abusech-urlhaus",
                "abusech-yaraify",
            ] {
                map.insert(id.to_string(), k.to_string());
            }
        }

        if let Some(k) = otx_key.map(str::trim).filter(|s| !s.is_empty()) {
            map.insert("SAMULIBRE_OTX_API_KEY".to_string(), k.to_string());
            map.insert("alienvault-otx".to_string(), k.to_string());
        }

        let tmp_path = key_file.with_extension("json.tmp");
        let payload = serde_json::to_string_pretty(&map)?;
        fs::write(&tmp_path, payload)?;
        fs::rename(&tmp_path, key_file)?;

        Ok(Self::get_intel_keys_status(key_file))
    }

    /// Ejecuta un conector respetando límites de consulta (rate-limit) y registrando métricas reales
    pub fn sync_connector(
        db: &IntelDatabase,
        cfg: &FeedConnectorConfig,
        bypass_rate_limit: bool,
    ) -> FeedSyncReport {
        Self::sync_connector_with_key_file(
            db,
            cfg,
            bypass_rate_limit,
            &Path::new("data").join("secure").join("intel_keys.json"),
        )
    }

    /// Ejecuta un conector resolviendo claves desde `key_file`
    pub fn sync_connector_with_key_file(
        db: &IntelDatabase,
        cfg: &FeedConnectorConfig,
        bypass_rate_limit: bool,
        key_file: &Path,
    ) -> FeedSyncReport {
        let t0 = Instant::now();
        let mut report = FeedSyncReport {
            source_id: cfg.source_id.clone(),
            name: cfg.name.clone(),
            status: "ERROR".to_string(),
            ..Default::default()
        };

        // Control de límites de consultas (rate-limit)
        if !bypass_rate_limit {
            if let Ok(Some(prev)) = db.get_source(&cfg.source_id) {
                if prev.status == "OK" {
                    if let Some(ref ts) = prev.last_sync_at {
                        if let Ok(dt) = DateTime::parse_from_rfc3339(ts) {
                            let elapsed = (Utc::now() - dt.with_timezone(&Utc)).num_seconds();
                            if elapsed >= 0 && (elapsed as u64) < cfg.rate_limit_seconds {
                                report.success = true;
                                report.status = "RATE_LIMITED_SKIPPED".to_string();
                                report.response_time_ms = t0.elapsed().as_millis() as u64;
                                return report;
                            }
                        }
                    }
                }
            }
        }

        let api_key =
            Self::resolve_api_key_at(cfg.api_key_env_var.as_deref(), &cfg.source_id, key_file);
        if cfg.requires_api_key && api_key.is_none() {
            let msg = format!(
                "API Key requerida no configurada ({} o data/secure/intel_keys.json)",
                cfg.api_key_env_var.as_deref().unwrap_or("env")
            );
            report.status = "CONFIG_REQUIRED".to_string();
            report.error = Some(msg.clone());
            report.response_time_ms = t0.elapsed().as_millis() as u64;
            Self::save_source_state(db, cfg, &report);
            return report;
        }

        let res = match cfg.source_id.as_str() {
            "abusech-malwarebazaar" => Self::sync_malwarebazaar(db, cfg, api_key.as_deref(), &mut report),
            "abusech-threatfox" => Self::sync_threatfox(db, cfg, api_key.as_deref(), &mut report),
            "abusech-urlhaus" => Self::sync_urlhaus(db, cfg, api_key.as_deref(), &mut report),
            "abusech-feodotracker" => Self::sync_feodo(db, cfg, &mut report),
            "abusech-yaraify" => Self::sync_yaraify(db, cfg, api_key.as_deref(), &mut report),
            "alienvault-otx" => Self::sync_otx(db, cfg, api_key.as_deref().unwrap_or_default(), &mut report),
            "clamav-community" => Self::sync_clamav_local(db, cfg, &mut report),
            _ => Err(anyhow!("Conector desconocido: {}", cfg.source_id)),
        };

        report.response_time_ms = t0.elapsed().as_millis() as u64;
        match res {
            Ok(_) => {
                report.success = true;
                report.status = "OK".to_string();
            }
            Err(e) => {
                report.success = false;
                report.status = "ERROR".to_string();
                report.error = Some(e.to_string());
            }
        }
        Self::save_source_state(db, cfg, &report);
        report
    }

    fn save_source_state(db: &IntelDatabase, cfg: &FeedConnectorConfig, report: &FeedSyncReport) {
        let _ = db.upsert_source(&IntelSource {
            source_id: cfg.source_id.clone(),
            name: cfg.name.clone(),
            source_kind: "api_feed".to_string(),
            url: cfg.url.clone(),
            last_sync_at: Some(Utc::now().to_rfc3339()),
            last_commit: None,
            status: report.status.clone(),
            received_count: report.received,
            accepted_count: report.accepted,
            rejected_count: report.rejected,
            last_error: report.error.clone(),
            response_time_ms: report.response_time_ms,
            license_default: cfg.license.clone(),
        });
    }

    fn http_get_text(url: &str, auth_header: Option<(&str, &str)>) -> Result<String> {
        let agent = ureq::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("SamuLibre-ThreatIntel/2.0")
            .build();
        let mut req = agent.get(url);
        if let Some((k, v)) = auth_header {
            req = req.set(k, v);
        }
        let resp = req.call().map_err(|e| anyhow!("HTTP GET fallo: {}", e))?;
        let text = resp.into_string()?;
        Ok(text)
    }

    fn sync_malwarebazaar(
        db: &IntelDatabase,
        cfg: &FeedConnectorConfig,
        api_key: Option<&str>,
        report: &mut FeedSyncReport,
    ) -> Result<()> {
        let key = api_key.ok_or_else(|| anyhow!("SAMULIBRE_ABUSECH_AUTH_KEY requerida"))?;
        let agent = ureq::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("SamuLibre-ThreatIntel/2.0")
            .build();
        let resp = agent
            .post(&cfg.url)
            .set("Auth-Key", key)
            .send_form(&[("query", "get_recent"), ("selector", "100")])
            .map_err(|e| anyhow!("MalwareBazaar API fallo: {}", e))?;
        let json: serde_json::Value = resp.into_json()?;
        let now = Utc::now().to_rfc3339();

        let items = json
            .get("data")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("Respuesta inesperada de MalwareBazaar API"))?;

        for item in items {
            report.received += 1;
            let hash = item
                .get("sha256_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let sig = item
                .get("signature")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("MalwareBazaar.Recent");
            if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                Self::insert_simple_ioc(
                    db,
                    IndicatorType::Sha256,
                    &hash,
                    sig,
                    "Malware",
                    cfg,
                    92,
                    &now,
                )?;
                report.accepted += 1;
            } else {
                report.rejected += 1;
            }
        }
        Ok(())
    }

    fn sync_feodo(
        db: &IntelDatabase,
        cfg: &FeedConnectorConfig,
        report: &mut FeedSyncReport,
    ) -> Result<()> {
        let body = Self::http_get_text(&cfg.url, None)?;
        let now = Utc::now().to_rfc3339();
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            report.received += 1;
            if let Ok(ip) = trimmed.parse::<IpAddr>() {
                Self::insert_simple_ioc(
                    db,
                    IndicatorType::C2Ip,
                    &ip.to_string(),
                    "FeodoTracker.BotnetC2",
                    "BotnetC2",
                    cfg,
                    96,
                    &now,
                )?;
                report.accepted += 1;
            } else {
                report.rejected += 1;
            }
        }
        Ok(())
    }

    fn sync_urlhaus(
        db: &IntelDatabase,
        cfg: &FeedConnectorConfig,
        api_key: Option<&str>,
        report: &mut FeedSyncReport,
    ) -> Result<()> {
        let key = api_key.ok_or_else(|| anyhow!("SAMULIBRE_ABUSECH_AUTH_KEY requerida"))?;
        let body = Self::http_get_text(&cfg.url, Some(("Auth-Key", key)))?;
        let json: serde_json::Value = serde_json::from_str(&body)?;
        let now = Utc::now().to_rfc3339();
        let urls = json
            .get("urls")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("Respuesta inesperada de URLhaus API"))?;
        for item in urls {
            report.received += 1;
            let url_val = item.get("url").and_then(|v| v.as_str()).unwrap_or("").trim();
            let threat = item
                .get("threat")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("URLhaus.MalwareDistribution");
            if url_val.starts_with("http://") || url_val.starts_with("https://") {
                Self::insert_simple_ioc(
                    db,
                    IndicatorType::Url,
                    url_val,
                    threat,
                    "MalwareURL",
                    cfg,
                    90,
                    &now,
                )?;
                report.accepted += 1;
            } else {
                report.rejected += 1;
            }
        }
        Ok(())
    }

    fn sync_threatfox(
        db: &IntelDatabase,
        cfg: &FeedConnectorConfig,
        api_key: Option<&str>,
        report: &mut FeedSyncReport,
    ) -> Result<()> {
        let key = api_key.ok_or_else(|| anyhow!("SAMULIBRE_ABUSECH_AUTH_KEY requerida"))?;
        let agent = ureq::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("SamuLibre-ThreatIntel/2.0")
            .build();
        let resp = agent
            .post(&cfg.url)
            .set("Auth-Key", key)
            .send_json(serde_json::json!({ "query": "get_iocs", "days": 7 }))
            .map_err(|e| anyhow!("ThreatFox API fallo: {}", e))?;
        let json: serde_json::Value = resp.into_json()?;
        let now = Utc::now().to_rfc3339();

        let items = json
            .get("data")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("Respuesta JSON inesperada de ThreatFox API"))?;
        for item in items {
            report.received += 1;
            let ioc_val = item
                .get("ioc")
                .or_else(|| item.get("ioc_value"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let ioc_type = item.get("ioc_type").and_then(|v| v.as_str()).unwrap_or("");
            let malware = item
                .get("malware_printable")
                .or_else(|| item.get("malware"))
                .and_then(|v| v.as_str())
                .unwrap_or("ThreatFoxIOC");
            let conf = item
                .get("confidence_level")
                .and_then(|v| v.as_u64())
                .unwrap_or(75)
                .min(100) as u8;

            if ioc_val.is_empty() {
                report.rejected += 1;
                continue;
            }

            let mapped = match ioc_type {
                "ip:port" => {
                    let ip_only = ioc_val.split(':').next().unwrap_or(ioc_val);
                    if ip_only.parse::<IpAddr>().is_ok() {
                        Some((IndicatorType::C2Ip, ip_only.to_string()))
                    } else {
                        None
                    }
                }
                "domain" => Some((IndicatorType::Domain, ioc_val.to_ascii_lowercase())),
                "url" => Some((IndicatorType::Url, ioc_val.to_string())),
                "sha256_hash" if ioc_val.len() == 64 => {
                    Some((IndicatorType::Sha256, ioc_val.to_ascii_lowercase()))
                }
                _ => None,
            };

            if let Some((itype, clean_val)) = mapped {
                Self::insert_simple_ioc(db, itype, &clean_val, malware, "ThreatFox", cfg, conf, &now)?;
                report.accepted += 1;
            } else {
                report.rejected += 1;
            }
        }
        Ok(())
    }

    fn sync_yaraify(
        db: &IntelDatabase,
        cfg: &FeedConnectorConfig,
        api_key: Option<&str>,
        report: &mut FeedSyncReport,
    ) -> Result<()> {
        let agent = ureq::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("SamuLibre-ThreatIntel/2.0")
            .build();
        let mut req = agent.post(&cfg.url);
        if let Some(k) = api_key {
            req = req.set("Auth-Key", k);
        }
        let resp = req
            .send_json(serde_json::json!({ "query": "get_yara_rules", "limit": 50 }))
            .map_err(|e| anyhow!("YARAify API fallo: {}", e))?;
        let json: serde_json::Value = resp.into_json()?;
        let now = Utc::now().to_rfc3339();

        let rules_arr = json
            .get("data")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        for item in rules_arr {
            if let Some(yar_src) = item.get("yara_rule").and_then(|v| v.as_str()) {
                for rule in YaraRuleValidator::split_yara_file(yar_src, &cfg.license) {
                    report.received += 1;
                    let id = IntelDatabase::compute_indicator_id(
                        IndicatorType::YaraRule,
                        &cfg.name,
                        &rule.rule_name,
                    );
                    let is_dup = db
                        .find_duplicate_by_content_hash(
                            IndicatorType::YaraRule,
                            &rule.content_hash,
                            &id,
                        )?
                        .is_some();
                    let val = YaraRuleValidator::validate_rule(&rule, is_dup);
                    if val.status.is_production_active() {
                        report.accepted += 1;
                    } else {
                        report.rejected += 1;
                    }
                    let rec = ThreatIndicatorRecord {
                        id,
                        indicator_type: IndicatorType::YaraRule,
                        value: rule.rule_name,
                        payload: rule.raw_source,
                        content_hash: rule.content_hash,
                        malware_family: rule.malware_family,
                        threat_name: rule.threat_name,
                        category: "YARAify".to_string(),
                        source_name: cfg.name.clone(),
                        repo_origin: cfg.name.clone(),
                        rule_author: rule.author,
                        license: rule.license,
                        source_url: cfg.url.clone(),
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
        }
        Ok(())
    }

    fn sync_otx(
        db: &IntelDatabase,
        cfg: &FeedConnectorConfig,
        api_key: &str,
        report: &mut FeedSyncReport,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let mut next_url = Some(cfg.url.clone());
        let mut pages = 0usize;

        while let Some(url) = next_url.take() {
            if pages >= 3 {
                break;
            }
            pages += 1;
            let body = Self::http_get_text(&url, Some(("X-OTX-API-KEY", api_key)))?;
            let json: serde_json::Value = serde_json::from_str(&body)?;
            let results = json
                .get("results")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            for pulse in results {
                let pulse_name = pulse.get("name").and_then(|v| v.as_str()).unwrap_or("OTX Pulse");
                let indicators = pulse
                    .get("indicators")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                for ind in indicators {
                    report.received += 1;
                    let itype = ind.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let val = ind.get("indicator").and_then(|v| v.as_str()).unwrap_or("").trim();
                    let mapped = match itype {
                        "FileHash-SHA256" if val.len() == 64 => {
                            Some((IndicatorType::Sha256, val.to_ascii_lowercase()))
                        }
                        "IPv4" | "IPv6" if val.parse::<IpAddr>().is_ok() => {
                            Some((IndicatorType::C2Ip, val.to_string()))
                        }
                        "domain" | "hostname" => Some((IndicatorType::Domain, val.to_ascii_lowercase())),
                        "URL" => Some((IndicatorType::Url, val.to_string())),
                        _ => None,
                    };
                    if let Some((t, clean)) = mapped {
                        Self::insert_simple_ioc(db, t, &clean, pulse_name, "OTX", cfg, 80, &now)?;
                        report.accepted += 1;
                    } else {
                        report.rejected += 1;
                    }
                }
            }

            next_url = json
                .get("next")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
        }
        Ok(())
    }

    fn sync_clamav_local(
        db: &IntelDatabase,
        cfg: &FeedConnectorConfig,
        report: &mut FeedSyncReport,
    ) -> Result<()> {
        let clam_dir = Path::new("data/signatures/clamav");
        if !clam_dir.exists() {
            fs::create_dir_all(clam_dir)?;
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        for entry in fs::read_dir(clam_dir)?.flatten() {
            let p = entry.path();
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
            if !matches!(ext.as_str(), "hdb" | "hsb" | "sha256") {
                continue;
            }
            let content = fs::read_to_string(&p)?;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                report.received += 1;
                let parts: Vec<&str> = trimmed.split(':').collect();
                let (hash, name) = if parts.len() >= 3 {
                    (parts[0].trim().to_ascii_lowercase(), parts[2].trim())
                } else if parts.len() == 2 {
                    (parts[0].trim().to_ascii_lowercase(), parts[1].trim())
                } else {
                    report.rejected += 1;
                    continue;
                };
                if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) && !name.is_empty() {
                    Self::insert_simple_ioc(
                        db,
                        IndicatorType::Sha256,
                        &hash,
                        &format!("ClamAV.{}", name),
                        "ClamAV",
                        cfg,
                        92,
                        &now,
                    )?;
                    report.accepted += 1;
                } else {
                    report.rejected += 1;
                }
            }
        }
        Ok(())
    }

    fn insert_simple_ioc(
        db: &IntelDatabase,
        itype: IndicatorType,
        value: &str,
        threat_name: &str,
        category: &str,
        cfg: &FeedConnectorConfig,
        confidence: u8,
        now: &str,
    ) -> Result<UpsertOutcome> {
        let id = IntelDatabase::compute_indicator_id(itype, &cfg.name, value);
        let content_hash = hex::encode(Sha256::digest(format!("{}:{}", value, threat_name).as_bytes()));
        let rec = ThreatIndicatorRecord {
            id,
            indicator_type: itype,
            value: value.to_string(),
            payload: threat_name.to_string(),
            content_hash,
            malware_family: category.to_string(),
            threat_name: threat_name.to_string(),
            category: category.to_string(),
            source_name: cfg.name.clone(),
            repo_origin: cfg.name.clone(),
            rule_author: cfg.name.clone(),
            license: cfg.license.clone(),
            source_url: cfg.url.clone(),
            first_seen: now.to_string(),
            last_modified: now.to_string(),
            expires_at: None,
            confidence,
            validation_status: ValidationStatus::Aprobada,
            validation_score: confidence,
            validation_notes: "Indicador validado desde feed Threat Intelligence".to_string(),
            version: 1,
            external_vars: Vec::new(),
            required_modules: Vec::new(),
        };
        db.upsert_indicator(&rec)
    }

    /// Ejecuta todos los conectores de Threat Intelligence contra `db_path` usando `key_file`
    pub fn sync_all_feeds(
        db_path: &Path,
        key_file: &Path,
        bypass_rate_limit: bool,
    ) -> Result<Vec<FeedSyncReport>> {
        let db = IntelDatabase::open(db_path)?;
        let mut reports = Vec::new();
        for cfg in Self::all_connectors() {
            reports.push(Self::sync_connector_with_key_file(
                &db,
                &cfg,
                bypass_rate_limit,
                key_file,
            ));
        }
        Ok(reports)
    }
}
