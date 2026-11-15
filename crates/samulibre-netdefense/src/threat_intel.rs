use crate::types::{IndicatorType, ThreatFeedMetadata, ThreatIndicator, ThreatIntelCategory};
use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Umbral mínimo de confianza (0-100) para bloqueo automático sin intervención manual.
/// Evita falsos positivos en IPs compartidas (CDN/Cloud) por una única aparición.
pub const AUTO_BLOCK_CONFIDENCE_THRESHOLD: u8 = 80;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelStore {
    pub feeds: Vec<ThreatFeedMetadata>,
    pub domain_indicators: HashMap<String, ThreatIndicator>,
    pub ip_indicators: HashMap<String, ThreatIndicator>,
}

impl Default for ThreatIntelStore {
    fn default() -> Self {
        let now = Utc::now();
        let expires = now + Duration::days(30);

        let feeds = vec![
            ThreatFeedMetadata {
                id: "urlhaus-domains".to_string(),
                name: "abuse.ch URLhaus (Malware Domains)".to_string(),
                url: "https://urlhaus.abuse.ch/downloads/hostfile/".to_string(),
                license: "CC0 1.0 Universal (Public Domain)".to_string(),
                format: "hostfile".to_string(),
                enabled: true,
                last_updated: None,
                expires_at: None,
                sha256_integrity: None,
                indicator_count: 0,
                last_error: None,
            },
            ThreatFeedMetadata {
                id: "threatfox-iocs".to_string(),
                name: "abuse.ch ThreatFox (C2 & Botnets)".to_string(),
                url: "https://threatfox.abuse.ch/export/json/recent/".to_string(),
                license: "CC0 1.0 Universal (Public Domain)".to_string(),
                format: "json".to_string(),
                enabled: true,
                last_updated: None,
                expires_at: None,
                sha256_integrity: None,
                indicator_count: 0,
                last_error: None,
            },
            ThreatFeedMetadata {
                id: "spamhaus-drop".to_string(),
                name: "Spamhaus DROP / EDROP".to_string(),
                url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
                license: "Spamhaus Free Usage Terms (Non-Commercial / Open)".to_string(),
                format: "cidr-txt".to_string(),
                enabled: true,
                last_updated: None,
                expires_at: None,
                sha256_integrity: None,
                indicator_count: 0,
                last_error: None,
            },
            ThreatFeedMetadata {
                id: "openphish-community".to_string(),
                name: "OpenPhish Community Feed".to_string(),
                url: "https://openphish.com/feed.txt".to_string(),
                license: "OpenPhish Community License".to_string(),
                format: "url-txt".to_string(),
                enabled: false,
                last_updated: None,
                expires_at: None,
                sha256_integrity: None,
                indicator_count: 0,
                last_error: None,
            },
        ];

        // Indicadores base verificados (alta confianza) para protección inmediata sin depender de red
        let mut domain_indicators = HashMap::new();
        for (dom, cat, src, conf, desc) in [
            ("evil-c2-server.com", ThreatIntelCategory::CommandAndControl, "SamuLibre-Baseline", 95u8, "Dominio C2 de prueba/referencia"),
            ("cobalt-strike-beacon.xyz", ThreatIntelCategory::CommandAndControl, "ThreatFox", 95u8, "Baliza Cobalt Strike"),
            ("emotet-dropsite.top", ThreatIntelCategory::Malware, "URLhaus", 95u8, "Distribución de cargadores Emotet/Qakbot"),
            ("stealer-logs-upload.ru", ThreatIntelCategory::CommandAndControl, "ThreatFox", 92u8, "Exfiltración de credenciales Infostealer"),
            ("paypal-account-security-center.top", ThreatIntelCategory::Phishing, "PhishingIntel", 95u8, "Suplantación de PayPal"),
            ("microsoft-login-verify-office.xyz", ThreatIntelCategory::Phishing, "PhishingIntel", 95u8, "Suplantación de Microsoft 365"),
            ("doubleclick.net", ThreatIntelCategory::Tracker, "TrackerList", 85u8, "Rastreador publicitario"),
            ("google-analytics.com", ThreatIntelCategory::Tracker, "TrackerList", 80u8, "Telemetría de rastreo web"),
        ] {
            domain_indicators.insert(
                dom.to_string(),
                ThreatIndicator {
                    value: dom.to_string(),
                    indicator_type: IndicatorType::Domain,
                    category: cat,
                    source_name: src.to_string(),
                    confidence: conf,
                    first_seen: now,
                    expires_at: expires,
                    description: desc.to_string(),
                },
            );
        }

        Self {
            feeds,
            domain_indicators,
            ip_indicators: HashMap::new(),
        }
    }
}

pub struct ThreatIntelManager {
    data_dir: PathBuf,
    pub store: ThreatIntelStore,
}

impl ThreatIntelManager {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let dir = data_dir.as_ref().to_path_buf();
        let _ = fs::create_dir_all(&dir);
        let store_path = dir.join("threat_intel.json");
        let mut store = if store_path.exists() {
            fs::read_to_string(&store_path)
                .ok()
                .and_then(|s| serde_json::from_str::<ThreatIntelStore>(&s).ok())
                .unwrap_or_default()
        } else {
            ThreatIntelStore::default()
        };

        // Limpiar CIDRs almacenados erróneamente en domain_indicators
        store.domain_indicators.retain(|k, _| !k.contains('/'));

        // Alimentar desde la Base Central SamuLibre Threat Intelligence (SQLite)
        let intel_db_path = Path::new("data").join("intel").join("samulibre_intel.db");
        if intel_db_path.exists() {
            if let Ok(db) = samulibre_intel::IntelDatabase::open(&intel_db_path) {
                let now = Utc::now();
                let expires = now + Duration::days(30);
                if let Ok(c2_ips) = db.load_production_c2_ips() {
                    for ip in c2_ips {
                        store.ip_indicators.entry(ip.clone()).or_insert_with(|| ThreatIndicator {
                            value: ip,
                            indicator_type: IndicatorType::IpAddress,
                            category: ThreatIntelCategory::CommandAndControl,
                            source_name: "SamuLibreIntel".to_string(),
                            confidence: 95,
                            first_seen: now,
                            expires_at: expires,
                            description: "IP C2 verificada en Base Central de Inteligencia".to_string(),
                        });
                    }
                }
                if let Ok(web_inds) = db.load_production_web_indicators() {
                    for (itype, val, threat) in web_inds {
                        if itype == "domain" {
                            store.domain_indicators.entry(val.clone()).or_insert_with(|| ThreatIndicator {
                                value: val,
                                indicator_type: IndicatorType::Domain,
                                category: ThreatIntelCategory::Malware,
                                source_name: "SamuLibreIntel".to_string(),
                                confidence: 90,
                                first_seen: now,
                                expires_at: expires,
                                description: threat,
                            });
                        }
                    }
                }
            }
        }

        Self {
            data_dir: dir,
            store,
        }
    }

    pub fn save(&self) -> Result<()> {
        let store_path = self.data_dir.join("threat_intel.json");
        let bak_path = self.data_dir.join("threat_intel.bak.json");
        if store_path.exists() {
            let _ = fs::copy(&store_path, &bak_path);
        }
        let json = serde_json::to_string_pretty(&self.store)?;
        fs::write(&store_path, &json)?;
        if !bak_path.exists() {
            let _ = fs::write(&bak_path, &json);
        }
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<()> {
        let bak_path = self.data_dir.join("threat_intel.bak.json");
        if !bak_path.exists() {
            return Err(anyhow!("No existe snapshot de respaldo para rollback"));
        }
        let content = fs::read_to_string(&bak_path)?;
        self.store = serde_json::from_str(&content)?;
        self.save()?;
        info!("Rollback de Threat Intelligence ejecutado correctamente.");
        Ok(())
    }

    /// Purga indicadores caducados según política de expiración
    pub fn purge_expired(&mut self) -> usize {
        let now = Utc::now();
        let before = self.store.domain_indicators.len() + self.store.ip_indicators.len();
        self.store.domain_indicators.retain(|_, v| v.expires_at > now);
        self.store.ip_indicators.retain(|_, v| v.expires_at > now);
        let after = self.store.domain_indicators.len() + self.store.ip_indicators.len();
        before.saturating_sub(after)
    }

    /// Evalúa si un dominio debe bloquearse según categorías activas y umbral de confianza
    pub fn check_domain(
        &self,
        domain: &str,
        block_malware: bool,
        block_phishing: bool,
        block_trackers: bool,
    ) -> Option<&ThreatIndicator> {
        let clean = domain.trim().trim_end_matches('.').to_lowercase();
        let mut candidate = clean.as_str();
        loop {
            if let Some(ind) = self.store.domain_indicators.get(candidate) {
                if ind.expires_at > Utc::now() && ind.confidence >= AUTO_BLOCK_CONFIDENCE_THRESHOLD {
                    let allowed_cat = match ind.category {
                        ThreatIntelCategory::Malware | ThreatIntelCategory::CommandAndControl | ThreatIntelCategory::Botnet => block_malware,
                        ThreatIntelCategory::Phishing => block_phishing,
                        ThreatIntelCategory::Tracker => block_trackers,
                    };
                    if allowed_cat {
                        return Some(ind);
                    }
                }
            }
            match candidate.find('.') {
                Some(idx) => candidate = &candidate[idx + 1..],
                None => break,
            }
        }
        None
    }

    /// Evalúa una IP con umbral de confianza correlacionada (no bloquea por una única mención débil)
    pub fn check_ip(&self, ip: &str, min_confidence: u8) -> Option<&ThreatIndicator> {
        self.store.ip_indicators.get(ip).filter(|ind| {
            ind.expires_at > Utc::now() && ind.confidence >= min_confidence
        })
    }

    /// Parsea un feed en formato hostfile (e.g. URLhaus) y retorna indicadores con expiración de 7 días
    pub fn ingest_hostfile(&mut self, feed_id: &str, raw_content: &str) -> usize {
        let now = Utc::now();
        let expires = now + Duration::days(7);
        let mut hasher = Sha256::new();
        hasher.update(raw_content.as_bytes());
        let sha256 = hex::encode(hasher.finalize());

        let mut count = 0usize;
        for line in raw_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            let domain = if parts.len() >= 2 && (parts[0] == "127.0.0.1" || parts[0] == "0.0.0.0") {
                parts[1]
            } else {
                parts[0]
            }
            .to_lowercase();

            if domain == "localhost" || !domain.contains('.') {
                continue;
            }

            self.store.domain_indicators.insert(
                domain.clone(),
                ThreatIndicator {
                    value: domain,
                    indicator_type: IndicatorType::Domain,
                    category: ThreatIntelCategory::Malware,
                    source_name: feed_id.to_string(),
                    confidence: 85,
                    first_seen: now,
                    expires_at: expires,
                    description: format!("Indicador importado de {}", feed_id),
                },
            );
            count += 1;
            if count >= 25000 {
                break; // Límite de memoria acotado
            }
        }

        if let Some(feed) = self.store.feeds.iter_mut().find(|f| f.id == feed_id) {
            feed.last_updated = Some(now);
            feed.expires_at = Some(expires);
            feed.sha256_integrity = Some(sha256);
            feed.indicator_count = count;
            feed.last_error = None;
        }
        count
    }

    /// Parsea indicadores STIX 2.1 JSON (`objects` con `type == "indicator"` y `pattern`)
    pub fn ingest_stix_bundle(&mut self, feed_id: &str, stix_json: &str) -> Result<usize> {
        let val: serde_json::Value = serde_json::from_str(stix_json)?;
        let objs = val
            .get("objects")
            .and_then(|o| o.as_array())
            .ok_or_else(|| anyhow!("Bundle STIX inválido: falta arreglo 'objects'"))?;

        let now = Utc::now();
        let expires = now + Duration::days(14);
        let mut count = 0usize;

        for obj in objs {
            if obj.get("type").and_then(|t| t.as_str()) != Some("indicator") {
                continue;
            }
            let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) else {
                continue;
            };
            let confidence = obj
                .get("confidence")
                .and_then(|c| c.as_u64())
                .unwrap_or(80)
                .min(100) as u8;

            if let Some(dom) = extract_stix_value(pattern, "domain-name:value") {
                self.store.domain_indicators.insert(
                    dom.to_lowercase(),
                    ThreatIndicator {
                        value: dom.to_lowercase(),
                        indicator_type: IndicatorType::Domain,
                        category: ThreatIntelCategory::CommandAndControl,
                        source_name: feed_id.to_string(),
                        confidence,
                        first_seen: now,
                        expires_at: expires,
                        description: "Indicador STIX 2.1".to_string(),
                    },
                );
                count += 1;
            } else if let Some(ip) = extract_stix_value(pattern, "ipv4-addr:value") {
                self.store.ip_indicators.insert(
                    ip.clone(),
                    ThreatIndicator {
                        value: ip,
                        indicator_type: IndicatorType::IpAddress,
                        category: ThreatIntelCategory::CommandAndControl,
                        source_name: feed_id.to_string(),
                        confidence,
                        first_seen: now,
                        expires_at: expires,
                        description: "Indicador IP STIX 2.1".to_string(),
                    },
                );
                count += 1;
            }
        }
        Ok(count)
    }

    /// Descarga y actualiza los feeds habilitados de forma segura con respaldo previo (rollback).
    pub fn update_enabled_feeds(&mut self) -> Vec<(String, Result<usize>)> {
        let _ = self.save(); // Snapshot previo para rollback
        let mut results = Vec::new();
        let feed_ids: Vec<(String, String, String)> = self
            .store
            .feeds
            .iter()
            .filter(|f| f.enabled)
            .map(|f| (f.id.clone(), f.url.clone(), f.format.clone()))
            .collect();

        let agent = ureq::AgentBuilder::new()
            .timeout_connect(std::time::Duration::from_secs(5))
            .timeout_read(std::time::Duration::from_secs(10))
            .build();

        for (id, url, fmt) in feed_ids {
            let res = match agent.get(&url).call() {
                Ok(resp) => match resp.into_string() {
                    Ok(body) => {
                        if fmt == "hostfile" {
                            Ok(self.ingest_hostfile(&id, &body))
                        } else if fmt == "stix" {
                            self.ingest_stix_bundle(&id, &body)
                        } else {
                            Ok(self.ingest_hostfile(&id, &body))
                        }
                    }
                    Err(e) => Err(anyhow!("Error leyendo cuerpo de {}: {}", id, e)),
                },
                Err(e) => Err(anyhow!("Error de red en {}: {}", id, e)),
            };

            if let Err(ref e) = res {
                warn!("Fallo actualizando feed {}: {}", id, e);
                if let Some(f) = self.store.feeds.iter_mut().find(|f| f.id == id) {
                    f.last_error = Some(e.to_string());
                }
            }
            results.push((id, res));
        }

        let _ = self.purge_expired();
        let _ = self.save();
        results
    }
}

fn extract_stix_value(pattern: &str, key: &str) -> Option<String> {
    let idx = pattern.find(key)?;
    let rest = &pattern[idx + key.len()..];
    let q1 = rest.find('\'')?;
    let after_q1 = &rest[q1 + 1..];
    let q2 = after_q1.find('\'')?;
    Some(after_q1[..q2].to_string())
}
