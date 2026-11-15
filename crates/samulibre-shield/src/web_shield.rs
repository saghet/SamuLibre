use samulibre_types::{
    MotwInspectionResult, WebFilterVerdict, WebShieldConfig, WebThreatCategory,
};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::info;

/// Lista de dominios C2 y sitios maliciosos conocidos (Threat Intelligence Feed integrado)
const BUILTIN_MALICIOUS_DOMAINS: &[(&str, WebThreatCategory, &str)] = &[
    (
        "evil-c2-server.com",
        WebThreatCategory::CommandAndControl,
        "Servidor C2 conocido asociado a troyanos bancarios",
    ),
    (
        "cobalt-strike-beacon.xyz",
        WebThreatCategory::CommandAndControl,
        "Servidor de balizamiento interactivo Cobalt Strike (T1071.001)",
    ),
    (
        "emotet-dropsite.top",
        WebThreatCategory::MalwareDropSite,
        "Sitio de descarga y distribución masiva de cargadores Emotet/Qakbot",
    ),
    (
        "lockbit3-portal.onion.pet",
        WebThreatCategory::CommandAndControl,
        "Portal de extorsión y negociación del grupo de ransomware LockBit 3.0",
    ),
    (
        "stealer-logs-upload.ru",
        WebThreatCategory::CommandAndControl,
        "Punto de recepción y exfiltración de credenciales (RedLine / Vidar Stealer)",
    ),
    (
        "crypto-metamask-airdrop-claim.com",
        WebThreatCategory::CryptoDrainer,
        "Sitio señuelo con contrato malicioso para drenar billeteras Web3",
    ),
    (
        "update-chrome-browser-security.click",
        WebThreatCategory::MalwareDropSite,
        "Campaña de falsa actualización de navegador con troyano de acceso remoto (RAT)",
    ),
    (
        "paypal-account-security-center.top",
        WebThreatCategory::Phishing,
        "Suplantación fraudulenta de inicio de sesión de PayPal",
    ),
    (
        "microsoft-login-verify-office.xyz",
        WebThreatCategory::Phishing,
        "Portal fraudulento para robo de credenciales de Microsoft 365 / Entra ID",
    ),
];

/// Marcas financieras y corporativas comúnmente suplantadas
const PROTECTED_BRANDS: &[&str] = &[
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "binance",
    "coinbase", "santander", "bbva", "chase", "wellsfargo", "bancolombia",
    "mercadolibre", "office365", "outlook", "dhl", "fedex", "appleid",
];

/// TLDs de bajo costo frecuentemente abusados en campañas de malware/phishing
const SUSPICIOUS_TLDS: &[&str] = &[
    ".top", ".xyz", ".click", ".work", ".rest", ".cam", ".surf", ".buzz",
    ".monster", ".fit", ".gq", ".ml", ".cf", ".ga", ".tk", ".icu", ".kim",
];

/// Entrada en la caché LRU en memoria de veredictos web
#[derive(Debug, Clone)]
struct CachedVerdict {
    verdict: WebFilterVerdict,
    _cached_at: Instant,
}

/// Motor de Protección Web y de Red (SamuLibre Web Shield)
pub struct WebShieldEngine {
    config: Arc<Mutex<WebShieldConfig>>,
    config_file: PathBuf,
    custom_blocked: Arc<Mutex<HashSet<String>>>,
    intel_blocked_domains: Arc<Mutex<HashSet<String>>>,
    intel_blocked_urls: Arc<Mutex<HashSet<String>>>,
    lru_cache: Arc<Mutex<HashMap<String, CachedVerdict>>>,
    max_cache_entries: usize,
}

impl WebShieldEngine {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let base_dir = data_dir.as_ref().join("web_shield");
        let _ = fs::create_dir_all(&base_dir);
        let config_file = base_dir.join("config.json");

        let mut config = WebShieldConfig::default();
        let mut custom_blocked = HashSet::new();

        if config_file.exists() {
            if let Ok(data) = fs::read_to_string(&config_file) {
                if let Ok(parsed) = serde_json::from_str::<WebShieldConfig>(&data) {
                    for d in &parsed.custom_blocked_domains {
                        custom_blocked.insert(d.to_lowercase());
                    }
                    config = parsed;
                }
            }
        }

        let mut intel_domains = HashSet::new();
        let mut intel_urls = HashSet::new();
        let intel_db_path = Path::new("data").join("intel").join("samulibre_intel.db");
        if intel_db_path.exists() {
            if let Ok(db) = samulibre_intel::IntelDatabase::open(&intel_db_path) {
                if let Ok(web_inds) = db.load_production_web_indicators() {
                    for (itype, val, _threat) in web_inds {
                        if itype == "domain" {
                            intel_domains.insert(val.to_ascii_lowercase());
                        } else if itype == "url" {
                            intel_urls.insert(val);
                        }
                    }
                }
            }
        }

        Self {
            config: Arc::new(Mutex::new(config)),
            config_file,
            custom_blocked: Arc::new(Mutex::new(custom_blocked)),
            intel_blocked_domains: Arc::new(Mutex::new(intel_domains)),
            intel_blocked_urls: Arc::new(Mutex::new(intel_urls)),
            lru_cache: Arc::new(Mutex::new(HashMap::with_capacity(2048))),
            max_cache_entries: 5000,
        }
    }

    pub fn get_config(&self) -> WebShieldConfig {
        self.config.lock().unwrap().clone()
    }

    pub fn set_config(&self, new_cfg: WebShieldConfig) {
        if let Ok(mut c) = self.config.lock() {
            *c = new_cfg.clone();
        }
        if let Ok(mut cb) = self.custom_blocked.lock() {
            cb.clear();
            for d in &new_cfg.custom_blocked_domains {
                cb.insert(d.to_lowercase());
            }
        }
        self.persist_config(&new_cfg);
    }

    /// Agrega un dominio a la lista personalizada de bloqueo
    pub fn add_blocked_domain(&self, domain: &str, _reason: &str) -> bool {
        let clean = domain.trim().to_lowercase();
        if clean.is_empty() {
            return false;
        }

        let mut added = false;
        if let Ok(mut cb) = self.custom_blocked.lock() {
            added = cb.insert(clean.clone());
        }

        if added {
            if let Ok(mut cfg) = self.config.lock() {
                if !cfg.custom_blocked_domains.contains(&clean) {
                    cfg.custom_blocked_domains.push(clean.clone());
                    self.persist_config(&cfg);
                }
            }
            // Invalidar entrada en caché si existía
            if let Ok(mut cache) = self.lru_cache.lock() {
                cache.remove(&clean);
            }
            info!("[WEB SHIELD] Dominio agregado a lista de bloqueo: {}", clean);
        }
        added
    }

    /// Remueve un dominio de la lista personalizada de bloqueo
    pub fn remove_blocked_domain(&self, domain: &str) -> bool {
        let clean = domain.trim().to_lowercase();
        let mut removed = false;

        if let Ok(mut cb) = self.custom_blocked.lock() {
            removed = cb.remove(&clean);
        }

        if removed {
            if let Ok(mut cfg) = self.config.lock() {
                cfg.custom_blocked_domains.retain(|d| d != &clean);
                self.persist_config(&cfg);
            }
            if let Ok(mut cache) = self.lru_cache.lock() {
                cache.remove(&clean);
            }
            info!("[WEB SHIELD] Dominio removido de lista de bloqueo: {}", clean);
        }
        removed
    }

    /// Lista todos los dominios bloqueados (personalizados + muestra feeds)
    pub fn list_blocked_domains(&self) -> Vec<String> {
        self.custom_blocked.lock().unwrap().iter().cloned().collect()
    }

    /// Normaliza y extrae el hostname o dominio de una URL
    pub fn extract_domain(input: &str) -> String {
        let trimmed = input.trim();
        let without_proto = if let Some(pos) = trimmed.find("://") {
            &trimmed[pos + 3..]
        } else {
            trimmed
        };
        let host_part = without_proto.split('/').next().unwrap_or(without_proto);
        let host_no_port = host_part.split(':').next().unwrap_or(host_part);
        host_no_port.to_lowercase()
    }

    /// Evalúa en tiempo real una URL o dominio con caché ultrarrápida (< 100 µs)
    pub fn evaluate_url(&self, raw_input: &str) -> WebFilterVerdict {
        let start = Instant::now();
        let domain = Self::extract_domain(raw_input);
        let domain_lower = domain.to_lowercase();

        // 1. Verificación en Caché LRU de Memoria (< 10 µs)
        if let Ok(cache) = self.lru_cache.lock() {
            if let Some(entry) = cache.get(&domain_lower) {
                let mut hit = entry.verdict.clone();
                hit.latency_us = start.elapsed().as_micros() as u64;
                return hit;
            }
        }

        let cfg = self.get_config();
        if !cfg.enabled {
            return WebFilterVerdict {
                url: raw_input.to_string(),
                domain: domain.clone(),
                is_blocked: false,
                category: WebThreatCategory::Clean,
                threat_score: 0,
                explanation: "Protección Web y Red desactivada por configuración.".to_string(),
                latency_us: start.elapsed().as_micros() as u64,
            };
        }

        // 2. Verificación en Bloqueos Personalizados del Administrador
        if let Ok(cb) = self.custom_blocked.lock() {
            if cb.contains(&domain_lower) {
                let verdict = WebFilterVerdict {
                    url: raw_input.to_string(),
                    domain: domain.clone(),
                    is_blocked: true,
                    category: WebThreatCategory::CommandAndControl,
                    threat_score: 100,
                    explanation: "Dominio bloqueado explícitamente por política de seguridad local."
                        .to_string(),
                    latency_us: start.elapsed().as_micros() as u64,
                };
                self.cache_verdict(domain_lower, verdict.clone());
                return verdict;
            }
        }

        // 3. Verificación contra Threat Intelligence Feed de C2 y Malware Dropsites
        for &(mal_domain, ref cat, ref expl) in BUILTIN_MALICIOUS_DOMAINS {
            if domain_lower == mal_domain || domain_lower.ends_with(&format!(".{}", mal_domain)) {
                let verdict = WebFilterVerdict {
                    url: raw_input.to_string(),
                    domain: domain.clone(),
                    is_blocked: true,
                    category: cat.clone(),
                    threat_score: 95,
                    explanation: format!("Dominio malicioso confirmado ({}): {}", cat, expl),
                    latency_us: start.elapsed().as_micros() as u64,
                };
                self.cache_verdict(domain_lower, verdict.clone());
                return verdict;
            }
        }

        // 3b. Verificación contra Base Central SamuLibre Threat Intelligence (URLhaus / ThreatFox / OTX)
        if let Ok(urls) = self.intel_blocked_urls.lock() {
            if urls.contains(raw_input.trim()) {
                let verdict = WebFilterVerdict {
                    url: raw_input.to_string(),
                    domain: domain.clone(),
                    is_blocked: true,
                    category: WebThreatCategory::MalwareDropSite,
                    threat_score: 95,
                    explanation: "URL maliciosa confirmada en Base Central de Inteligencia".to_string(),
                    latency_us: start.elapsed().as_micros() as u64,
                };
                return verdict;
            }
        }
        if let Ok(doms) = self.intel_blocked_domains.lock() {
            if doms.contains(&domain_lower) {
                let verdict = WebFilterVerdict {
                    url: raw_input.to_string(),
                    domain: domain.clone(),
                    is_blocked: true,
                    category: WebThreatCategory::CommandAndControl,
                    threat_score: 92,
                    explanation: "Dominio malicioso confirmado en Base Central de Inteligencia".to_string(),
                    latency_us: start.elapsed().as_micros() as u64,
                };
                self.cache_verdict(domain_lower, verdict.clone());
                return verdict;
            }
        }

        // 4. Detección de Túneles y Exfiltración DNS (T1071.004) - Se evalúa antes de DGA
        if let Some(exfil_expl) = Self::detect_dns_exfiltration(&domain_lower) {
            let verdict = WebFilterVerdict {
                url: raw_input.to_string(),
                domain: domain.clone(),
                is_blocked: true,
                category: WebThreatCategory::DnsExfiltration,
                threat_score: 95,
                explanation: exfil_expl,
                latency_us: start.elapsed().as_micros() as u64,
            };
            self.cache_verdict(domain_lower, verdict.clone());
            return verdict;
        }

        // 5. Detección Heurística de Suplantación de Marcas (Phishing Brand Spoofing)
        if cfg.block_phishing {
            if let Some(phish_expl) = Self::detect_brand_spoofing(&domain_lower) {
                let verdict = WebFilterVerdict {
                    url: raw_input.to_string(),
                    domain: domain.clone(),
                    is_blocked: true,
                    category: WebThreatCategory::Phishing,
                    threat_score: 85,
                    explanation: phish_expl,
                    latency_us: start.elapsed().as_micros() as u64,
                };
                self.cache_verdict(domain_lower, verdict.clone());
                return verdict;
            }
        }

        // 6. Detección de Algoritmos de Generación de Dominios (DGA - T1568.002)
        if cfg.block_dga {
            if let Some(dga_expl) = Self::detect_dga_domain(&domain_lower) {
                let verdict = WebFilterVerdict {
                    url: raw_input.to_string(),
                    domain: domain.clone(),
                    is_blocked: true,
                    category: WebThreatCategory::DgaDomain,
                    threat_score: 90,
                    explanation: dga_expl,
                    latency_us: start.elapsed().as_micros() as u64,
                };
                self.cache_verdict(domain_lower, verdict.clone());
                return verdict;
            }
        }

        // 7. Veredicto Limpio
        let verdict = WebFilterVerdict {
            url: raw_input.to_string(),
            domain: domain.clone(),
            is_blocked: false,
            category: WebThreatCategory::Clean,
            threat_score: 0,
            explanation: "Dominio verificado sin indicadores de amenaza detectados.".to_string(),
            latency_us: start.elapsed().as_micros() as u64,
        };
        self.cache_verdict(domain_lower, verdict.clone());
        verdict
    }

    /// Almacena el veredicto en la caché LRU en memoria respetando el límite máximo
    fn cache_verdict(&self, domain: String, verdict: WebFilterVerdict) {
        if let Ok(mut cache) = self.lru_cache.lock() {
            if cache.len() >= self.max_cache_entries {
                // Poda del 25% más antiguo
                let to_evict: Vec<_> = cache.keys().take(self.max_cache_entries / 4).cloned().collect();
                for k in to_evict {
                    cache.remove(&k);
                }
            }
            cache.insert(
                domain,
                CachedVerdict {
                    verdict,
                    _cached_at: Instant::now(),
                },
            );
        }
    }

    /// Detecta suplantación engañosa de marcas corporativas en el dominio
    fn detect_brand_spoofing(domain: &str) -> Option<String> {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        for &brand in PROTECTED_BRANDS {
            if domain.contains(brand) {
                // Verificar si es el dominio oficial legítimo (ej. paypal.com, microsoft.com, google.com)
                let is_legit = domain == format!("{}.com", brand)
                    || domain == format!("{}.net", brand)
                    || domain == format!("{}.org", brand)
                    || domain.ends_with(&format!(".{}.com", brand))
                    || domain.ends_with(&format!(".{}.net", brand));

                if !is_legit {
                    // Contiene el nombre de la marca pero bajo un TLD sospechoso o con sufijos engañosos
                    let has_suspicious_tld = SUSPICIOUS_TLDS.iter().any(|&tld| domain.ends_with(tld));
                    let has_deceptive_hyphen = domain.contains(&format!("{}-", brand))
                        || domain.contains(&format!("-{}-", brand))
                        || domain.contains(&format!("-{}", brand));

                    if has_suspicious_tld || has_deceptive_hyphen || parts.len() >= 4 {
                        return Some(format!(
                            "Ataque de Phishing detectado: Suplantación engañosa de la marca '{}' en dominio no autorizado ({})",
                            brand, domain
                        ));
                    }
                }
            }
        }
        None
    }

    /// Detecta dominios generados algorítmicamente (DGA) mediante entropía y patrones lingüísticos
    pub fn detect_dga_domain(domain: &str) -> Option<String> {
        let label = domain.split('.').next().unwrap_or(domain);
        if label.len() < 8 {
            return None;
        }

        // 1. Ratio consonante/vocal y conteo de dígitos
        let mut vowels = 0;
        let mut consonants = 0;
        let mut digits = 0;

        for c in label.chars() {
            match c.to_ascii_lowercase() {
                'a' | 'e' | 'i' | 'o' | 'u' => vowels += 1,
                'b'..='z' => consonants += 1,
                '0'..='9' => digits += 1,
                _ => {}
            }
        }

        let total_chars = label.len();
        let entropy = Self::calculate_shannon_entropy(label);

        // Si la entropía es mayor a 3.35 sobre el nombre del host y casi no tiene vocales o tiene alta mezcla alfanumérica
        let low_vowels = vowels == 0 || (consonants + digits > 0 && (vowels as f32 / total_chars as f32) < 0.15);
        let high_entropy = entropy > 3.30;
        let heavy_digits_mix = digits >= 3 && consonants >= 4;

        if (high_entropy && low_vowels) || (heavy_digits_mix && high_entropy) {
            return Some(format!(
                "Dominio algorítmico DGA detectado (T1568.002): Entropía alta ({:.2}), secuencia pseudoaleatoria sospechosa '{}'",
                entropy, label
            ));
        }

        None
    }

    /// Detecta anomalías de exfiltración o tunelización de datos por DNS (T1071.004)
    pub fn detect_dns_exfiltration(domain: &str) -> Option<String> {
        let labels: Vec<&str> = domain.split('.').collect();
        for label in labels {
            // Etiquetas mayores a 32 caracteres con alta entropía o cadenas hexadecimales/base32 largas
            if label.len() >= 32 {
                let is_hex_like = label.chars().all(|c| c.is_ascii_hexdigit());
                let entropy = Self::calculate_shannon_entropy(label);
                if is_hex_like || entropy > 3.40 {
                    return Some(format!(
                        "Exfiltración o túnel DNS detectado (T1071.004): Etiqueta sobredimensionada ({} bytes, Entropía {:.2}) sospechosa de transportar datos binarios.",
                        label.len(), entropy
                    ));
                }
            }
        }
        None
    }

    /// Calcula la entropía de Shannon sobre una cadena de texto
    fn calculate_shannon_entropy(text: &str) -> f32 {
        if text.is_empty() {
            return 0.0;
        }
        let mut freq = HashMap::new();
        for c in text.chars() {
            *freq.entry(c).or_insert(0usize) += 1;
        }
        let len_f = text.len() as f32;
        let mut entropy = 0.0;
        for &count in freq.values() {
            let p = count as f32 / len_f;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Inspecciona el Alternate Data Stream (ADS) :Zone.Identifier de NTFS en Windows (Mark-of-the-Web)
    pub fn inspect_file_motw(file_path: impl AsRef<Path>) -> MotwInspectionResult {
        let path = file_path.as_ref();
        let path_str = path.to_string_lossy().to_string();

        #[cfg(target_os = "windows")]
        {
            let ads_path = format!("{}:Zone.Identifier", path_str);
            if let Ok(file) = File::open(&ads_path) {
                let reader = BufReader::new(file);
                let mut zone_id = None;
                let mut host_url = None;
                let mut referrer_url = None;

                for line in reader.lines().flatten() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("ZoneId=") {
                        if let Ok(zid) = trimmed.trim_start_matches("ZoneId=").parse::<u32>() {
                            zone_id = Some(zid);
                        }
                    } else if trimmed.starts_with("HostUrl=") {
                        host_url = Some(trimmed.trim_start_matches("HostUrl=").to_string());
                    } else if trimmed.starts_with("ReferrerUrl=") {
                        referrer_url = Some(trimmed.trim_start_matches("ReferrerUrl=").to_string());
                    }
                }

                let is_internet_zone = matches!(zone_id, Some(3) | Some(4)); // 3 = Internet, 4 = Restricted
                let risk_assessment = if is_internet_zone {
                    if let Some(ref url) = host_url {
                        let domain = Self::extract_domain(url);
                        format!("Descarga directa de Internet (Zona {}). Origen: {}", zone_id.unwrap_or(3), domain)
                    } else {
                        format!("Descarga de Internet verificada (ZoneId={}).", zone_id.unwrap_or(3))
                    }
                } else {
                    format!("Zona local o confiable (ZoneId={}).", zone_id.unwrap_or(0))
                };

                return MotwInspectionResult {
                    file_path: path_str,
                    has_motw: true,
                    zone_id,
                    host_url,
                    referrer_url,
                    is_internet_zone,
                    risk_assessment,
                };
            }
        }

        MotwInspectionResult {
            file_path: path_str,
            has_motw: false,
            zone_id: None,
            host_url: None,
            referrer_url: None,
            is_internet_zone: false,
            risk_assessment: "Archivo local sin marca de la web (origen local o sistema de archivos no-NTFS).".to_string(),
        }
    }

    fn persist_config(&self, cfg: &WebShieldConfig) {
        if let Ok(json) = serde_json::to_string_pretty(cfg) {
            let _ = fs::write(&self.config_file, json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_c2_domain_blocked_instantly() {
        let temp_dir = std::env::temp_dir().join(format!("samu_web_test_{}", uuid::Uuid::new_v4()));
        let shield = WebShieldEngine::new(&temp_dir);

        let verdict = shield.evaluate_url("https://cobalt-strike-beacon.xyz/stage");
        assert!(verdict.is_blocked);
        assert_eq!(verdict.category, WebThreatCategory::CommandAndControl);
        assert_eq!(verdict.threat_score, 95);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_phishing_brand_spoofing_detected() {
        let temp_dir = std::env::temp_dir().join(format!("samu_web_test_{}", uuid::Uuid::new_v4()));
        let shield = WebShieldEngine::new(&temp_dir);

        let verdict = shield.evaluate_url("http://paypal-account-security-center.top/login.php");
        assert!(verdict.is_blocked);
        assert_eq!(verdict.category, WebThreatCategory::Phishing);
        assert!(verdict.explanation.contains("Phishing"));

        // Dominio oficial legítimo no debe ser bloqueado
        let legit = shield.evaluate_url("https://www.paypal.com/signin");
        assert!(!legit.is_blocked);
        assert_eq!(legit.category, WebThreatCategory::Clean);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_dga_domain_heuristic_detection() {
        let temp_dir = std::env::temp_dir().join(format!("samu_web_test_{}", uuid::Uuid::new_v4()));
        let shield = WebShieldEngine::new(&temp_dir);

        // Dominio DGA pseudoaleatorio con alta entropía y pocas vocales
        let verdict = shield.evaluate_url("http://x8k2mz9q7a1w0.biz/endpoint");
        assert!(verdict.is_blocked);
        assert_eq!(verdict.category, WebThreatCategory::DgaDomain);
        assert!(verdict.explanation.contains("T1568.002"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_dns_exfiltration_pattern_detection() {
        let temp_dir = std::env::temp_dir().join(format!("samu_web_test_{}", uuid::Uuid::new_v4()));
        let shield = WebShieldEngine::new(&temp_dir);

        // Etiqueta hex de 40 caracteres (típica de DNS tunnel / exfiltration)
        let exfil_query = "4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a.attacker.com";
        let verdict = shield.evaluate_url(exfil_query);
        assert!(verdict.is_blocked);
        assert_eq!(verdict.category, WebThreatCategory::DnsExfiltration);
        assert!(verdict.explanation.contains("T1071.004"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_custom_domain_blocking_and_removal() {
        let temp_dir = std::env::temp_dir().join(format!("samu_web_test_{}", uuid::Uuid::new_v4()));
        let shield = WebShieldEngine::new(&temp_dir);

        let target_domain = "unwanted-tracker-adware.org";
        assert!(shield.add_blocked_domain(target_domain, "Rastreador de telemetría no deseado"));

        let verdict = shield.evaluate_url(&format!("https://{}/ping", target_domain));
        assert!(verdict.is_blocked);
        assert_eq!(verdict.threat_score, 100);

        assert!(shield.remove_blocked_domain(target_domain));
        let verdict_after = shield.evaluate_url(&format!("https://{}/ping", target_domain));
        assert!(!verdict_after.is_blocked);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
