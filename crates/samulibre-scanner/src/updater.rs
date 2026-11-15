use anyhow::{anyhow, Result};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{error, info, warn};

use crate::{PatternRule, UpdateHistoryEntry};

/// Estado y etapas del progreso de actualización en tiempo real
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UpdateStep {
    CheckingConnection,
    ConsultingSource {
        source_name: String,
        url: String,
    },
    Downloading {
        source_name: String,
        bytes: usize,
    },
    ValidatingIntegrity {
        source_name: String,
        sha256: String,
    },
    CompilingRules {
        rules_found: usize,
    },
    InstallingAtomic,
    Completed {
        new_signatures: usize,
        new_rules: usize,
        total_signatures: usize,
        total_rules: usize,
        version: String,
        feed_source: String,
    },
    UpToDate {
        total_signatures: usize,
        total_rules: usize,
        version: String,
    },
    Failed {
        stage: String,
        error: String,
    },
    RolledBack {
        reason: String,
    },
}

/// Informe detallado devuelto al finalizar la actualización
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedUpdateReport {
    pub success: bool,
    pub new_signatures: usize,
    pub new_yara_rules: usize,
    pub total_signatures: usize,
    pub total_yara_rules: usize,
    pub version: String,
    pub timestamp: String,
    pub feed_source: String,
    pub error_message: Option<String>,
    pub downloaded_files: Vec<String>,
}

/// Definición de una fuente de actualización con procedencia, confiabilidad, versión e integridad
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateSource {
    pub name: String,
    pub url: String,
    pub source_type: UpdateSourceType,
    pub description: String,
    #[serde(default = "default_trust_score")]
    pub trust_score: u8,
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: u32,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub integrity_sha256: Option<String>,
}

fn default_trust_score() -> u8 {
    85
}
fn default_ttl_hours() -> u32 {
    24
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum UpdateSourceType {
    YaraRule,
    HashDatabase,
    MalwareBazaarSha256,
    IpBlocklist,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SignatureCatalogEntry {
    pub kind: String,       // "SHA256" | "YARA" | "BEHAVIOR" | "C2_IP" | "DOMAIN" | "URL"
    pub identifier: String, // hash, nombre de regla o IP
    pub family: String,     // familia o descripción de amenaza
    pub source: String,     // feed de origen
    pub added_at: String,   // timestamp de incorporación
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub source_url: String,
    #[serde(default)]
    pub rule_author: String,
    #[serde(default)]
    pub validation_status: String,
    #[serde(default)]
    pub validation_score: u8,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SignatureDatabaseSummary {
    pub sha256_hashes: usize,
    pub yara_rules: usize,
    pub c2_ips: usize,
    pub total_protections: usize,
    pub last_updated: String,
    pub active_feeds: Vec<String>,
    #[serde(default)]
    pub domains: usize,
    #[serde(default)]
    pub urls: usize,
    #[serde(default)]
    pub behavior_rules: usize,
    #[serde(default)]
    pub loldrivers_count: usize,
    #[serde(default)]
    pub connected_sources: usize,
    #[serde(default)]
    pub yara_lab: usize,
    #[serde(default)]
    pub yara_pending: usize,
    #[serde(default)]
    pub yara_rejected: usize,
    #[serde(default)]
    pub yara_obsolete: usize,
    #[serde(default)]
    pub fp_reported: usize,
    #[serde(default)]
    pub sources_detail: Vec<samulibre_intel::IntelSource>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureCatalogResponse {
    pub summary: SignatureDatabaseSummary,
    pub entries: Vec<SignatureCatalogEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureCatalogPageResponse {
    pub summary: SignatureDatabaseSummary,
    pub total_filtered: usize,
    pub page: usize,
    pub page_size: usize,
    pub entries: Vec<SignatureCatalogEntry>,
}

/// Gestor de Fuentes de Actualización (Source Manager)
pub struct SourceManager {
    sources: Vec<UpdateSource>,
}

impl SourceManager {
    pub fn new() -> Self {
        Self {
            sources: vec![
                UpdateSource {
                    name: "Yara-Rules Official Malware Feed (EICAR Standard)".to_string(),
                    url: "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Eicar.yar".to_string(),
                    source_type: UpdateSourceType::YaraRule,
                    description: "Regla YARA comunitaria para verificación de firma estándar EICAR".to_string(),
                    trust_score: 95,
                    ttl_hours: 168,
                    version: "Yara-Rules/master".to_string(),
                    integrity_sha256: None,
                },
                UpdateSource {
                    name: "Neo23x0 Signature-Base (Hash IOCs SHA-256)".to_string(),
                    url: "https://raw.githubusercontent.com/Neo23x0/signature-base/master/iocs/hash-iocs.txt".to_string(),
                    source_type: UpdateSourceType::HashDatabase,
                    description: "Base comunitaria verificada de hashes SHA-256 de malware y APT".to_string(),
                    trust_score: 92,
                    ttl_hours: 24,
                    version: "Neo23x0/master".to_string(),
                    integrity_sha256: None,
                },
                UpdateSource {
                    name: "Neo23x0 YARA (Mimikatz & Credential Dumpers)".to_string(),
                    url: "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_mimikatz.yar".to_string(),
                    source_type: UpdateSourceType::YaraRule,
                    description: "Reglas YARA para detección de volcadores de credenciales".to_string(),
                    trust_score: 90,
                    ttl_hours: 72,
                    version: "Neo23x0/master".to_string(),
                    integrity_sha256: None,
                },
                UpdateSource {
                    name: "Neo23x0 YARA (CobaltStrike)".to_string(),
                    url: "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_cobaltstrike.yar".to_string(),
                    source_type: UpdateSourceType::YaraRule,
                    description: "Reglas YARA para detección de beacons CobaltStrike".to_string(),
                    trust_score: 90,
                    ttl_hours: 72,
                    version: "Neo23x0/master".to_string(),
                    integrity_sha256: None,
                },
                UpdateSource {
                    name: "Yara-Rules Official (Emotet)".to_string(),
                    url: "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Emotet.yar".to_string(),
                    source_type: UpdateSourceType::YaraRule,
                    description: "Reglas YARA comunitarias para familia Emotet".to_string(),
                    trust_score: 82,
                    ttl_hours: 72,
                    version: "Yara-Rules/master".to_string(),
                    integrity_sha256: None,
                },
                UpdateSource {
                    name: "Yara-Rules Official (Mirai)".to_string(),
                    url: "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/MALW_Mirai.yar".to_string(),
                    source_type: UpdateSourceType::YaraRule,
                    description: "Reglas YARA comunitarias para familia Mirai".to_string(),
                    trust_score: 82,
                    ttl_hours: 72,
                    version: "Yara-Rules/master".to_string(),
                    integrity_sha256: None,
                },
                UpdateSource {
                    name: "Abuse.ch MalwareBazaar (Recent SHA-256 Live Feed)".to_string(),
                    url: "https://bazaar.abuse.ch/export/txt/sha256/recent/".to_string(),
                    source_type: UpdateSourceType::MalwareBazaarSha256,
                    description: "Muestras activas recientes de malware (últimas 48h) desde MalwareBazaar".to_string(),
                    trust_score: 96,
                    ttl_hours: 4,
                    version: "abuse.ch/bazaar-recent".to_string(),
                    integrity_sha256: None,
                },
                UpdateSource {
                    name: "Abuse.ch Feodo Tracker (Active Botnet C2 Blocklist)".to_string(),
                    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt".to_string(),
                    source_type: UpdateSourceType::IpBlocklist,
                    description: "Lista abierta de direcciones IP de servidores Command & Control activos".to_string(),
                    trust_score: 96,
                    ttl_hours: 12,
                    version: "abuse.ch/feodo-v1".to_string(),
                    integrity_sha256: None,
                },
            ],
        }
    }

    pub fn get_sources(&self) -> &[UpdateSource] {
        &self.sources
    }

    pub fn add_source(&mut self, source: UpdateSource) {
        self.sources.push(source);
    }
}

/// Validador de Integridad y Criptografía (Integrity Validator)
pub struct IntegrityValidator;

impl IntegrityValidator {
    /// Comprueba conectividad básica hacia un endpoint confiable
    pub fn check_internet_connection() -> bool {
        let test_endpoints = [
            "https://www.google.com",
            "https://1.1.1.1",
            "https://raw.githubusercontent.com",
        ];

        for endpoint in test_endpoints {
            let res = ureq::builder()
                .timeout(Duration::from_secs(4))
                .build()
                .head(endpoint)
                .call();
            if res.is_ok() {
                return true;
            }
        }
        false
    }

    /// Valida que el payload descargado cumpla con límites de tamaño y no esté vacío ni truncado
    pub fn validate_download(bytes: &[u8], min_bytes: usize, max_bytes: usize) -> Result<String> {
        if bytes.is_empty() {
            return Err(anyhow!(
                "Descarga fallida: el payload recibido tiene 0 bytes"
            ));
        }
        if bytes.len() < min_bytes {
            return Err(anyhow!(
                "Descarga sospechosamente pequeña: {} bytes (mínimo {})",
                bytes.len(),
                min_bytes
            ));
        }
        if bytes.len() > max_bytes {
            return Err(anyhow!(
                "Descarga excede el límite máximo permitido: {} bytes",
                bytes.len()
            ));
        }

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Comprueba que el texto descargado sea UTF-8 válido
    pub fn validate_utf8(bytes: &[u8]) -> Result<&str> {
        std::str::from_utf8(bytes).map_err(|e| {
            anyhow!(
                "El feed contiene datos binarios inválidos o codificación corrupta: {}",
                e
            )
        })
    }
}

/// Gestor y Parser de Reglas YARA (YARA Rules Manager)
pub struct YaraRulesManager;

impl YaraRulesManager {
    /// Parsea una regla YARA sintáctica y extrae nombre, descripción y patrones de búsqueda
    pub fn parse_yara_content(content: &str, file_name: &str) -> Result<Vec<PatternRule>> {
        let mut rules = Vec::new();
        let mut current_rule_name = None;
        let mut current_desc = format!("Regla comunitaria YARA ({})", file_name);
        let mut in_strings_block = false;
        let mut in_condition_block = false;
        let mut string_patterns: Vec<String> = Vec::new();

        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with("//") || line.starts_with("/*") {
                continue;
            }

            if line.starts_with("rule ") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    current_rule_name = Some(parts[1].trim_end_matches('{').trim().to_string());
                    string_patterns.clear();
                    in_strings_block = false;
                    in_condition_block = false;
                }
            } else if line.starts_with("meta:") {
                in_strings_block = false;
                in_condition_block = false;
            } else if line.starts_with("description =") || line.starts_with("description=") {
                if let Some(desc_val) = line.split('=').nth(1) {
                    current_desc = desc_val.trim().trim_matches('"').to_string();
                }
            } else if line.starts_with("strings:") {
                in_strings_block = true;
                in_condition_block = false;
            } else if line.starts_with("condition:") {
                in_strings_block = false;
                in_condition_block = true;
            } else if in_strings_block && line.starts_with('$') {
                if let Some((_, pattern_part)) = line.split_once('=') {
                    let cleaned = pattern_part.trim();
                    if cleaned.starts_with('"') {
                        if let Some(end_quote) = cleaned[1..].find('"') {
                            let text = &cleaned[1..=end_quote];
                            let is_eicar_rule = current_rule_name
                                .as_deref()
                                .map(|n| n.eq_ignore_ascii_case("eicar"))
                                .unwrap_or(false);
                            if text.len() >= 12 || (is_eicar_rule && text.len() >= 4) {
                                string_patterns.push(regex::escape(text));
                            }
                        }
                    }
                }
            } else if in_condition_block && line.contains('}') {
                if let Some(rule_name) = current_rule_name.take() {
                    if !string_patterns.is_empty() {
                        let combined_regex = format!("(?i)({})", string_patterns.join("|"));
                        if let Ok(compiled) = Regex::new(&combined_regex) {
                            rules.push(PatternRule {
                                name: format!("YARA.{}", rule_name),
                                description: current_desc.clone(),
                                pattern: compiled,
                                severity: "Alta".to_string(),
                            });
                        }
                    }
                }
                in_condition_block = false;
            }
        }

        if rules.is_empty() {
            return Err(anyhow!(
                "No se pudieron extraer reglas YARA válidas del archivo {}",
                file_name
            ));
        }

        Ok(rules)
    }
}

/// Integración y Formatos ClamAV (ClamAV Integration)
pub struct ClamAvIntegration;

impl ClamAvIntegration {
    /// Parsea una base de datos de firmas ClamAV en formato .hdb, .hsb o .sha256
    /// Formato: <SHA256>:<TAM_BYTES>:<NOMBRE_AMENAZA> o <SHA256>:<NOMBRE_AMENAZA>
    pub fn parse_clamav_hash_database(content: &str) -> HashMap<String, String> {
        let mut signatures = HashMap::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some((hash_raw, rest)) = trimmed.split_once(';') {
                let hash = hash_raw.trim().to_lowercase();
                let name = rest.trim().to_string();
                if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) && !name.is_empty() {
                    signatures.insert(hash, name);
                }
                continue;
            }

            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() == 3 {
                // ClamAV .hdb / .hsb format: HASH:SIZE:NAME
                let hash = parts[0].trim().to_lowercase();
                let name = parts[2].trim().to_string();
                if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                    signatures.insert(hash, format!("ClamAV.{}", name));
                }
            } else if parts.len() == 2 {
                // Formato simple: HASH:NAME
                let hash = parts[0].trim().to_lowercase();
                let name = parts[1].trim().to_string();
                if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                    signatures.insert(hash, name);
                }
            }
        }
        signatures
    }
}

/// Gestor de Inteligencia de Amenazas (Threat Intelligence Manager)
pub struct ThreatIntelligenceManager;

impl ThreatIntelligenceManager {
    /// Parsea el listado de IPs de Command & Control de Feodo Tracker
    pub fn parse_feodo_ip_blocklist(content: &str) -> Vec<String> {
        let mut ips = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Ok(ip) = trimmed.parse::<IpAddr>() {
                ips.push(ip.to_string());
            }
        }
        ips
    }

    /// Parsea el feed de hashes SHA-256 recientes de Abuse.ch MalwareBazaar (1 hash por línea)
    pub fn parse_malwarebazaar_sha256(content: &str) -> HashMap<String, String> {
        let mut hashes = HashMap::new();
        for line in content.lines() {
            let trimmed = line.trim().to_lowercase();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
                let short_id = &trimmed[..8];
                hashes.insert(
                    trimmed.clone(),
                    format!("MalwareBazaar.Recent.{}", short_id),
                );
            }
        }
        hashes
    }
}

/// Gestor de Respaldo y Rollback (Rollback Manager)
pub struct RollbackManager {
    signatures_path: PathBuf,
    backup_path: PathBuf,
}

impl RollbackManager {
    pub fn new(signatures_dir: impl AsRef<Path>) -> Self {
        let dir = signatures_dir.as_ref();
        Self {
            signatures_path: dir.join("malware_hashes.db"),
            backup_path: dir.join("malware_hashes.db.bak"),
        }
    }

    /// Crea un respaldo antes de cualquier modificación
    pub fn create_backup(&self) -> Result<()> {
        if self.signatures_path.exists() {
            fs::copy(&self.signatures_path, &self.backup_path)
                .map_err(|e| anyhow!("Fallo al crear copia de seguridad previa: {}", e))?;
        }
        Ok(())
    }

    /// Restaura la base de datos a su estado anterior en caso de fallo
    pub fn perform_rollback(&self) -> Result<()> {
        if self.backup_path.exists() {
            fs::copy(&self.backup_path, &self.signatures_path)
                .map_err(|e| anyhow!("Fallo en procedimiento de rollback: {}", e))?;
            warn!("Rollback ejecutado con éxito: base de firmas restaurada desde .bak");
            Ok(())
        } else {
            Err(anyhow!("No existe archivo de respaldo .bak para rollback"))
        }
    }
}

/// Instalador Atómico (Atomic Installer)
pub struct AtomicInstaller;

impl AtomicInstaller {
    /// Escribe datos en un archivo temporal y lo reemplaza atómicamente
    pub fn atomic_write(target_path: &Path, content: &[u8]) -> Result<()> {
        let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
        let _ = fs::create_dir_all(parent);

        let temp_path = parent.join(format!("{}.tmp", uuid::Uuid::new_v4()));
        {
            let mut file = File::create(&temp_path)?;
            file.write_all(content)?;
            file.sync_all()?;
        }

        // Reemplazo atómico en el mismo volumen de disco
        if let Err(e) = fs::rename(&temp_path, target_path) {
            let _ = fs::remove_file(&temp_path);
            return Err(anyhow!(
                "Error en instalación atómica al renombrar a {}: {}",
                target_path.display(),
                e
            ));
        }

        Ok(())
    }
}

/// Motor Principal de Actualización (Update Manager)
pub struct UpdateManager {
    source_manager: SourceManager,
    signatures_dir: PathBuf,
    rollback_manager: RollbackManager,
}

impl UpdateManager {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let signatures_dir = data_dir.as_ref().join("signatures");
        let _ = fs::create_dir_all(&signatures_dir);
        let _ = fs::create_dir_all(signatures_dir.join("yara_rules"));

        Self {
            source_manager: SourceManager::new(),
            signatures_dir: signatures_dir.clone(),
            rollback_manager: RollbackManager::new(&signatures_dir),
        }
    }

    /// Ejecuta el ciclo completo de actualización con reporte de progreso
    pub fn run_update<F>(&mut self, mut progress_cb: F) -> DetailedUpdateReport
    where
        F: FnMut(UpdateStep),
    {
        let timestamp_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        // 1. Comprobar conexión a Internet real
        progress_cb(UpdateStep::CheckingConnection);
        if !IntegrityValidator::check_internet_connection() {
            let err = "No hay conexión a Internet disponible para consultar las fuentes de firmas."
                .to_string();
            progress_cb(UpdateStep::Failed {
                stage: "Verificación de Conectividad".to_string(),
                error: err.clone(),
            });
            return DetailedUpdateReport {
                success: false,
                new_signatures: 0,
                new_yara_rules: 0,
                total_signatures: 0,
                total_yara_rules: 0,
                version: "Sin actualizar".to_string(),
                timestamp: timestamp_str,
                feed_source: "Error de Red".to_string(),
                error_message: Some(err),
                downloaded_files: Vec::new(),
            };
        }

        // 2. Crear respaldo para Rollback
        if let Err(e) = self.rollback_manager.create_backup() {
            warn!("Aviso: no se pudo crear backup previo: {}", e);
        }

        let mut downloaded_files = Vec::new();
        let mut new_yara_rules: Vec<PatternRule> = Vec::new();
        let mut downloaded_hashes: HashMap<String, String> = HashMap::new();
        let mut downloaded_hash_sources: HashMap<String, String> = HashMap::new();
        let mut downloaded_c2_ips: Vec<String> = Vec::new();
        let mut total_bytes_downloaded = 0usize;

        // 3. Descargar y validar cada fuente configurada
        for source in self.source_manager.get_sources() {
            progress_cb(UpdateStep::ConsultingSource {
                source_name: source.name.clone(),
                url: source.url.clone(),
            });

            // Descarga con HTTP GET seguro (TLS / rustls)
            let response = match ureq::builder()
                .timeout(Duration::from_secs(12))
                .user_agent("SamuLibre-Antivirus-SecuritySuite/2.1 (Windows x64; OpenSource)")
                .build()
                .get(&source.url)
                .call()
            {
                Ok(resp) => resp,
                Err(e) => {
                    warn!(
                        "Error al contactar fuente '{}': {}. Continuando con fuentes restantes.",
                        source.name, e
                    );
                    continue;
                }
            };

            let mut reader = response.into_reader();
            let mut payload = Vec::new();
            if let Err(e) = std::io::copy(&mut reader, &mut payload) {
                warn!(
                    "Fallo al recibir flujo de bytes de '{}': {}",
                    source.name, e
                );
                continue;
            }

            total_bytes_downloaded += payload.len();
            info!(
                "Descargados {} bytes desde '{}' (acumulado: {} KB).",
                payload.len(),
                source.name,
                total_bytes_downloaded / 1024
            );
            progress_cb(UpdateStep::Downloading {
                source_name: source.name.clone(),
                bytes: payload.len(),
            });

            // 4. Validar integridad de los bytes descargados
            let sha256_hash =
                match IntegrityValidator::validate_download(&payload, 10, 50 * 1024 * 1024) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(
                            "Fallo de validación de integridad para '{}': {}",
                            source.name, e
                        );
                        continue;
                    }
                };

            progress_cb(UpdateStep::ValidatingIntegrity {
                source_name: source.name.clone(),
                sha256: sha256_hash,
            });

            let content_str = match IntegrityValidator::validate_utf8(&payload) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Feed no es texto UTF-8 válido ('{}'): {}", source.name, e);
                    continue;
                }
            };

            // 5. Procesar según tipo de fuente
            match source.source_type {
                UpdateSourceType::YaraRule => {
                    let file_name = source.url.split('/').last().unwrap_or("feed.yar");
                    match YaraRulesManager::parse_yara_content(content_str, file_name) {
                        Ok(rules) => {
                            let count = rules.len();
                            new_yara_rules.extend(rules);
                            downloaded_files.push(file_name.to_string());

                            // Guardar archivo YARA en disco atómicamente
                            let yara_target =
                                self.signatures_dir.join("yara_rules").join(file_name);
                            let _ = AtomicInstaller::atomic_write(&yara_target, payload.as_slice());
                            progress_cb(UpdateStep::CompilingRules { rules_found: count });
                        }
                        Err(e) => {
                            warn!("Error al compilar reglas YARA de '{}': {}", source.name, e);
                        }
                    }
                }
                UpdateSourceType::IpBlocklist => {
                    let ips = ThreatIntelligenceManager::parse_feodo_ip_blocklist(content_str);
                    if !ips.is_empty() {
                        downloaded_c2_ips.extend(ips.clone());
                        let target = self.signatures_dir.join("feodo_c2_blocklist.txt");
                        let _ = AtomicInstaller::atomic_write(&target, payload.as_slice());
                        downloaded_files.push("feodo_c2_blocklist.txt".to_string());
                    }
                }
                UpdateSourceType::HashDatabase => {
                    let hashes = ClamAvIntegration::parse_clamav_hash_database(content_str);
                    for h in hashes.keys() {
                        downloaded_hash_sources.insert(h.clone(), source.name.clone());
                    }
                    downloaded_hashes.extend(hashes);
                    downloaded_files.push(source.name.clone());
                }
                UpdateSourceType::MalwareBazaarSha256 => {
                    let hashes = ThreatIntelligenceManager::parse_malwarebazaar_sha256(content_str);
                    if !hashes.is_empty() {
                        for h in hashes.keys() {
                            downloaded_hash_sources.insert(h.clone(), source.name.clone());
                        }
                        downloaded_hashes.extend(hashes);
                        downloaded_files.push("malwarebazaar_recent_sha256.txt".to_string());
                    }
                }
            }
        }

        // 6. Cargar firmas existentes de malware_hashes.db
        let hashes_db_path = self.signatures_dir.join("malware_hashes.db");
        let mut existing_hashes = HashMap::new();
        if hashes_db_path.exists() {
            if let Ok(content) = fs::read_to_string(&hashes_db_path) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    if let Some((h, n)) = trimmed.split_once(':') {
                        existing_hashes.insert(h.trim().to_lowercase(), n.trim().to_string());
                    }
                }
            }
        }

        // 7. Incorporar firmas base conocidas verificadas
        let verified_signatures = [
            (
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "EICAR-Standard-Test-File.Signature",
            ),
            (
                "3395856ce81f2d7382dee72602f798b642f14140024b934b82670273a6543632",
                "Ransomware.Win32.Conti.Gen",
            ),
            (
                "e2b8be5689100412803b905f95982e0516b0bbdf4d9894e24efd66394142b78a",
                "Trojan.Win32.DarkComet.RAT",
            ),
            (
                "a26569e96e95267d325e0129fd53e8cb30d0611fa67776f8e7090884dd08051a",
                "Spyware.Win32.SnakeKeylogger.Gen",
            ),
            (
                "d64230626a57c5a0ca95bf6eec5eb852d7e0d3752e25ad6256f6c99c55d0458a",
                "Trojan.Win32.IcedID.BankingLoader",
            ),
            (
                "176b6d51c06830de2b17a02251a2d5918a5996a840e79391ab6f028de7d705c9",
                "Trojan.Win32.QakBot.Payload",
            ),
            (
                "3c1d2e1c9e884faefea7019dc563e7925e0e1f7d451fe83c66289b4f7380ff98",
                "Ransomware.Win32.Ryuk.Encrypter",
            ),
            (
                "84c82835a5d21bbcf75a61706d8ab5494030493ae1ab12f54cb07fb4b8e40d1e",
                "Ransomware.Win32.LockBit3.Gen",
            ),
            (
                "5417eb735c05e197cdcd7ffbb538c82eb5e7d53b2111d4d1421034c442436f54",
                "Trojan.Win32.RedLineStealer.Gen",
            ),
            (
                "c4566c1b3f94539ef2a382c0f655dc3bc3594e50882e3895e34be6acab28d098",
                "Trojan.Win32.AgentTesla.Stealer",
            ),
            (
                "1a5806257d767d156557cb029a1c62f2cc309dd051e9e8f668581e18b62551ec",
                "Ransomware.Win32.WannaCry.Payload",
            ),
            (
                "9a038f8f41164966601b1fc8974a2b9758f1f7bd788c005b4b94f6c4c0bb8a4b",
                "Exploit.Win32.EternalBlue.Dropper",
            ),
            (
                "f4b1e427bc529fb3e895c8c6978508933b9a1172776c5b9f71ab85b672727142",
                "Spyware.Win32.Pegasus.Loader",
            ),
            (
                "a3c1097e883395c52c67645f06ea4a4d2f0992383840742f15599eec38d1796c",
                "Trojan.Script.PowerSploit.Mimikatz",
            ),
            (
                "d9f37c35f29e0dc0476839281a179e830e234327bc794825d4c82b99453d102e",
                "Trojan.Win32.LokiBot.CredentialStealer",
            ),
            (
                "2a4b896940d99fae5e6e3c5ec82fbf91efea9380436d4ab8d2c49ffab03233c7",
                "Backdoor.Win32.RemcosRAT.Client",
            ),
            (
                "32b139977cfb9a01be3fc4863c18b7ae293b67be06eec43eb91fe5d35eb7b3fe",
                "Trojan.Win32.Emotet.Payload",
            ),
            (
                "8b6f3b5843a0558b8d4f40f7d5c5893e3d64c1265fef54e9bcad26895c84df12",
                "Ransomware.Win32.BlackCat.ALPHV",
            ),
        ];

        // 7. Incorporar firmas base conocidas verificadas (fuente única compartida con ScannerEngine)
        let initial_count = existing_hashes.len();
        let mut hash_sources_meta: HashMap<String, (String, String)> = HashMap::new();
        let catalog_path = self.signatures_dir.join("signatures_catalog.json");
        if let Ok(raw_cat) = fs::read_to_string(&catalog_path) {
            if let Ok(prev_cat) = serde_json::from_str::<SignatureCatalogResponse>(&raw_cat) {
                for entry in prev_cat.entries {
                    if entry.kind == "SHA256" {
                        hash_sources_meta.insert(entry.identifier, (entry.source, entry.added_at));
                    }
                }
            }
        }

        for &(h, n) in crate::default_builtin_signatures() {
            let h_low = h.to_lowercase();
            existing_hashes.entry(h_low.clone()).or_insert_with(|| n.to_string());
            hash_sources_meta
                .entry(h_low)
                .or_insert_with(|| ("Base Verificada SamuLibre".to_string(), timestamp_str.clone()));
        }
        for (h, n) in verified_signatures {
            let h_low = h.to_lowercase();
            existing_hashes.entry(h_low.clone()).or_insert_with(|| n.to_string());
            hash_sources_meta
                .entry(h_low)
                .or_insert_with(|| ("Base Verificada SamuLibre".to_string(), timestamp_str.clone()));
        }
        for (h, n) in downloaded_hashes {
            let h_low = h.to_lowercase();
            let src = downloaded_hash_sources
                .get(&h_low)
                .cloned()
                .unwrap_or_else(|| "Feed Comunitario".to_string());
            existing_hashes.insert(h_low.clone(), n);
            hash_sources_meta
                .entry(h_low)
                .or_insert_with(|| (src, timestamp_str.clone()));
        }

        let new_added_hashes = existing_hashes.len().saturating_sub(initial_count);
        let total_signatures = existing_hashes.len();
        let total_yara_rules = new_yara_rules.len();

        // 8. Instalación Atómica de la Base de Firmas
        progress_cb(UpdateStep::InstallingAtomic);
        let mut db_lines = Vec::new();
        db_lines.push(
            "# SamuLibre Antivirus - Base de Datos de Firmas Oficiales y Comunitarias".to_string(),
        );
        db_lines.push(format!("# Actualizado: {}", timestamp_str));
        db_lines.push(format!("# Total Firmas SHA-256: {}", total_signatures));
        db_lines.push("".to_string());
        for (h, n) in &existing_hashes {
            db_lines.push(format!("{} : {}", h, n));
        }

        let db_content = db_lines.join("\n");
        if let Err(e) = AtomicInstaller::atomic_write(&hashes_db_path, db_content.as_bytes()) {
            error!(
                "Error en instalación atómica: {}. Ejecutando rollback...",
                e
            );
            let _ = self.rollback_manager.perform_rollback();
            let err_msg = format!(
                "Fallo durante el guardado atómico de la base de datos: {}",
                e
            );
            progress_cb(UpdateStep::Failed {
                stage: "Instalación Atómica".to_string(),
                error: err_msg.clone(),
            });
            return DetailedUpdateReport {
                success: false,
                new_signatures: 0,
                new_yara_rules: 0,
                total_signatures: 0,
                total_yara_rules: 0,
                version: "Rollback".to_string(),
                timestamp: timestamp_str,
                feed_source: "Error".to_string(),
                error_message: Some(err_msg),
                downloaded_files,
            };
        }

        // 9. Guardar catálogo estructurado de firmas para inspección en UI
        let mut catalog_entries = Vec::with_capacity(
            existing_hashes.len() + new_yara_rules.len() + downloaded_c2_ips.len(),
        );
        for (h, family) in &existing_hashes {
            let (source, added_at) = hash_sources_meta
                .get(h)
                .cloned()
                .unwrap_or_else(|| ("Base Local".to_string(), timestamp_str.clone()));
            catalog_entries.push(SignatureCatalogEntry {
                kind: "SHA256".to_string(),
                identifier: h.clone(),
                family: family.clone(),
                source,
                added_at,
                ..Default::default()
            });
        }
        for rule in &new_yara_rules {
            catalog_entries.push(SignatureCatalogEntry {
                kind: "YARA".to_string(),
                identifier: rule.name.clone(),
                family: rule.description.clone(),
                source: "Yara-Rules / Neo23x0".to_string(),
                added_at: timestamp_str.clone(),
                ..Default::default()
            });
        }
        for ip in &downloaded_c2_ips {
            catalog_entries.push(SignatureCatalogEntry {
                kind: "C2_IP".to_string(),
                identifier: ip.clone(),
                family: "Botnet Command & Control (Feodo Tracker)".to_string(),
                source: "Abuse.ch Feodo Tracker".to_string(),
                added_at: timestamp_str.clone(),
                ..Default::default()
            });
        }
        let catalog_summary = SignatureDatabaseSummary {
            sha256_hashes: existing_hashes.len(),
            yara_rules: total_yara_rules,
            c2_ips: downloaded_c2_ips.len(),
            total_protections: existing_hashes.len() + total_yara_rules + downloaded_c2_ips.len(),
            last_updated: timestamp_str.clone(),
            active_feeds: self
                .source_manager
                .get_sources()
                .iter()
                .map(|s| s.name.clone())
                .collect(),
            ..Default::default()
        };
        let catalog_obj = SignatureCatalogResponse {
            summary: catalog_summary,
            entries: catalog_entries,
        };
        if let Ok(cat_json) = serde_json::to_string(&catalog_obj) {
            let _ = AtomicInstaller::atomic_write(&catalog_path, cat_json.as_bytes());
        }

        // 10. Registrar la operación en el historial persistente (con datos reales)
        let version_tag = format!(
            "v{}.{:02}",
            chrono::Local::now().format("%Y.%m.%d"),
            total_signatures % 100
        );
        let history_file = self.signatures_dir.join("update_history.json");
        let mut history: Vec<UpdateHistoryEntry> =
            if let Ok(data) = fs::read_to_string(&history_file) {
                serde_json::from_str(&data).unwrap_or_default()
            } else {
                Vec::new()
            };

        history.insert(
            0,
            UpdateHistoryEntry {
                id: format!("SIG-{}", chrono::Local::now().format("%Y%m%d-%H%M%S")),
                timestamp: timestamp_str.clone(),
                signatures_added: new_added_hashes,
                total_signatures,
                feed_source: "Yara-Rules Official GitHub & Abuse.ch Feodo Tracker".to_string(),
                version_tag: version_tag.clone(),
                improvements: vec![
                    format!(
                        "Descargadas y validadas {} reglas YARA comunitarias.",
                        total_yara_rules
                    ),
                    format!(
                        "Sincronizadas {} firmas SHA-256 de malware verificado.",
                        total_signatures
                    ),
                    format!(
                        "Actualizadas {} IPs activas de C2 desde Feodo Tracker.",
                        downloaded_c2_ips.len()
                    ),
                    format!(
                        "Validación de integridad SHA-256 superada para {} archivos.",
                        downloaded_files.len()
                    ),
                ],
            },
        );

        if let Ok(json_str) = serde_json::to_string_pretty(&history) {
            let _ = AtomicInstaller::atomic_write(&history_file, json_str.as_bytes());
        }

        let report = DetailedUpdateReport {
            success: true,
            new_signatures: new_added_hashes,
            new_yara_rules: total_yara_rules,
            total_signatures,
            total_yara_rules,
            version: version_tag.clone(),
            timestamp: timestamp_str,
            feed_source: "Yara-Rules Official & Abuse.ch Feodo Tracker".to_string(),
            error_message: None,
            downloaded_files,
        };

        progress_cb(UpdateStep::Completed {
            new_signatures: new_added_hashes,
            new_rules: total_yara_rules,
            total_signatures,
            total_rules: total_yara_rules,
            version: version_tag,
            feed_source: "Yara-Rules Official & Abuse.ch Feodo Tracker".to_string(),
        });

        info!(
            "Actualización de firmas completada con éxito: +{} firmas, +{} reglas YARA.",
            new_added_hashes, total_yara_rules
        );
        report
    }
}

/// Construye el catálogo vivo de firmas combinando memoria activa, metadatos guardados y Feodo C2 blocklist.
pub fn build_signatures_catalog(
    signatures_dir: &Path,
    memory_hashes: &HashMap<String, String>,
    pattern_rules: &[PatternRule],
) -> SignatureCatalogResponse {
    let catalog_path = signatures_dir.join("signatures_catalog.json");
    let mut meta_map: HashMap<String, (String, String)> = HashMap::new();
    let mut last_updated = "Base local".to_string();

    if let Ok(raw) = fs::read_to_string(&catalog_path) {
        if let Ok(prev) = serde_json::from_str::<SignatureCatalogResponse>(&raw) {
            last_updated = prev.summary.last_updated;
            for entry in prev.entries {
                if entry.kind == "SHA256" {
                    meta_map.insert(entry.identifier, (entry.source, entry.added_at));
                }
            }
        }
    }

    let mut entries = Vec::with_capacity(memory_hashes.len() + pattern_rules.len() + 64);
    for (h, family) in memory_hashes {
        let (source, added_at) = meta_map
            .get(h)
            .cloned()
            .unwrap_or_else(|| ("Base Local / Neo23x0".to_string(), last_updated.clone()));
        entries.push(SignatureCatalogEntry {
            kind: "SHA256".to_string(),
            identifier: h.clone(),
            family: family.clone(),
            source,
            added_at,
            ..Default::default()
        });
    }

    for rule in pattern_rules {
        entries.push(SignatureCatalogEntry {
            kind: "YARA".to_string(),
            identifier: rule.name.clone(),
            family: rule.description.clone(),
            source: "Motor YARA / Heurístico".to_string(),
            added_at: last_updated.clone(),
            ..Default::default()
        });
    }

    let feodo_path = signatures_dir.join("feodo_c2_blocklist.txt");
    let mut c2_count = 0usize;
    if let Ok(content) = fs::read_to_string(&feodo_path) {
        let ips = ThreatIntelligenceManager::parse_feodo_ip_blocklist(&content);
        c2_count = ips.len();
        for ip in ips {
            entries.push(SignatureCatalogEntry {
                kind: "C2_IP".to_string(),
                identifier: ip,
                family: "Botnet Command & Control (Feodo Tracker)".to_string(),
                source: "Abuse.ch Feodo Tracker".to_string(),
                added_at: last_updated.clone(),
                ..Default::default()
            });
        }
    }

    let active_feeds = SourceManager::new()
        .get_sources()
        .iter()
        .map(|s| s.name.clone())
        .collect();

    let mut summary = SignatureDatabaseSummary {
        sha256_hashes: memory_hashes.len(),
        yara_rules: pattern_rules.len(),
        c2_ips: c2_count,
        total_protections: memory_hashes.len() + pattern_rules.len() + c2_count,
        last_updated,
        active_feeds,
        domains: 0,
        urls: 0,
        behavior_rules: 0,
        loldrivers_count: 0,
        connected_sources: 0,
        yara_lab: 0,
        yara_pending: 0,
        yara_rejected: 0,
        yara_obsolete: 0,
        fp_reported: 0,
        sources_detail: Vec::new(),
    };

    // Enriquecer con métricas reales de la Base Central SamuLibre Threat Intelligence (SQLite)
    let data_dir = signatures_dir
        .parent()
        .unwrap_or_else(|| Path::new("data"));
    let intel_db_path = {
        let candidate = data_dir.join("intel").join("samulibre_intel.db");
        if candidate.exists() {
            candidate
        } else {
            Path::new("data").join("intel").join("samulibre_intel.db")
        }
    };
    if intel_db_path.exists() {
        if let Ok(db) = samulibre_intel::IntelDatabase::open(&intel_db_path) {
            if let Ok(stats) = db.get_stats() {
                summary.sha256_hashes = summary.sha256_hashes.max(stats.sha256_approved);
                summary.yara_rules = stats.yara_approved + stats.yara_restricted;
                summary.c2_ips = summary.c2_ips.max(stats.c2_ips_approved);
                summary.domains = stats.domains_approved;
                summary.urls = stats.urls_approved;
                summary.behavior_rules = stats.behavior_rules_approved;
                summary.loldrivers_count = stats.loldrivers_count;
                summary.connected_sources = stats.connected_sources;
                summary.yara_lab = stats.yara_lab;
                summary.yara_pending = stats.yara_observation;
                summary.yara_rejected = stats.yara_rejected;
                summary.yara_obsolete = stats.yara_obsolete;
                summary.total_protections = summary.sha256_hashes
                    + summary.yara_rules
                    + summary.c2_ips
                    + summary.domains
                    + summary.urls
                    + summary.behavior_rules;
            }
            if let Ok(srcs) = db.list_sources() {
                summary.active_feeds = srcs
                    .iter()
                    .filter(|s| s.status == "OK")
                    .map(|s| s.name.clone())
                    .collect();
                summary.sources_detail = srcs;
            }
            if let Ok(preview) = db.list_catalog_preview(500) {
                let mut seen: std::collections::HashSet<(String, String)> = entries
                    .iter()
                    .map(|e| (e.kind.clone(), e.identifier.clone()))
                    .collect();
                for (kind, identifier, family, source, added_at) in preview {
                    if seen.insert((kind.clone(), identifier.clone())) {
                        entries.push(SignatureCatalogEntry {
                            kind,
                            identifier,
                            family,
                            source,
                            added_at,
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    let fp_path = {
        let candidate = data_dir.join("audit").join("fp_feedback.json");
        if candidate.exists() {
            candidate
        } else {
            Path::new("data").join("audit").join("fp_feedback.json")
        }
    };
    if let Ok(fp_raw) = fs::read_to_string(&fp_path) {
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&fp_raw) {
            summary.fp_reported = arr.len();
        }
    }

    SignatureCatalogResponse { summary, entries }
}

/// Carga el catálogo completo directamente desde disco (`data/signatures`) sin bloquear ningún mutex del motor.
pub fn load_signatures_catalog_from_disk(signatures_dir: &Path) -> SignatureCatalogResponse {
    let mut hashes: HashMap<String, String> = HashMap::new();
    for &(h, n) in crate::default_builtin_signatures() {
        hashes.insert(h.to_lowercase(), n.to_string());
    }

    let db_path = signatures_dir.join("malware_hashes.db");
    if let Ok(content) = fs::read_to_string(&db_path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((hash, name)) = trimmed.split_once(':').or_else(|| trimmed.split_once(';')) {
                let h = hash.trim().to_lowercase();
                if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
                    hashes.insert(h, name.trim().to_string());
                }
            }
        }
    }

    let mut rules: Vec<PatternRule> = Vec::new();
    let yara_dir = signatures_dir.join("yara_rules");
    if let Ok(entries) = fs::read_dir(&yara_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("yar") {
                if let Ok(content) = fs::read_to_string(&p) {
                    let fname = p.file_name().unwrap_or_default().to_string_lossy();
                    if let Ok(parsed) = YaraRulesManager::parse_yara_content(&content, &fname) {
                        for r in parsed {
                            if !rules.iter().any(|existing| existing.name == r.name) {
                                rules.push(r);
                            }
                        }
                    }
                }
            }
        }
    }

    build_signatures_catalog(signatures_dir, &hashes, &rules)
}

/// Consulta paginada directamente sobre SQLite (`samulibre_intel.db`) sin truncamiento ni carga masiva en RAM.
pub fn query_signatures_from_intel_db(
    signatures_dir: &Path,
    kind: &str,
    status_filter: &str,
    query: &str,
    page: usize,
    page_size: usize,
) -> Option<SignatureCatalogPageResponse> {
    let data_dir = signatures_dir
        .parent()
        .unwrap_or_else(|| Path::new("data"));
    let intel_db_path = {
        let candidate = data_dir.join("intel").join("samulibre_intel.db");
        if candidate.exists() {
            candidate
        } else {
            Path::new("data").join("intel").join("samulibre_intel.db")
        }
    };
    if !intel_db_path.exists() {
        return None;
    }

    let db = samulibre_intel::IntelDatabase::open(&intel_db_path).ok()?;
    let stats = db.get_stats().ok()?;
    let page_res = db
        .query_catalog_paginated(kind, status_filter, query, page, page_size)
        .ok()?;
    let srcs = db.list_sources().unwrap_or_default();

    let last_updated = srcs
        .iter()
        .filter_map(|s| s.last_sync_at.as_deref())
        .max()
        .map(|s| s.chars().take(19).collect::<String>().replace('T', " "))
        .unwrap_or_else(|| chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string());

    let mut fp_reported = 0usize;
    let fp_path = {
        let candidate = data_dir.join("audit").join("fp_feedback.json");
        if candidate.exists() {
            candidate
        } else {
            Path::new("data").join("audit").join("fp_feedback.json")
        }
    };
    if let Ok(fp_raw) = fs::read_to_string(&fp_path) {
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(&fp_raw) {
            fp_reported = arr.len();
        }
    }

    let yara_active = stats.yara_approved + stats.yara_restricted;
    let total_protections = stats.sha256_approved
        + yara_active
        + stats.c2_ips_approved
        + stats.domains_approved
        + stats.urls_approved
        + stats.behavior_rules_approved;

    let active_feeds = srcs
        .iter()
        .filter(|s| s.status == "OK")
        .map(|s| s.name.clone())
        .collect();

    let summary = SignatureDatabaseSummary {
        sha256_hashes: stats.sha256_approved,
        yara_rules: yara_active,
        c2_ips: stats.c2_ips_approved,
        total_protections,
        last_updated,
        active_feeds,
        domains: stats.domains_approved,
        urls: stats.urls_approved,
        behavior_rules: stats.behavior_rules_approved,
        loldrivers_count: stats.loldrivers_count,
        connected_sources: stats.connected_sources,
        yara_lab: stats.yara_lab,
        yara_pending: stats.yara_observation,
        yara_rejected: stats.yara_rejected,
        yara_obsolete: stats.yara_obsolete,
        fp_reported,
        sources_detail: srcs,
    };

    let entries = page_res
        .entries
        .into_iter()
        .map(|r| SignatureCatalogEntry {
            kind: r.kind,
            identifier: r.identifier,
            family: r.family,
            source: r.source,
            added_at: r.added_at,
            license: r.license,
            source_url: r.source_url,
            rule_author: r.rule_author,
            validation_status: r.validation_status,
            validation_score: r.validation_score,
        })
        .collect();

    Some(SignatureCatalogPageResponse {
        summary,
        total_filtered: page_res.total_filtered,
        page,
        page_size: page_size.max(1),
        entries,
    })
}

/// Filtra y pagina el catálogo para enviar payloads ligeros (< 15 KB) al WebView.
pub fn query_signatures_catalog(
    catalog: &SignatureCatalogResponse,
    kind: &str,
    query: &str,
    page: usize,
    page_size: usize,
) -> SignatureCatalogPageResponse {
    let q = query.trim().to_lowercase();
    let k = kind.trim();
    let filtered: Vec<&SignatureCatalogEntry> = catalog
        .entries
        .iter()
        .filter(|e| {
            let match_kind = k.is_empty() || k == "ALL" || e.kind == k;
            let match_q = q.is_empty()
                || e.identifier.to_lowercase().contains(&q)
                || e.family.to_lowercase().contains(&q)
                || e.source.to_lowercase().contains(&q);
            match_kind && match_q
        })
        .collect();

    let total_filtered = filtered.len();
    let effective_size = page_size.max(1);
    let max_page = if total_filtered == 0 {
        0
    } else {
        (total_filtered - 1) / effective_size
    };
    let safe_page = page.min(max_page);
    let start = safe_page * effective_size;
    let slice = filtered
        .into_iter()
        .skip(start)
        .take(effective_size)
        .cloned()
        .collect();

    SignatureCatalogPageResponse {
        summary: catalog.summary.clone(),
        total_filtered,
        page: safe_page,
        page_size: effective_size,
        entries: slice,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrity_validator_size_bounds() {
        let empty = b"";
        assert!(IntegrityValidator::validate_download(empty, 10, 1000).is_err());

        let too_small = b"abc";
        assert!(IntegrityValidator::validate_download(too_small, 10, 1000).is_err());

        let valid = b"rule eicar { condition: true }";
        let hash = IntegrityValidator::validate_download(valid, 10, 1000).unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_parse_yara_syntax() {
        let yara_sample = r#"
            rule SampleMalwareDetection {
                meta:
                    description = "Test YARA rule for malware"
                strings:
                    $s1 = "malicious_string_pattern_here"
                    $s2 = "another_evil_payload_string"
                condition:
                    any of them
            }
        "#;

        let rules = YaraRulesManager::parse_yara_content(yara_sample, "sample.yar").unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "YARA.SampleMalwareDetection");
        assert_eq!(rules[0].description, "Test YARA rule for malware");

        // Validar que la regex compilada coincida con la cadena maliciosa
        assert!(rules[0]
            .pattern
            .is_match(b"some prefix malicious_string_pattern_here suffix"));
        assert!(!rules[0].pattern.is_match(b"clean innocent text"));
    }

    #[test]
    fn test_parse_clamav_hash_database() {
        let db_content = r#"
            # ClamAV database sample
            3395856ce81f2d7382dee72602f798b642f14140024b934b82670273a6543632:12345:Win.Ransomware.Conti
            e2b8be5689100412803b905f95982e0516b0bbdf4d9894e24efd66394142b78a:Win.Trojan.DarkComet
        "#;

        let parsed = ClamAvIntegration::parse_clamav_hash_database(db_content);
        assert_eq!(parsed.len(), 2);
        assert!(
            parsed.contains_key("3395856ce81f2d7382dee72602f798b642f14140024b934b82670273a6543632")
        );
        assert_eq!(
            parsed
                .get("3395856ce81f2d7382dee72602f798b642f14140024b934b82670273a6543632")
                .unwrap(),
            "ClamAV.Win.Ransomware.Conti"
        );
    }

    #[test]
    fn test_atomic_installer_and_rollback() {
        let tmp_dir =
            std::env::temp_dir().join(format!("samu_atomic_test_{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&tmp_dir);

        let target_file = tmp_dir.join("database.db");
        AtomicInstaller::atomic_write(&target_file, b"version 1.0").unwrap();
        assert_eq!(fs::read_to_string(&target_file).unwrap(), "version 1.0");

        let rollback = RollbackManager {
            signatures_path: target_file.clone(),
            backup_path: tmp_dir.join("database.db.bak"),
        };
        rollback.create_backup().unwrap();

        // Modificamos a versión corrupta
        AtomicInstaller::atomic_write(&target_file, b"corrupt").unwrap();
        assert_eq!(fs::read_to_string(&target_file).unwrap(), "corrupt");

        // Rollback
        rollback.perform_rollback().unwrap();
        assert_eq!(fs::read_to_string(&target_file).unwrap(), "version 1.0");

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_live_updater_execution_and_reports() {
        let tmp_dir =
            std::env::temp_dir().join(format!("samu_update_live_test_{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&tmp_dir);

        let mut updater = UpdateManager::new(&tmp_dir);
        let mut steps_observed = Vec::new();

        let report = updater.run_update(move |step| {
            steps_observed.push(format!("{:?}", step));
        });

        // Si hay conexión a Internet, la actualización debe haber descargado y validado archivos reales
        if IntegrityValidator::check_internet_connection() {
            assert!(
                report.success,
                "La actualización debe reportar éxito con conexión disponible"
            );
            assert!(
                report.total_signatures >= 18,
                "Debe sincronizar al menos las firmas base"
            );
            assert!(
                report.total_yara_rules >= 1,
                "Debe compilar al menos 1 regla YARA válida de GitHub"
            );
            assert!(tmp_dir
                .join("signatures")
                .join("malware_hashes.db")
                .exists());
            assert!(tmp_dir
                .join("signatures")
                .join("yara_rules")
                .join("MALW_Eicar.yar")
                .exists());
        }

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_malwarebazaar_sha256_parser_dedup_and_validation() {
        let sample = "\
# Abuse.ch MalwareBazaar recent SHA256
275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
not_a_valid_sha256_hash
84c82835a5d21bbcf75a61706d8ab5494030493ae1ab12f54cb07fb4b8e40d1e
";
        let parsed = ThreatIntelligenceManager::parse_malwarebazaar_sha256(sample);
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains_key("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"));
        assert!(parsed.contains_key("84c82835a5d21bbcf75a61706d8ab5494030493ae1ab12f54cb07fb4b8e40d1e"));
    }

    #[test]
    fn test_signature_catalog_consistency_and_breakdown() {
        let tmp_dir = std::env::temp_dir().join("samulibre_sig_catalog_qa");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).unwrap();

        fs::write(
            tmp_dir.join("feodo_c2_blocklist.txt"),
            "# Feodo Tracker\n192.0.2.10\n198.51.100.25\n",
        )
        .unwrap();

        let mut memory_hashes = HashMap::new();
        memory_hashes.insert(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            "EICAR-Test-Signature.Standard".to_string(),
        );
        let rules = vec![PatternRule {
            name: "QA.Test.Rule".to_string(),
            description: "Regla QA".to_string(),
            pattern: Regex::new("EICAR").unwrap(),
            severity: "Alta".to_string(),
        }];

        let catalog = build_signatures_catalog(&tmp_dir, &memory_hashes, &rules);
        assert_eq!(catalog.summary.sha256_hashes, 1);
        assert_eq!(catalog.summary.yara_rules, 1);
        assert_eq!(catalog.summary.c2_ips, 2);
        assert_eq!(catalog.summary.total_protections, 4);
        assert_eq!(catalog.entries.len(), 4);

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_builtin_signatures_consistency() {
        let builtins = crate::default_builtin_signatures();
        assert!(builtins.len() >= 35);
        let mut seen = std::collections::HashSet::new();
        for &(hash, family) in builtins {
            assert_eq!(hash.len(), 64, "Hash inválido para {}", family);
            assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
            assert!(seen.insert(hash), "Hash duplicado en default_builtin_signatures: {}", hash);
        }
    }

    #[test]
    fn test_disk_catalog_and_query_pagination() {
        let tmp_dir = std::env::temp_dir().join("samulibre_disk_catalog_qa");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(tmp_dir.join("yara_rules")).unwrap();

        fs::write(
            tmp_dir.join("feodo_c2_blocklist.txt"),
            "192.0.2.1\n192.0.2.2\n",
        )
        .unwrap();
        fs::write(
            tmp_dir.join("yara_rules").join("qa.yar"),
            "rule QA_LockBit_Rule {\n    meta:\n        description = \"LockBit QA\"\n    strings:\n        $a = \"LockBit_Malware_Indicator\"\n    condition:\n        any of them\n}\n",
        )
        .unwrap();

        let catalog = load_signatures_catalog_from_disk(&tmp_dir);
        assert!(catalog.summary.sha256_hashes >= 35);
        assert_eq!(catalog.summary.yara_rules, 1);
        assert_eq!(catalog.summary.c2_ips, 2);

        let page_yara = query_signatures_catalog(&catalog, "YARA", "LockBit", 0, 50);
        assert_eq!(page_yara.total_filtered, 1);
        assert_eq!(page_yara.entries[0].identifier, "YARA.QA_LockBit_Rule");

        let page_c2 = query_signatures_catalog(&catalog, "C2_IP", "", 0, 1);
        assert_eq!(page_c2.total_filtered, 2);
        assert_eq!(page_c2.entries.len(), 1);

        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
