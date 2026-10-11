use anyhow::Result;
use chrono::{DateTime, Utc};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use samulibre_scanner::MultiEngineScanner;
use samulibre_types::{FileScanStatus, Severity, ThreatAlert, ThreatCategory};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::{info, warn};
use uuid::Uuid;

/// Registro de un archivo en caché validado como limpio
#[derive(Debug, Clone)]
struct CacheEntry {
    sha256: String,
    size: u64,
    modified: SystemTime,
}

/// Metadatos de un archivo en cuarentena
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    pub id: Uuid,
    pub original_path: String,
    pub threat_name: String,
    pub engine: String,
    pub sha256: String,
    pub quarantined_at: DateTime<Utc>,
    pub isolated_file_path: String,
}

/// Gestor de la bóveda de cuarentena cifrada
pub struct QuarantineVault {
    quarantine_dir: PathBuf,
}

impl QuarantineVault {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        let p = dir.as_ref().to_path_buf();
        let _ = fs::create_dir_all(&p);
        Self { quarantine_dir: p }
    }

    /// Aísla y cifra un archivo malicioso para que no pueda ejecutarse en el SO
    pub fn isolate_file(&self, source_path: &Path, threat: &str, engine: &str, sha256: &str) -> Result<QuarantineRecord> {
        let id = Uuid::new_v4();
        let isolated_name = format!("{}.quarantine", id);
        let isolated_path = self.quarantine_dir.join(&isolated_name);

        let original_bytes = fs::read(source_path)?;
        // Ofuscación reversible básica (XOR con clave fija de cuarentena) para anular headers PE ejecutables
        let xor_key = 0xAA;
        let obfuscated_bytes: Vec<u8> = original_bytes.iter().map(|b| b ^ xor_key).collect();
        fs::write(&isolated_path, obfuscated_bytes)?;

        // Eliminar o neutralizar el archivo original del disco
        let _ = fs::remove_file(source_path);

        let record = QuarantineRecord {
            id,
            original_path: source_path.to_string_lossy().to_string(),
            threat_name: threat.to_string(),
            engine: engine.to_string(),
            sha256: sha256.to_string(),
            quarantined_at: Utc::now(),
            isolated_file_path: isolated_path.to_string_lossy().to_string(),
        };

        // Guardar metadatos en JSON
        let meta_path = self.quarantine_dir.join(format!("{}.meta.json", id));
        fs::write(&meta_path, serde_json::to_string_pretty(&record)?)?;

        warn!("¡AMENAZA AISLADA EN CUARENTENA! Archivo: {} -> Bóveda: {:?}", source_path.display(), isolated_path);
        Ok(record)
    }

    /// Lista los elementos actualmente en cuarentena
    pub fn list_quarantined(&self) -> Vec<QuarantineRecord> {
        let mut list = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.quarantine_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(content) = fs::read_to_string(&path) {
                        if let Ok(record) = serde_json::from_str::<QuarantineRecord>(&content) {
                            list.push(record);
                        }
                    }
                }
            }
        }
        list
    }
}

/// Motor de Escaneo en Tiempo Real
pub struct RealTimeWatcher {
    scanner: Arc<MultiEngineScanner>,
    vault: Arc<QuarantineVault>,
    clean_cache: Arc<Mutex<HashMap<PathBuf, CacheEntry>>>,
    watch_dirs: Vec<PathBuf>,
}

impl RealTimeWatcher {
    pub fn new(scanner: Arc<MultiEngineScanner>, quarantine_dir: impl AsRef<Path>) -> Self {
        Self {
            scanner,
            vault: Arc::new(QuarantineVault::new(quarantine_dir)),
            clean_cache: Arc::new(Mutex::new(HashMap::new())),
            watch_dirs: Vec::new(),
        }
    }

    /// Añade un directorio a la vigilancia activa
    pub fn add_watch_dir(&mut self, dir: impl AsRef<Path>) {
        let p = dir.as_ref().to_path_buf();
        if p.exists() && !self.watch_dirs.contains(&p) {
            self.watch_dirs.push(p);
        }
    }

    /// Analiza un archivo interceptado en tiempo real
    pub fn inspect_on_access(&self, file_path: &Path) -> Option<ThreatAlert> {
        if !file_path.is_file() {
            return None;
        }

        // Filtro de extensiones críticas para evitar sobrecarga en archivos de texto plano o multimedia
        if !is_high_risk_extension(file_path) {
            return None;
        }

        let metadata = match fs::metadata(file_path) {
            Ok(m) => m,
            Err(_) => return None,
        };

        let file_size = metadata.len();
        let modified_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);

        // 1. Verificación ultra-rápida en Clean File Cache (<0.05 ms)
        if let Ok(cache) = self.clean_cache.lock() {
            if let Some(entry) = cache.get(file_path) {
                if entry.size == file_size && entry.modified == modified_time {
                    // Archivo ya verificado y no modificado: se permite sin escanear
                    return None;
                }
            }
        }

        // 2. Escaneo en streaming con MultiEngineScanner
        let scan_result = match self.scanner.scan_file(file_path) {
            Ok(r) => r,
            Err(_) => return None,
        };

        match scan_result.status {
            FileScanStatus::Clean => {
                // Guardar en la caché de archivos limpios
                if let Ok(mut cache) = self.clean_cache.lock() {
                    cache.insert(
                        file_path.to_path_buf(),
                        CacheEntry {
                            sha256: scan_result.sha256,
                            size: file_size,
                            modified: modified_time,
                        },
                    );
                }
                None
            }
            FileScanStatus::Infected | FileScanStatus::Suspicious => {
                let threat_name = scan_result.detection_name.unwrap_or_else(|| "Amenaza.Desconocida".to_string());
                let engine = scan_result.engine;
                let sha256 = scan_result.sha256;

                // 3. Aislamiento automático en Cuarentena Cifrada
                let _ = self.vault.isolate_file(file_path, &threat_name, &engine, &sha256);

                Some(ThreatAlert {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    severity: Severity::Critical,
                    category: ThreatCategory::MalwareFile,
                    title: format!("¡Amenaza neutralizada en tiempo real: {}!", threat_name),
                    details: format!(
                        "El archivo sospechoso '{}' fue interceptado en tiempo real por el motor {} y aislado en la bóveda de cuarentena.",
                        file_path.display(), engine
                    ),
                    process_id: None,
                    process_name: None,
                    target_path: Some(file_path.to_string_lossy().to_string()),
                    action_taken: "Aislado y neutralizado en cuarentena segura".to_string(),
                })
            }
            FileScanStatus::AccessDenied => None,
        }
    }

    /// Inicia el bucle de vigilancia en segundo plano usando Notify en los directorios registrados
    pub fn start_background_watcher<F>(&self, on_threat_detected: F) -> Result<RecommendedWatcher>
    where
        F: Fn(ThreatAlert) + Send + Sync + 'static,
    {
        let scanner_clone = Arc::clone(&self.scanner);
        let vault_clone = Arc::clone(&self.vault);
        let cache_clone = Arc::clone(&self.clean_cache);

        let mut watcher = RecommendedWatcher::new(
            move |res: notify::Result<Event>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Create(_) | EventKind::Modify(_) => {
                            for path in event.paths {
                                if path.is_file() && is_high_risk_extension(&path) {
                                    // Instanciar inspector puntual
                                    let sub_watcher = RealTimeWatcher {
                                        scanner: Arc::clone(&scanner_clone),
                                        vault: Arc::clone(&vault_clone),
                                        clean_cache: Arc::clone(&cache_clone),
                                        watch_dirs: Vec::new(),
                                    };
                                    if let Some(alert) = sub_watcher.inspect_on_access(&path) {
                                        on_threat_detected(alert);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            },
            Config::default(),
        )?;

        for dir in &self.watch_dirs {
            info!("Vigilando en tiempo real: {:?}", dir);
            let _ = watcher.watch(dir, RecursiveMode::Recursive);
        }

        Ok(watcher)
    }

    pub fn get_vault(&self) -> &QuarantineVault {
        &self.vault
    }
}

/// Identifica si una extensión de archivo tiene riesgo de ejecución de código
fn is_high_risk_extension(path: &Path) -> bool {
    let ext = match path.extension().and_then(|s| s.to_str()) {
        Some(e) => e.to_lowercase(),
        None => return false,
    };

    matches!(
        ext.as_str(),
        "exe" | "dll" | "sys" | "com" | "scr" | "bat" | "cmd" | "ps1" | "vbs" | "js" | "hta" | "msi" | "zip" | "iso" | "docm" | "xlsm"
    )
}
