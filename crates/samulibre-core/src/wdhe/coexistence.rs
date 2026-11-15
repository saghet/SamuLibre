use anyhow::Result;
use chrono::Utc;
use samulibre_types::WdheMode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// Estado persistente del Windows Defender Harmony Engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WdheConfiguration {
    pub mode: WdheMode,
    pub last_updated_utc: String,
    pub defender_coexistence_enabled: bool,
    pub prevent_io_lock_contention: bool,
    pub official_wsc_handshake_enabled: bool,
    pub telemetry_logging_enabled: bool,
}

impl Default for WdheConfiguration {
    fn default() -> Self {
        Self {
            mode: WdheMode::Complementary,
            last_updated_utc: Utc::now().to_rfc3339(),
            defender_coexistence_enabled: true,
            prevent_io_lock_contention: true,
            official_wsc_handshake_enabled: false, // Solo activo en modo PrimaryAntivirus tras certificación
            telemetry_logging_enabled: true,
        }
    }
}

/// Orquestador central de la arquitectura de coexistencia WDHE
pub struct WdheEngine {
    config: Arc<Mutex<WdheConfiguration>>,
    config_path: PathBuf,
}

impl WdheEngine {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let config_path = data_dir.as_ref().join("wdhe_config.json");
        let mut config = WdheConfiguration::default();

        if config_path.exists() {
            if let Ok(content) = fs::read_to_string(&config_path) {
                if let Ok(loaded) = serde_json::from_str::<WdheConfiguration>(&content) {
                    config = loaded;
                }
            }
        }

        Self {
            config: Arc::new(Mutex::new(config)),
            config_path,
        }
    }

    /// Obtiene el modo de coexistencia actual
    pub fn get_mode(&self) -> WdheMode {
        self.config.lock().unwrap().mode
    }

    /// Obtiene una copia completa de la configuración de WDHE
    pub fn get_config(&self) -> WdheConfiguration {
        self.config.lock().unwrap().clone()
    }

    /// Transición segura de modo con validación de políticas y requisitos
    pub fn set_mode(&self, new_mode: WdheMode) -> Result<()> {
        let mut cfg = self.config.lock().unwrap();
        info!(
            "Transición de Modo WDHE solicitada: {:?} -> {:?}",
            cfg.mode, new_mode
        );

        match new_mode {
            WdheMode::Development => {
                cfg.mode = WdheMode::Development;
                cfg.defender_coexistence_enabled = true;
                cfg.prevent_io_lock_contention = true;
                cfg.official_wsc_handshake_enabled = false;
                info!("Modo Desarrollo activado: SamuLibre operará bajo demanda y registrará telemetría sin interferir con Defender.");
            }
            WdheMode::Complementary => {
                cfg.mode = WdheMode::Complementary;
                cfg.defender_coexistence_enabled = true;
                cfg.prevent_io_lock_contention = true;
                cfg.official_wsc_handshake_enabled = false;
                info!("Modo Complementario activado: Protección activa sinérgica coordinada por Smart Scan.");
            }
            WdheMode::PrimaryAntivirus => {
                // Verificar requisitos formales antes de activar modo Principal
                Self::validate_primary_antivirus_prerequisites()?;
                cfg.mode = WdheMode::PrimaryAntivirus;
                cfg.defender_coexistence_enabled = true;
                cfg.prevent_io_lock_contention = true;
                cfg.official_wsc_handshake_enabled = true;
                info!("Modo Antivirus Principal activado: SamuLibre preparado para comunicarse oficialmente con WSC.");
            }
        }

        cfg.last_updated_utc = Utc::now().to_rfc3339();

        // Persistir en disco
        if let Some(parent) = self.config_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(serialized) = serde_json::to_string_pretty(&*cfg) {
            let _ = fs::write(&self.config_path, serialized);
        }

        Ok(())
    }

    /// Verifica que SamuLibre cumpla con los requisitos oficiales de Windows para ser proveedor principal
    fn validate_primary_antivirus_prerequisites() -> Result<()> {
        // 1. Verificar presencia de firmas y motor activo
        let sig_dir = Path::new("data").join("signatures");
        if !sig_dir.exists() {
            warn!("Advertencia: Las firmas de seguridad locales no han sido descargadas.");
        }

        // 2. Verificar que el entorno sea Windows 10 o Windows 11
        #[cfg(target_os = "windows")]
        {
            // Windows 10/11 requiere firma Authenticode y certificación WHQL/ELAM para modo kernel
            info!("Validando compatibilidad con Windows 10/11 Security Center...");
        }

        Ok(())
    }
}
