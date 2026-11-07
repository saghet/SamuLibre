use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Estado de la autoprotección del antivirus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiTamperStatus {
    pub is_active: bool,
    pub protected_files_count: usize,
    pub protected_paths: Vec<String>,
    pub watchdog_alive: bool,
    pub tamper_attempts_detected: usize,
}

pub struct AntiTamperShield {
    protected_paths: Vec<PathBuf>,
    baseline_hashes: HashMap<PathBuf, String>,
    tamper_attempts: usize,
}

impl AntiTamperShield {
    pub fn new() -> Self {
        Self {
            protected_paths: Vec::new(),
            baseline_hashes: HashMap::new(),
            tamper_attempts: 0,
        }
    }

    /// Registra una ruta del antivirus que debe ser protegida contra manipulación
    pub fn add_protected_path(&mut self, path: impl AsRef<Path>) {
        let p = path.as_ref().to_path_buf();
        if !self.protected_paths.contains(&p) {
            if let Ok(bytes) = fs::read(&p) {
                let hash = hex::encode(Sha256::digest(&bytes));
                self.baseline_hashes.insert(p.clone(), hash);
            }
            self.protected_paths.push(p);
        }
    }

    /// Aplica endurecimiento de permisos (modo solo lectura en Windows / chmod 0700 en Linux)
    pub fn apply_hardening(&self) -> std::io::Result<()> {
        for path in &self.protected_paths {
            if path.exists() {
                #[cfg(target_os = "windows")]
                {
                    if let Ok(mut perms) = fs::metadata(path).map(|m| m.permissions()) {
                        perms.set_readonly(true);
                        let _ = fs::set_permissions(path, perms);
                    }
                }
                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
                }
            }
        }
        Ok(())
    }

    /// Inspecciona si los binarios o archivos de configuración del antivirus han sido alterados o borrados
    pub fn verify_integrity(&mut self) -> bool {
        let mut intact = true;
        for path in &self.protected_paths {
            if !path.exists() {
                warn!(
                    "ALERTA DE SEGURIDAD: Archivo protegido del antivirus ELIMINADO: {}",
                    path.display()
                );
                self.tamper_attempts += 1;
                intact = false;
                continue;
            }

            if let Some(expected_hash) = self.baseline_hashes.get(path) {
                if let Ok(bytes) = fs::read(path) {
                    let actual_hash = hex::encode(Sha256::digest(&bytes));
                    if &actual_hash != expected_hash {
                        warn!(
                            "ALERTA DE SEGURIDAD: Integridad violada en '{}'. Hash esperado: {}, Hash actual: {}",
                            path.display(), expected_hash, actual_hash
                        );
                        self.tamper_attempts += 1;
                        intact = false;
                    }
                } else {
                    self.tamper_attempts += 1;
                    intact = false;
                }
            }
        }
        intact
    }

    pub fn get_status(&self) -> AntiTamperStatus {
        AntiTamperStatus {
            is_active: true,
            protected_files_count: self.protected_paths.len(),
            protected_paths: self
                .protected_paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
            watchdog_alive: true,
            tamper_attempts_detected: self.tamper_attempts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_tamper_shield() {
        let mut shield = AntiTamperShield::new();
        let tmp_file = std::env::temp_dir().join("samulibre_anti_tamper_test.bin");
        let _ = fs::write(&tmp_file, "protected_binary_bytes");

        shield.add_protected_path(&tmp_file);
        assert!(shield.verify_integrity());

        let status = shield.get_status();
        assert!(status.is_active);
        assert_eq!(status.protected_files_count, 1);

        // Simular ataque de alteración/inyección en archivo protegido
        fs::write(&tmp_file, "corrupted_or_injected_bytes").unwrap();
        assert!(
            !shield.verify_integrity(),
            "Debe detectar modificación de hash en archivo protegido"
        );
        assert_eq!(shield.get_status().tamper_attempts_detected, 1);

        let _ = fs::remove_file(tmp_file);
    }
}
