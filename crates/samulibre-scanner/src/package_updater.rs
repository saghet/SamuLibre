use anyhow::{anyhow, Result};
use samulibre_types::{
    ManifestFileEntry, PackageComponentType, PackageVerificationStatus, UpdatePackageManifest,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};
use uuid::Uuid;

/// Clave pública canónica de verificación de versiones de SamuLibre
pub const OFFICIAL_SIGNER_FINGERPRINT: &str = "SAMULIBRE-ROOT-RELEASE-KEY-2026-V1";
pub const OFFICIAL_SIGNING_SALT: &[u8] = b"SamuLibre-Secure-Update-Signature-Salt-v1";

/// Gestor Avanzado de Paquetes de Actualización Criptográfica
pub struct PackageUpdater {
    data_dir: PathBuf,
    current_version_file: PathBuf,
}

impl PackageUpdater {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let dir = data_dir.as_ref().to_path_buf();
        let current_version_file = dir.join("signatures").join(".installed_version");
        Self {
            data_dir: dir,
            current_version_file,
        }
    }

    /// Obtiene la versión secuencial actualmente instalada en el sistema
    pub fn get_current_version_sequence(&self) -> u64 {
        if self.current_version_file.exists() {
            if let Ok(content) = fs::read_to_string(&self.current_version_file) {
                if let Ok(seq) = content.trim().parse::<u64>() {
                    return seq;
                }
            }
        }
        2026110101 // Versión base inicial por defecto
    }

    /// Guarda la nueva versión secuencial instalada de forma atómica
    pub fn record_installed_version(&self, seq: u64) -> Result<()> {
        if let Some(parent) = self.current_version_file.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let temp_file = self
            .current_version_file
            .with_extension(format!("tmp.{}", Uuid::new_v4()));
        fs::write(&temp_file, seq.to_string())?;
        fs::rename(&temp_file, &self.current_version_file)?;
        Ok(())
    }

    /// Limpia residuos de actualizaciones interrumpidas o abortadas previamente
    pub fn cleanup_interrupted_staging(&self) -> usize {
        let mut cleaned = 0;
        let sig_dir = self.data_dir.join("signatures");
        if sig_dir.exists() {
            if let Ok(entries) = fs::read_dir(&sig_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name.starts_with(".staging-") || name.ends_with(".tmp") {
                        if path.is_dir() {
                            let _ = fs::remove_dir_all(&path);
                        } else {
                            let _ = fs::remove_file(&path);
                        }
                        cleaned += 1;
                    }
                }
            }
        }
        cleaned
    }

    /// Calcula la firma criptográfica digital sobre el manifiesto
    pub fn compute_signature(
        package_id: &str,
        version_seq: u64,
        semantic_version: &str,
        files: &[ManifestFileEntry],
        signing_key: &[u8],
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(OFFICIAL_SIGNING_SALT);
        hasher.update(package_id.as_bytes());
        hasher.update(&version_seq.to_le_bytes());
        hasher.update(semantic_version.as_bytes());
        for f in files {
            hasher.update(f.relative_path.as_bytes());
            hasher.update(f.sha256.as_bytes());
            hasher.update(&f.size_bytes.to_le_bytes());
        }
        hasher.update(signing_key);
        hex::encode(hasher.finalize())
    }

    /// Valida un paquete completo contra su manifiesto firmado y reglas de seguridad
    pub fn verify_package(
        &self,
        manifest: &UpdatePackageManifest,
        files_data: &HashMap<String, Vec<u8>>,
        signing_key: &[u8],
    ) -> PackageVerificationStatus {
        // 1. Verificación de Huella Digital del Firmante
        if manifest.signer_fingerprint != OFFICIAL_SIGNER_FINGERPRINT {
            return PackageVerificationStatus::InvalidSignature;
        }

        // 2. Verificación de Firma Criptográfica
        let expected_sig = Self::compute_signature(
            &manifest.package_id,
            manifest.version_sequence,
            &manifest.semantic_version,
            &manifest.files,
            signing_key,
        );
        if expected_sig != manifest.digital_signature {
            return PackageVerificationStatus::InvalidSignature;
        }

        // 3. Protección Anti-Downgrade: la versión entrante no debe ser inferior a la instalada
        let current_seq = self.get_current_version_sequence();
        if manifest.version_sequence < current_seq {
            warn!(
                "[ANTI-DOWNGRADE] Bloqueada actualización maliciosa o desactualizada: actual={}, recibida={}",
                current_seq, manifest.version_sequence
            );
            return PackageVerificationStatus::DowngradeDetected {
                current_seq,
                incoming_seq: manifest.version_sequence,
            };
        }

        // 4. Verificación de Integridad de Archivos y Mitigación Path Traversal (Zip Slip)
        for expected_file in &manifest.files {
            // Mitigación Path Traversal
            if expected_file.relative_path.contains("..")
                || expected_file.relative_path.starts_with('/')
                || expected_file.relative_path.starts_with('\\')
            {
                return PackageVerificationStatus::PathTraversalDetected {
                    path: expected_file.relative_path.clone(),
                };
            }

            let data = match files_data.get(&expected_file.relative_path) {
                Some(d) => d,
                None => {
                    return PackageVerificationStatus::CorruptedManifest {
                        reason: format!("Archivo faltante en paquete: {}", expected_file.relative_path),
                    };
                }
            };

            // Validación de tamaño exacto
            if data.len() as u64 != expected_file.size_bytes {
                return PackageVerificationStatus::SizeMismatch {
                    file: expected_file.relative_path.clone(),
                    expected: expected_file.size_bytes,
                    actual: data.len() as u64,
                };
            }

            // Validación de SHA-256
            let mut hasher = Sha256::new();
            hasher.update(data);
            let calculated_hash = hex::encode(hasher.finalize());
            if calculated_hash != expected_file.sha256 {
                return PackageVerificationStatus::HashMismatch {
                    file: expected_file.relative_path.clone(),
                    expected: expected_file.sha256.clone(),
                    actual: calculated_hash,
                };
            }
        }

        PackageVerificationStatus::Valid
    }

    /// Instala un paquete atómicamente con respaldo previo y capacidad de rollback
    pub fn install_package(
        &self,
        manifest: &UpdatePackageManifest,
        files_data: &HashMap<String, Vec<u8>>,
        signing_key: &[u8],
    ) -> Result<()> {
        info!(
            "[UPDATE MANAGER] Iniciando instalación de paquete '{}' ({:?}, v{})",
            manifest.package_id, manifest.component_type, manifest.semantic_version
        );

        // 1. Validar integridad y firma
        let verification = self.verify_package(manifest, files_data, signing_key);
        if verification != PackageVerificationStatus::Valid {
            return Err(anyhow!(
                "Rechazada instalación de paquete: Verificación fallida ({:?})",
                verification
            ));
        }

        // 2. Limpiar residuos previos de staging
        self.cleanup_interrupted_staging();

        let sig_dir = self.data_dir.join("signatures");
        let staging_dir = sig_dir.join(format!(".staging-{}", Uuid::new_v4()));
        fs::create_dir_all(&staging_dir)?;

        // 3. Escribir archivos validados en el directorio de staging
        let mut backups_made: Vec<(PathBuf, PathBuf)> = Vec::new();

        for (rel_path, content) in files_data {
            let staged_file = staging_dir.join(rel_path);
            if let Some(parent) = staged_file.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut f = File::create(&staged_file)?;
            f.write_all(content)?;
            f.sync_all()?;
        }

        // 4. Crear copias de respaldo (.bak) para cada archivo que será reemplazado
        for rel_path in files_data.keys() {
            let target_path = sig_dir.join(rel_path);
            if target_path.exists() {
                let bak_path = target_path.with_extension(format!("bak.{}", Uuid::new_v4()));
                if let Err(e) = fs::copy(&target_path, &bak_path) {
                    warn!("Error creando respaldo de '{}': {}", target_path.display(), e);
                } else {
                    backups_made.push((target_path, bak_path));
                }
            }
        }

        // 5. Commit atómico: mover cada archivo staged a su ubicación definitiva
        let mut commit_failed = false;
        let mut commit_error = String::new();

        for (rel_path, _) in files_data {
            let staged_file = staging_dir.join(rel_path);
            let target_path = sig_dir.join(rel_path);

            if let Some(parent) = target_path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            // Usar AtomicInstaller / rename
            if let Err(_e) = fs::rename(&staged_file, &target_path) {
                // Si rename falla (ej. entre volúmenes), copiar y borrar
                if let Err(copy_err) = fs::copy(&staged_file, &target_path) {
                    commit_failed = true;
                    commit_error = format!("Fallo al mover '{}' a producción: {}", rel_path, copy_err);
                    break;
                }
            }
        }

        // 6. Si hubo fallo en el commit, ejecutar ROLLBACK inmediato de todos los archivos respaldados
        if commit_failed {
            error!("[ROLLBACK] Error en commit atómico: {}. Restaurando respaldos...", commit_error);
            for (target_path, bak_path) in backups_made {
                if bak_path.exists() {
                    let _ = fs::copy(&bak_path, &target_path);
                    let _ = fs::remove_file(&bak_path);
                }
            }
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(anyhow!("Rollback completado. Causa del fallo: {}", commit_error));
        }

        // 7. Si fue una actualización incremental de firmas, indexar o consolidar
        if manifest.is_incremental && manifest.component_type == PackageComponentType::MalwareSignatures {
            self.consolidate_incremental_signatures(&sig_dir)?;
        }

        // 8. Actualizar la versión instalada y eliminar backups
        self.record_installed_version(manifest.version_sequence)?;
        let _ = fs::remove_dir_all(&staging_dir);
        for (_, bak_path) in backups_made {
            let _ = fs::remove_file(&bak_path);
        }

        info!(
            "[UPDATE MANAGER] Paquete v{} instalado con éxito. Manifiesto y firmas consolidadas.",
            manifest.semantic_version
        );

        Ok(())
    }

    /// Consolida firmas incrementales en la base de datos principal y actualiza cabecera
    fn consolidate_incremental_signatures(&self, sig_dir: &Path) -> Result<()> {
        let delta_path = sig_dir.join("delta_signatures.txt");
        let db_path = sig_dir.join("malware_hashes.db");

        if delta_path.exists() && db_path.exists() {
            let delta_content = fs::read_to_string(&delta_path)?;
            let mut existing_db = fs::read_to_string(&db_path)?;

            let mut added = 0;
            for line in delta_content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('+') {
                    let entry = trimmed.trim_start_matches('+').trim();
                    if !existing_db.contains(entry) {
                        existing_db.push_str(&format!("\n{}", entry));
                        added += 1;
                    }
                }
            }

            fs::write(&db_path, existing_db)?;
            let _ = fs::remove_file(&delta_path);
            info!("[UPDATE MANAGER] Incremento consolidado: {} nuevas firmas añadidas a malware_hashes.db", added);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &[u8] = b"samulibre_official_test_secret_key_32b!";

    fn create_dummy_manifest(
        seq: u64,
        semver: &str,
        files: Vec<ManifestFileEntry>,
    ) -> UpdatePackageManifest {
        let pkg_id = format!("PKG-TEST-{}", seq);
        let sig = PackageUpdater::compute_signature(&pkg_id, seq, semver, &files, TEST_KEY);

        UpdatePackageManifest {
            package_id: pkg_id,
            version_sequence: seq,
            semantic_version: semver.to_string(),
            min_engine_version: "2.1.0".to_string(),
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            component_type: PackageComponentType::MalwareSignatures,
            is_incremental: false,
            files,
            changelog: vec![
                "Añadidas 50 nuevas firmas de ransomware Conti y LockBit".to_string(),
                "Actualizadas reglas YARA para detección de LOLBins".to_string(),
            ],
            digital_signature: sig,
            signer_fingerprint: OFFICIAL_SIGNER_FINGERPRINT.to_string(),
        }
    }

    #[test]
    fn test_package_signature_verification_success() {
        let temp_dir = std::env::temp_dir().join(format!("samu_pkg_test_{}", Uuid::new_v4()));
        let updater = PackageUpdater::new(&temp_dir);

        let content = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855:EmptyFile.Trojan";
        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = hex::encode(hasher.finalize());

        let file_entry = ManifestFileEntry {
            relative_path: "malware_hashes.db".to_string(),
            sha256: hash,
            size_bytes: content.len() as u64,
        };

        let manifest = create_dummy_manifest(2026110702, "2.1.14", vec![file_entry]);

        let mut files_map = HashMap::new();
        files_map.insert("malware_hashes.db".to_string(), content.to_vec());

        let res = updater.verify_package(&manifest, &files_map, TEST_KEY);
        assert_eq!(res, PackageVerificationStatus::Valid);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_anti_downgrade_protection_blocks_older_versions() {
        let temp_dir = std::env::temp_dir().join(format!("samu_downgrade_test_{}", Uuid::new_v4()));
        let updater = PackageUpdater::new(&temp_dir);

        // Fijar versión instalada actual: 2026110705
        updater.record_installed_version(2026110705).unwrap();
        assert_eq!(updater.get_current_version_sequence(), 2026110705);

        // Intentar aplicar paquete antiguo: 2026110101
        let manifest = create_dummy_manifest(2026110101, "2.1.10", Vec::new());
        let files_map = HashMap::new();

        let res = updater.verify_package(&manifest, &files_map, TEST_KEY);
        match res {
            PackageVerificationStatus::DowngradeDetected { current_seq, incoming_seq } => {
                assert_eq!(current_seq, 2026110705);
                assert_eq!(incoming_seq, 2026110101);
            }
            other => panic!("Se esperaba DowngradeDetected, se obtuvo: {:?}", other),
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_tampered_package_hash_mismatch_rejected() {
        let temp_dir = std::env::temp_dir().join(format!("samu_tamper_test_{}", Uuid::new_v4()));
        let updater = PackageUpdater::new(&temp_dir);

        let genuine_content = b"GENUINE_SIGNATURE_CONTENT";
        let mut hasher = Sha256::new();
        hasher.update(genuine_content);
        let hash = hex::encode(hasher.finalize());

        let file_entry = ManifestFileEntry {
            relative_path: "malware_hashes.db".to_string(),
            sha256: hash,
            size_bytes: genuine_content.len() as u64,
        };

        let manifest = create_dummy_manifest(2026110703, "2.1.14", vec![file_entry]);

        // Manipular el contenido inyectando bytes falsos
        let mut tampered_map = HashMap::new();
        tampered_map.insert("malware_hashes.db".to_string(), b"TAMPERED_MALICIOUS_BYTES".to_vec());

        let res = updater.verify_package(&manifest, &tampered_map, TEST_KEY);
        match res {
            PackageVerificationStatus::SizeMismatch { .. } | PackageVerificationStatus::HashMismatch { .. } => {
                // Correcto: alteración detectada
            }
            other => panic!("Se esperaba detección de manipulación, se obtuvo: {:?}", other),
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_path_traversal_zip_slip_rejected() {
        let temp_dir = std::env::temp_dir().join(format!("samu_traversal_test_{}", Uuid::new_v4()));
        let updater = PackageUpdater::new(&temp_dir);

        let file_entry = ManifestFileEntry {
            relative_path: "../../Windows/System32/evil.dll".to_string(),
            sha256: "dummy".to_string(),
            size_bytes: 10,
        };

        let manifest = create_dummy_manifest(2026110704, "2.1.14", vec![file_entry]);
        let mut files_map = HashMap::new();
        files_map.insert("../../Windows/System32/evil.dll".to_string(), b"0123456789".to_vec());

        let res = updater.verify_package(&manifest, &files_map, TEST_KEY);
        match res {
            PackageVerificationStatus::PathTraversalDetected { path } => {
                assert!(path.contains(".."));
            }
            other => panic!("Se esperaba PathTraversalDetected, se obtuvo: {:?}", other),
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_atomic_package_installation_and_version_recording() {
        let temp_dir = std::env::temp_dir().join(format!("samu_install_test_{}", Uuid::new_v4()));
        let updater = PackageUpdater::new(&temp_dir);

        let content = b"48d6215903dff56236030821680f45b2f81fc60d9d86b524dd7304c369387460:TestThreat.Payload";
        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = hex::encode(hasher.finalize());

        let file_entry = ManifestFileEntry {
            relative_path: "malware_hashes.db".to_string(),
            sha256: hash,
            size_bytes: content.len() as u64,
        };

        let manifest = create_dummy_manifest(2026110710, "2.1.15", vec![file_entry]);
        let mut files_map = HashMap::new();
        files_map.insert("malware_hashes.db".to_string(), content.to_vec());

        updater.install_package(&manifest, &files_map, TEST_KEY).unwrap();

        // Verificar que el archivo fue instalado en el directorio signatures
        let installed_file = temp_dir.join("signatures").join("malware_hashes.db");
        assert!(installed_file.exists());
        let read_back = fs::read(&installed_file).unwrap();
        assert_eq!(read_back, content);

        // Verificar que la versión fue registrada
        assert_eq!(updater.get_current_version_sequence(), 2026110710);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
