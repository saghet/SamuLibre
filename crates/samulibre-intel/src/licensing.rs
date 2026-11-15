use crate::db::IntelDatabase;
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Categoría de compatibilidad de licencia para distribución libre y comercial
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseCompatibility {
    PermissiveCommercialSafe,
    CopyleftAttribution,
    AttributionRequired,
    RestrictedReviewRequired,
    MetadataOnlyRecommended,
}

/// Entrada resumida de licencia en el SBOM de inteligencia
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseSummaryEntry {
    pub license: String,
    pub compatibility: LicenseCompatibility,
    pub indicator_count: usize,
    pub notes: String,
}

/// Inventario SBOM y de procedencia de firmas/reglas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomInventory {
    pub generated_at: String,
    pub total_indicators: usize,
    pub by_license: Vec<LicenseSummaryEntry>,
    pub by_source: HashMap<String, usize>,
}

/// Manifiesto de integridad firmado por SamuLibre para actualizaciones verificables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelManifest {
    pub schema_version: u32,
    pub manifest_version: String,
    pub generated_at: String,
    pub publisher: String,
    pub total_active_indicators: usize,
    pub db_sha256: String,
    pub compiled_yara_sha256: Option<String>,
    pub manifest_hmac_sha256: String,
}

pub struct LicensingAndManifestManager;

impl LicensingAndManifestManager {
    /// Indica si una licencia es apta para distribución comercial en producción (bloquea CC BY-NC / no comercial)
    pub fn is_commercial_production_allowed(license: &str) -> bool {
        let l = license.to_ascii_lowercase();
        !(l.contains("by-nc") || l.contains("noncommercial") || l.contains("non-commercial"))
    }

    /// Clasifica una cadena de licencia según compatibilidad comercial y obligaciones
    pub fn classify_license(license: &str) -> (LicenseCompatibility, &'static str) {
        let l = license.to_ascii_lowercase();
        if !Self::is_commercial_production_allowed(license) {
            (
                LicenseCompatibility::RestrictedReviewRequired,
                "Licencia No Comercial (CC BY-NC); bloqueada automáticamente para producción comercial.",
            )
        } else if l.contains("cc0") || l.contains("mit") || l.contains("bsd") || l.contains("apache") {
            (
                LicenseCompatibility::PermissiveCommercialSafe,
                "Permisiva; apta para distribución libre y comercial conservando aviso de copyright.",
            )
        } else if l.contains("gpl-2.0") || l.contains("gpl-3.0") || l.contains("gpl") {
            (
                LicenseCompatibility::CopyleftAttribution,
                "Copyleft GPL; compatible con SamuLibre (GPL-3.0-or-later); requiere código fuente y atribución.",
            )
        } else if l.contains("drl") || l.contains("detection rule license") || l.contains("cc by 4") || l.contains("cc-by") && !l.contains("sa") {
            (
                LicenseCompatibility::AttributionRequired,
                "Requiere atribución explícita del autor y enlace a la fuente original.",
            )
        } else if l.contains("cc by-sa") || l.contains("elastic") || l.contains("restricted") || l.contains("malpedia") {
            (
                LicenseCompatibility::RestrictedReviewRequired,
                "Restricción comercial/ShareAlike; recomendar modo metadata-only o descarga directa por el usuario.",
            )
        } else {
            (
                LicenseCompatibility::MetadataOnlyRecommended,
                "Sin licencia explícita o mixta; revisar regla individual antes de redistribuir.",
            )
        }
    }

    /// Genera el inventario SBOM real consultando `IntelDatabase`
    pub fn generate_sbom(db: &IntelDatabase) -> Result<SbomInventory> {
        let yara_rules = db.load_production_yara_rules()?;
        let mut lic_counts: HashMap<String, usize> = HashMap::new();
        let mut src_counts: HashMap<String, usize> = HashMap::new();

        for r in &yara_rules {
            *lic_counts.entry(r.license.clone()).or_insert(0) += 1;
            *src_counts.entry(r.source_name.clone()).or_insert(0) += 1;
        }

        let mut by_license = Vec::new();
        for (lic, count) in lic_counts {
            let (compat, notes) = Self::classify_license(&lic);
            by_license.push(LicenseSummaryEntry {
                license: lic,
                compatibility: compat,
                indicator_count: count,
                notes: notes.to_string(),
            });
        }
        by_license.sort_by(|a, b| b.indicator_count.cmp(&a.indicator_count));

        Ok(SbomInventory {
            generated_at: Utc::now().to_rfc3339(),
            total_indicators: yara_rules.len(),
            by_license,
            by_source: src_counts,
        })
    }

    /// Construye y firma un manifiesto de integridad para los artefactos de inteligencia
    pub fn create_signed_manifest(
        db_path: &Path,
        compiled_yara_path: Option<&Path>,
        total_active_indicators: usize,
        signing_secret: &[u8],
    ) -> Result<IntelManifest> {
        let db_bytes = fs::read(db_path)?;
        let db_sha256 = hex::encode(Sha256::digest(&db_bytes));

        let compiled_yara_sha256 = match compiled_yara_path {
            Some(p) if p.exists() => Some(hex::encode(Sha256::digest(&fs::read(p)?))),
            _ => None,
        };

        let now = Utc::now();
        let manifest_version = now.format("%Y.%m.%d.%H%M%S").to_string();
        let payload = format!(
            "1|{}|{}|{}|{}",
            manifest_version,
            total_active_indicators,
            db_sha256,
            compiled_yara_sha256.as_deref().unwrap_or("none")
        );

        let mut mac = Sha256::new();
        mac.update(signing_secret);
        mac.update(b":");
        mac.update(payload.as_bytes());
        let manifest_hmac_sha256 = hex::encode(mac.finalize());

        Ok(IntelManifest {
            schema_version: 1,
            manifest_version,
            generated_at: now.to_rfc3339(),
            publisher: "SamuLibre Security Community".to_string(),
            total_active_indicators,
            db_sha256,
            compiled_yara_sha256,
            manifest_hmac_sha256,
        })
    }

    /// Verifica la firma HMAC-SHA256 de un manifiesto contra su secreto
    pub fn verify_manifest(manifest: &IntelManifest, signing_secret: &[u8]) -> bool {
        let payload = format!(
            "1|{}|{}|{}|{}",
            manifest.manifest_version,
            manifest.total_active_indicators,
            manifest.db_sha256,
            manifest.compiled_yara_sha256.as_deref().unwrap_or("none")
        );
        let mut mac = Sha256::new();
        mac.update(signing_secret);
        mac.update(b":");
        mac.update(payload.as_bytes());
        let expected = hex::encode(mac.finalize());
        expected == manifest.manifest_hmac_sha256
    }
}
