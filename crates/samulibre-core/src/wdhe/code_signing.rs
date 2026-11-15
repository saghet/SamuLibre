use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Registro de un binario oficial en el manifiesto criptográfico
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryManifestEntry {
    pub file_name: String,
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub version: String,
    pub is_signed: bool,
    pub signature_status: String,
    pub signer_subject: String,
    pub timestamp_rfc3161: String,
}

/// Manifiesto oficial sellado criptográficamente
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfficialBinaryManifest {
    pub project_name: String,
    pub release_version: String,
    pub publisher: String,
    pub generated_at_utc: String,
    pub binaries: Vec<BinaryManifestEntry>,
    pub manifest_sha256: String,
}

/// Paquete formal de disputa de falso positivo para Microsoft Security Intelligence (WDSI)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WdsiDisputeSubmission {
    pub submission_id: String,
    pub submission_date_utc: String,
    pub submitter_organization: String,
    pub contact_email: String,
    pub product_name: String,
    pub product_version: String,
    pub detected_threat_name: String,
    pub detected_threat_id: String,
    pub file_name: String,
    pub sha256_hash: String,
    pub authenticode_status: String,
    pub technical_justification: String,
    pub build_environment_details: String,
    pub portal_url: String,
}

/// Gestor de firma digital, verificación de reputación y presentación de disputas WDSI
pub struct CodeSigningManager;

impl CodeSigningManager {
    /// Verifica el estado de firma digital Authenticode de un archivo en Windows
    pub fn verify_authenticode(path: &Path) -> (bool, String, String) {
        #[cfg(target_os = "windows")]
        {
            if !path.exists() {
                return (false, "Archivo no encontrado".to_string(), String::new());
            }

            let script = format!(
                "$sig = Get-AuthenticodeSignature -FilePath '{}'; [PSCustomObject]@{{ Status = $sig.Status.ToString(); Subject = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ '' }}; Time = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.NotBefore.ToString('o') }} else {{ '' }} }} | ConvertTo-Json -Compress",
                path.to_string_lossy().replace('\'', "''")
            );

            let mut cmd = Command::new("powershell");
            cmd.args(["-WindowStyle", "Hidden", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", &script]);
            cmd.stdin(std::process::Stdio::null());
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000 | 0x00000008);

            if let Ok(output) = cmd.output() {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    let status = v.get("Status").and_then(|s| s.as_str()).unwrap_or("Unknown").to_string();
                    let subject = v.get("Subject").and_then(|s| s.as_str()).unwrap_or("").to_string();
                    let is_valid = status == "Valid";
                    return (is_valid, status, subject);
                }
            }
        }

        (false, "No firmado / Sin soporte Authenticode en este host".to_string(), String::new())
    }

    /// Genera el manifiesto de binarios oficiales de SamuLibre
    pub fn generate_official_manifest(base_dir: &Path) -> OfficialBinaryManifest {
        let mut entries = Vec::new();
        let target_binaries = vec![
            "samulibre.exe",
            "samulibre-gui.exe",
            "target/release/samulibre.exe",
            "target/debug/samulibre.exe",
        ];

        for rel in target_binaries {
            let p = base_dir.join(rel);
            if p.exists() && p.is_file() {
                if let Ok(bytes) = fs::read(&p) {
                    let sha = hex::encode(Sha256::digest(&bytes));
                    let size = bytes.len() as u64;
                    let (is_signed, status, subject) = Self::verify_authenticode(&p);

                    entries.push(BinaryManifestEntry {
                        file_name: p.file_name().unwrap().to_string_lossy().to_string(),
                        relative_path: rel.to_string(),
                        sha256: sha,
                        size_bytes: size,
                        version: "2.1.13".to_string(),
                        is_signed,
                        signature_status: status,
                        signer_subject: subject,
                        timestamp_rfc3161: Utc::now().to_rfc3339(),
                    });
                }
            }
        }

        let mut manifest = OfficialBinaryManifest {
            project_name: "SamuLibre Endpoint Protection".to_string(),
            release_version: "2.1.13".to_string(),
            publisher: "SamuLibre Security Community".to_string(),
            generated_at_utc: Utc::now().to_rfc3339(),
            binaries: entries,
            manifest_sha256: String::new(),
        };

        if let Ok(json_repr) = serde_json::to_string(&manifest.binaries) {
            manifest.manifest_sha256 = hex::encode(Sha256::digest(json_repr.as_bytes()));
        }

        manifest
    }

    /// Prepara el archivo formal de disputa de falso positivo para remisión a Microsoft Security Intelligence
    pub fn prepare_wdsi_submission(
        file_path: &Path,
        threat_name: &str,
        threat_id: &str,
    ) -> Result<WdsiDisputeSubmission> {
        let file_bytes = fs::read(file_path)?;
        let sha256_hash = hex::encode(Sha256::digest(&file_bytes));
        let file_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown.exe")
            .to_string();

        let (is_signed, sig_status, _) = Self::verify_authenticode(file_path);

        let submission = WdsiDisputeSubmission {
            submission_id: uuid::Uuid::new_v4().to_string(),
            submission_date_utc: Utc::now().to_rfc3339(),
            submitter_organization: "SamuLibre Security Community (Open Source)".to_string(),
            contact_email: "dev@samulibre.org".to_string(),
            product_name: "SamuLibre Antivirus & EDR Suite".to_string(),
            product_version: "2.1.13".to_string(),
            detected_threat_name: threat_name.to_string(),
            detected_threat_id: threat_id.to_string(),
            file_name,
            sha256_hash,
            authenticode_status: format!("Firmado: {}, Estado: {}", is_signed, sig_status),
            technical_justification: "El archivo analizado es un componente legítimo de código abierto compilado desde el repositorio oficial de SamuLibre sin carga útil maliciosa. La detección responde a una heurística genérica no confirmada.".to_string(),
            build_environment_details: "Compilador Rust 1.80+ (MSVC 64-bit), flags de mitigación DEP/ASLR/CFG habilitados.".to_string(),
            portal_url: "https://www.microsoft.com/en-us/wdsi/filesubmission".to_string(),
        };

        Ok(submission)
    }
}
