use anyhow::{anyhow, Result};
use chrono::Utc;
use samulibre_types::SafeExclusionProposal;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use uuid::Uuid;

/// Asesor y Gestor de Exclusiones Seguras con Blindaje Anti-Bypass
pub struct SafeExclusionManager;

impl SafeExclusionManager {
    /// Evalúa rigurosamente una propuesta de exclusión contra las políticas de seguridad
    pub fn evaluate_exclusion_request(
        target_path: &str,
        rule_type: &str,
        justification: &str,
        conflict_id: &str,
    ) -> Result<SafeExclusionProposal> {
        let normalized = target_path.trim().replace('/', "\\");
        let lower = normalized.to_lowercase();

        // 1. Prohibición de unidades completas
        if lower.len() <= 3 && lower.ends_with(":\\") || lower.ends_with(':') {
            return Err(anyhow!(
                "VIOLACIÓN DE POLÍTICA CRÍTICA: Prohibido excluir unidades de disco completas ({}). Riesgo catastrófico de seguridad.",
                normalized
            ));
        }

        // 2. Prohibición de C:\Windows y directorios del sistema operativo
        if lower.starts_with("c:\\windows") || lower.contains("\\system32") || lower.contains("\\syswow64") {
            return Err(anyhow!(
                "VIOLACIÓN DE POLÍTICA CRÍTICA: Prohibido excluir directorios del sistema Windows ({}). Los archivos del sistema deben ser analizados sin excepción.",
                normalized
            ));
        }

        // 3. Prohibición de exclusiones genéricas de carpetas de usuario
        if lower == "c:\\users" || lower == "c:\\users\\" || lower.ends_with("\\appdata") || lower.ends_with("\\temp") {
            return Err(anyhow!(
                "VIOLACIÓN DE POLÍTICA CRÍTICA: Prohibido excluir de forma amplia directorios de usuario o carpetas temporales globales ({}).",
                normalized
            ));
        }

        // 4. Prohibición de extensiones ejecutables completas
        if normalized.starts_with("*.") || rule_type.to_lowercase().contains("extension") {
            return Err(anyhow!(
                "VIOLACIÓN DE POLÍTICA CRÍTICA: Prohibido excluir extensiones completas (*.exe, *.dll, etc.). Toda exclusión debe ser por ruta o hash específico.",
            ));
        }

        // 5. Verificación de hash SHA-256 anclado si es un archivo existente
        let path_obj = Path::new(&normalized);
        let mut sha256_pinned = None;

        if path_obj.is_file() {
            if let Ok(bytes) = fs::read(path_obj) {
                sha256_pinned = Some(hex::encode(Sha256::digest(&bytes)));
            }
        }

        let proposal = SafeExclusionProposal {
            id: Uuid::new_v4().to_string(),
            rule_type: rule_type.to_string(),
            target_path: normalized,
            sha256_pinned,
            justification: justification.to_string(),
            conflict_id: conflict_id.to_string(),
            risk_assessment: "Bajo / Controlado mediante hash anclado y ruta absoluta específica.".to_string(),
            is_approved_by_admin: false, // Requiere aprobación explícita humana
            created_at: Utc::now().to_rfc3339(),
        };

        Ok(proposal)
    }

    /// Genera recomendaciones arquitectónicas en lugar de exclusiones cuando sea posible
    pub fn suggest_architectural_mitigation(conflict_description: &str) -> String {
        if conflict_description.to_lowercase().contains("sharing violation")
            || conflict_description.to_lowercase().contains("en uso")
        {
            return "RECOMENDACIÓN ARQUITECTÓNICA (SIN EXCLUSIÓN): Utilizar lectura compartida (FILE_SHARE_READ | FILE_SHARE_WRITE) con reintentos exponenciales en SmartScanCoordinator para permitir que Defender y SamuLibre lean el archivo sin bloquearse mutuamente.".to_string();
        }

        if conflict_description.to_lowercase().contains("eicar") {
            return "RECOMENDACIÓN ARQUITECTÓNICA (SIN EXCLUSIÓN): Registrar la detección como artefacto de prueba en el False Positive Investigation Engine. No excluir carpetas temporales.".to_string();
        }

        "RECOMENDACIÓN ARQUITECTÓNICA: Mantener ambos motores activos y limitar la tasa de escaneo en el SamuLibre Resource Governor para reducir contienda de I/O.".to_string()
    }
}
