use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Informe de auditoría de una extensión de navegador instalada
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionAuditReport {
    pub name: String,
    pub id: String,
    pub browser: String,
    pub manifest_version: u32,
    pub is_suspicious: bool,
    pub risky_permissions: Vec<String>,
    pub risk_summary: Option<String>,
}

/// Permisos críticos de extensiones que permiten interceptación y robo de sesiones
const DANGEROUS_PERMISSIONS: &[&str] = &[
    "<all_urls>",
    "*://*/*",
    "cookies",
    "webRequestBlocking",
    "debugger",
    "nativeMessaging",
    "proxy",
    "declarativeNetRequestFeedback",
];

/// Examina el archivo manifest.json de una extensión de navegador
pub fn audit_extension_manifest(manifest_path: impl AsRef<Path>, browser_name: &str) -> Option<ExtensionAuditReport> {
    let content = fs::read_to_string(manifest_path.as_ref()).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;

    let name = json["name"].as_str().unwrap_or("Unknown Extension").to_string();
    let id = manifest_path
        .as_ref()
        .parent()
        .and_then(|p| p.file_name())
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "id_desconocido".to_string());

    let manifest_version = json["manifest_version"].as_u64().unwrap_or(2) as u32;

    let mut risky_permissions = Vec::new();
    if let Some(perms) = json["permissions"].as_array() {
        for p in perms {
            if let Some(perm_str) = p.as_str() {
                for &danger in DANGEROUS_PERMISSIONS {
                    if perm_str.eq_ignore_ascii_case(danger) {
                        risky_permissions.push(perm_str.to_string());
                    }
                }
            }
        }
    }

    let is_suspicious = risky_permissions.len() >= 2;
    let risk_summary = if is_suspicious {
        Some(format!(
            "Extensión '{}' solicita permisos de alto riesgo ({}) que permiten acceso total a sesiones web y credenciales bancarias.",
            name,
            risky_permissions.join(", ")
        ))
    } else {
        None
    };

    Some(ExtensionAuditReport {
        name,
        id,
        browser: browser_name.to_string(),
        manifest_version,
        is_suspicious,
        risky_permissions,
        risk_summary,
    })
}

/// Detecta si un proceso ajeno a los navegadores web está intentando acceder a los almacenes de cookies o contraseñas
pub fn is_unauthorized_browser_store_access(proc_name: &str, target_path: &str) -> bool {
    let lower_proc = proc_name.to_lowercase();
    let lower_path = target_path.to_lowercase();

    let is_browser_binary = lower_proc.contains("chrome")
        || lower_proc.contains("msedge")
        || lower_proc.contains("firefox")
        || lower_proc.contains("brave")
        || lower_proc.contains("opera")
        || lower_proc.contains("samulibre");

    let is_sensitive_store = lower_path.contains("login data")
        || lower_path.contains("cookies")
        || lower_path.contains("key4.db")
        || lower_path.contains("logins.json")
        || lower_path.contains("web data");

    if is_sensitive_store && !is_browser_binary {
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unauthorized_browser_access() {
        // Un script o binario no navegador accediendo a Login Data debe ser bloqueado
        assert!(is_unauthorized_browser_store_access(
            "stealer_payload.exe",
            "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
        ));

        // Chrome accediendo a sus propias cookies debe ser permitido
        assert!(!is_unauthorized_browser_store_access(
            "chrome.exe",
            "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"
        ));
    }
}
