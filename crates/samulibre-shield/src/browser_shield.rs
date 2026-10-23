use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Informe de auditoría de una extensión de navegador instalada
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionAuditReport {
    pub name: String,
    pub raw_name: String,
    pub id: String,
    pub browser: String,
    pub profile: String,
    pub manifest_version: u32,
    pub version: String,
    pub is_suspicious: bool,
    pub risk_level: String, // "Inocua", "Baja", "Media", "Alta", "Crítica"
    pub risky_permissions: Vec<String>,
    pub host_permissions: Vec<String>,
    pub risk_summary: Option<String>,
    pub install_dir: String,
    pub can_delete: bool,
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
    "browsingData",
];

/// Resuelve el nombre humano traducido de la extensión a partir de su catálogo _locales
pub fn resolve_locales_name(version_dir: &Path, raw_name: &str) -> String {
    if !raw_name.starts_with("__MSG_") || !raw_name.ends_with("__") {
        return raw_name.to_string();
    }

    let key = &raw_name[6..raw_name.len() - 2];
    let locales_dir = version_dir.join("_locales");
    if !locales_dir.exists() {
        return raw_name.to_string();
    }

    // Prioridad de idiomas para resolver el nombre
    let preferred_langs = ["es", "es_419", "es_ES", "en", "en_US", "en_GB"];
    for lang in preferred_langs {
        let msg_file = locales_dir.join(lang).join("messages.json");
        if msg_file.exists() {
            if let Ok(content) = fs::read_to_string(&msg_file) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(msg) = json.get(key).and_then(|v| v.get("message")).and_then(|m| m.as_str()) {
                        return msg.to_string();
                    }
                }
            }
        }
    }

    // Buscar en cualquier otro subdirectorio de idioma disponible
    if let Ok(entries) = fs::read_dir(&locales_dir) {
        for entry in entries.flatten() {
            let msg_file = entry.path().join("messages.json");
            if msg_file.exists() {
                if let Ok(content) = fs::read_to_string(&msg_file) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(msg) = json.get(key).and_then(|v| v.get("message")).and_then(|m| m.as_str()) {
                            return msg.to_string();
                        }
                    }
                }
            }
        }
    }

    raw_name.to_string()
}

/// Examina el archivo manifest.json de una extensión de navegador
pub fn audit_extension_manifest(
    manifest_path: impl AsRef<Path>,
    browser_name: &str,
    profile_name: &str,
) -> Option<ExtensionAuditReport> {
    let p = manifest_path.as_ref();
    let content = fs::read_to_string(p).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;

    let raw_name = json["name"].as_str().unwrap_or("Unknown Extension").to_string();
    let version_dir = p.parent()?;
    let ext_dir = version_dir.parent()?;
    let id = ext_dir.file_name()?.to_string_lossy().to_string();

    let name = resolve_locales_name(version_dir, &raw_name);
    let version = json["version"].as_str().unwrap_or("1.0").to_string();
    let manifest_version = json["manifest_version"].as_u64().unwrap_or(2) as u32;

    let mut risky_permissions = Vec::new();
    if let Some(perms) = json["permissions"].as_array() {
        for p_val in perms {
            if let Some(perm_str) = p_val.as_str() {
                for &danger in DANGEROUS_PERMISSIONS {
                    if perm_str.eq_ignore_ascii_case(danger) {
                        risky_permissions.push(perm_str.to_string());
                    }
                }
            }
        }
    }

    let mut host_permissions = Vec::new();
    if let Some(hosts) = json.get("host_permissions").and_then(|h| h.as_array()) {
        for h in hosts {
            if let Some(h_str) = h.as_str() {
                host_permissions.push(h_str.to_string());
            }
        }
    }

    // Análisis heurístico del nivel de riesgo
    let has_all_urls = risky_permissions.iter().any(|p| p == "<all_urls>" || p == "*://*/*")
        || host_permissions.iter().any(|h| h == "<all_urls>" || h == "*://*/*");
    let has_cookies = risky_permissions.iter().any(|p| p.eq_ignore_ascii_case("cookies"));
    let has_native_messaging = risky_permissions.iter().any(|p| p.eq_ignore_ascii_case("nativeMessaging"));

    let (is_suspicious, risk_level, risk_summary) = if has_cookies && has_native_messaging {
        (
            true,
            "Crítica".to_string(),
            Some(format!(
                "La extensión '{}' solicita lectura de todas las cookies y comunicación nativa (.exe), permitiendo acceso absoluto a sesiones bancarias y del sistema.",
                name
            )),
        )
    } else if has_all_urls && (has_cookies || risky_permissions.len() >= 2) {
        (
            true,
            "Alta".to_string(),
            Some(format!(
                "Extensión '{}' con permisos de interceptación total en todas las webs ({}) y manipulación de datos sensibles.",
                name,
                risky_permissions.join(", ")
            )),
        )
    } else if !risky_permissions.is_empty() || !host_permissions.is_empty() {
        (
            false,
            "Media".to_string(),
            Some(format!("Extensión con permisos estándar ({})", risky_permissions.join(", "))),
        )
    } else {
        (false, "Inocua".to_string(), None)
    };

    Some(ExtensionAuditReport {
        name,
        raw_name,
        id,
        browser: browser_name.to_string(),
        profile: profile_name.to_string(),
        manifest_version,
        version,
        is_suspicious,
        risk_level,
        risky_permissions,
        host_permissions,
        risk_summary,
        install_dir: ext_dir.to_string_lossy().to_string(),
        can_delete: true,
    })
}

/// Elimina de forma segura y permanente una extensión instalada en Chrome o Edge
pub fn remove_browser_extension(browser: &str, profile: &str, ext_id: &str) -> Result<String> {
    if ext_id.trim().is_empty() {
        anyhow::bail!("Identificador de extensión inválido");
    }

    let mut ext_dir_opt: Option<PathBuf> = None;
    let mut profile_dir_opt: Option<PathBuf> = None;

    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let base = PathBuf::from(local_app_data);
            let browser_folder = if browser.contains("Edge") {
                base.join("Microsoft").join("Edge").join("User Data")
            } else {
                base.join("Google").join("Chrome").join("User Data")
            };
            let p_dir = browser_folder.join(profile);
            let ext_dir = p_dir.join("Extensions").join(ext_id);
            if ext_dir.exists() {
                ext_dir_opt = Some(ext_dir);
                profile_dir_opt = Some(p_dir);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let base = PathBuf::from(home);
            let browser_folder = if browser.contains("Edge") {
                base.join(".config").join("microsoft-edge")
            } else {
                base.join(".config").join("google-chrome")
            };
            let p_dir = browser_folder.join(profile);
            let ext_dir = p_dir.join("Extensions").join(ext_id);
            if ext_dir.exists() {
                ext_dir_opt = Some(ext_dir);
                profile_dir_opt = Some(p_dir);
            }
        }
    }

    let ext_dir = ext_dir_opt.ok_or_else(|| anyhow::anyhow!("No se encontró la carpeta de la extensión '{}'", ext_id))?;

    // 1. Borrado físico del directorio de la extensión
    fs::remove_dir_all(&ext_dir)?;

    // 2. Limpieza en el archivo Preferences si existe
    if let Some(p_dir) = profile_dir_opt {
        let prefs_file = p_dir.join("Preferences");
        if prefs_file.exists() {
            if let Ok(content) = fs::read_to_string(&prefs_file) {
                if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(extensions) = json.get_mut("extensions").and_then(|e| e.get_mut("settings")) {
                        if let Some(map) = extensions.as_object_mut() {
                            map.remove(ext_id);
                            if let Ok(updated) = serde_json::to_string(&json) {
                                let _ = fs::write(&prefs_file, updated);
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Limpieza en Registro de Windows si aplica
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        use std::os::windows::process::CommandExt;

        let reg_paths = [
            format!(r"HKCU\Software\Google\Chrome\Extensions\{}", ext_id),
            format!(r"HKLM\Software\Google\Chrome\Extensions\{}", ext_id),
            format!(r"HKCU\Software\Microsoft\Edge\Extensions\{}", ext_id),
            format!(r"HKLM\Software\Microsoft\Edge\Extensions\{}", ext_id),
        ];

        for rk in reg_paths {
            let mut cmd = Command::new("reg");
            cmd.args(["delete", &rk, "/f"]);
            cmd.creation_flags(CREATE_NO_WINDOW);
            let _ = cmd.output();
        }
    }

    Ok(format!("Extensión '{}' eliminada con éxito de {} ({})", ext_id, browser, profile))
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
        assert!(is_unauthorized_browser_store_access(
            "stealer_payload.exe",
            "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
        ));

        assert!(!is_unauthorized_browser_store_access(
            "chrome.exe",
            "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"
        ));
    }

    #[test]
    fn test_resolve_locales_fallback() {
        let dummy_path = Path::new("dummy_dir");
        let raw = "Normal Extension Name";
        let resolved = resolve_locales_name(dummy_path, raw);
        assert_eq!(resolved, "Normal Extension Name");
    }
}
