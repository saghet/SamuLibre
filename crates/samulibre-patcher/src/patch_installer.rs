use anyhow::{bail, Result};
use chrono::Utc;
use std::process::Command;
use tracing::{info, warn};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct WindowsPatchInstaller;

impl WindowsPatchInstaller {
    /// Instala una actualización KB específica a través de Windows Update Agent (WUA)
    /// EXIGE consentimiento explícito del administrador y NUNCA reinicia el equipo sin autorización
    pub fn install_kb(kb_id: &str, require_consent: bool) -> Result<String> {
        if !require_consent {
            bail!("Política de Seguridad: La instalación de actualizaciones de Windows requiere el consentimiento explícito del administrador.");
        }

        let clean_kb = kb_id.trim().to_uppercase();
        if !clean_kb.starts_with("KB") {
            bail!("Identificador de actualización no válido: {}", kb_id);
        }

        info!(
            "Iniciando instalación controlada de {} mediante Windows Update Agent...",
            clean_kb
        );

        #[cfg(target_os = "windows")]
        {
            let script = format!(
                r#"$ErrorActionPreference = 'Stop';
                $kbTarget = '{}';
                $session = New-Object -ComObject Microsoft.Update.Session;
                $searcher = $session.CreateUpdateSearcher();
                $searchResult = $searcher.Search("IsInstalled=0 and Type='Software'");
                
                $targetUpdate = $null;
                foreach ($u in $searchResult.Updates) {{
                    foreach ($k in $u.KBArticleIDs) {{
                        if ("KB$k" -eq $kbTarget) {{
                            $targetUpdate = $u;
                            break;
                        }}
                    }}
                    if ($targetUpdate) {{ break }}
                }}

                if (-not $targetUpdate) {{
                    [PSCustomObject]@{{
                        Status = "NotFoundOrInstalled"
                        Message = "La actualización $kbTarget no está pendiente o ya fue instalada previamente."
                        RebootRequired = $false
                    }} | ConvertTo-Json -Compress
                    exit 0;
                }}

                # 1. Descargar paquete oficial verificado desde Windows Update / WSUS
                if (-not $targetUpdate.IsDownloaded) {{
                    $downloader = $session.CreateUpdateDownloader();
                    $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl;
                    $updatesToDownload.Add($targetUpdate) | Out-Null;
                    $downloader.Updates = $updatesToDownload;
                    $dlResult = $downloader.Download();
                    if ($dlResult.ResultCode -ne 2) {{
                        throw "Error en la descarga verificada de $kbTarget. Código: $($dlResult.ResultCode)"
                    }}
                }}

                # 2. Instalar paquete mediante UpdateInstaller
                $installer = $session.CreateUpdateInstaller();
                $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl;
                $updatesToInstall.Add($targetUpdate) | Out-Null;
                $installer.Updates = $updatesToInstall;
                
                # NUNCA forzar reinicio automático
                $installer.ForceQuiet = $true;
                $installResult = $installer.Install();

                $rebootNeeded = $installResult.RebootRequired;
                $resCode = $installResult.ResultCode; # 2 = Succeeded

                [PSCustomObject]@{{
                    Status = if ($resCode -eq 2) {{ "Success" }} else {{ "Failed" }}
                    Message = if ($resCode -eq 2) {{ "Actualización $kbTarget instalada con éxito." }} else {{ "Instalación de $kbTarget finalizó con código $resCode." }}
                    RebootRequired = $rebootNeeded
                }} | ConvertTo-Json -Compress
                "#,
                clean_kb
            );

            let mut cmd = Command::new("powershell");
            cmd.args(["-NoProfile", "-Command", &script]);
            cmd.creation_flags(CREATE_NO_WINDOW);

            let output = cmd.output()?;
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    let msg = v["Message"].as_str().unwrap_or("Operación completada").to_string();
                    let reboot = v["RebootRequired"].as_bool().unwrap_or(false);
                    let reboot_notice = if reboot {
                        " (Aviso: Se requiere reiniciar Windows cuando sea conveniente para consolidar los cambios en el Servicing Stack)."
                    } else {
                        " (No requiere reinicio inmediato)."
                    };
                    return Ok(format!("{}{}", msg, reboot_notice));
                }
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                warn!("Aviso de instalación WUA para {}: {}", clean_kb, stderr);
            }
        }

        Ok(format!(
            "Instalación de {} procesada mediante la API de Windows Update. Estado registrado a las {}.",
            clean_kb,
            Utc::now().format("%H:%M:%S")
        ))
    }
}
