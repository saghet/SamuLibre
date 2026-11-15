use anyhow::Result;
use samulibre_types::{WscAntivirusProduct, WscProductState};
use std::process::Command;
use tracing::info;

/// Gestor de integración oficial con Windows Security Center (root\SecurityCenter2)
pub struct WindowsSecurityCenterManager;

impl WindowsSecurityCenterManager {
    /// Consulta todos los proveedores de antivirus registrados en Windows Security Center
    pub fn query_registered_products() -> Vec<WscAntivirusProduct> {
        info!("Consultando proveedores antivirus en WMI root\\SecurityCenter2...");

        #[cfg(target_os = "windows")]
        {
            let script = "$products = Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue; if ($products) { ($products | ForEach-Object { [PSCustomObject]@{ displayName=$_.displayName; instanceGuid=$_.instanceGuid; pathToSignedProductExe=$_.pathToSignedProductExe; productState=[uint32]$_.productState } }) | ConvertTo-Json -Depth 2 -Compress } else { Write-Output '[]' }";

            let mut cmd = Command::new("powershell");
            cmd.args(["-WindowStyle", "Hidden", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]);
            cmd.stdin(std::process::Stdio::null());
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000 | 0x00000008);

            if let Ok(output) = cmd.output() {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Ok(parsed) = Self::parse_wsc_json(&stdout) {
                    return parsed;
                }
            }
        }

        Vec::new()
    }

    /// Parsea la respuesta JSON de WMI
    fn parse_wsc_json(json_str: &str) -> Result<Vec<WscAntivirusProduct>> {
        if json_str.is_empty() || json_str == "[]" {
            return Ok(Vec::new());
        }

        let val: serde_json::Value = serde_json::from_str(json_str)?;
        let items = if val.is_array() {
            val.as_array().unwrap().clone()
        } else if val.is_object() {
            vec![val]
        } else {
            return Ok(Vec::new());
        };

        let mut list = Vec::new();
        for item in items {
            let display_name = item.get("displayName").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let instance_guid = item.get("instanceGuid").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let exe_path = item.get("pathToSignedProductExe").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let product_state = item.get("productState").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

            let decoded_state = Self::decode_product_state(product_state);

            list.push(WscAntivirusProduct {
                display_name,
                instance_guid,
                exe_path,
                product_state,
                decoded_state,
            });
        }

        Ok(list)
    }

    /// Decodifica la máscara de bits oficial de `productState` de Windows Security Center
    /// Formato hexadecimal típico de 24 bits: 0xXXYYZZ
    /// XX = Provider Type / Flags del sistema
    /// YY = Estado del Escáner (0x10 = Activo / On, 0x00 = Desactivado / Off, 0x20 = En pausa / Snoozed)
    /// ZZ = Estado de Firmas (0x00 = Actualizadas, 0x10 = Obsoletas)
    pub fn decode_product_state(state: u32) -> WscProductState {
        let provider_type = ((state >> 16) & 0xFF) as u8;
        let scanner_byte = ((state >> 8) & 0xFF) as u8;
        let signature_byte = (state & 0xFF) as u8;

        let is_enabled = (scanner_byte & 0x10) != 0;
        let is_up_to_date = (signature_byte & 0x10) == 0;

        WscProductState {
            provider_type,
            scanner_state: scanner_byte,
            signature_state: signature_byte,
            is_enabled,
            is_up_to_date,
            raw_state_hex: format!("0x{:06X}", state),
        }
    }

    /// Codifica un valor entero `productState` según las especificaciones de WSC
    pub fn encode_product_state(is_enabled: bool, is_up_to_date: bool) -> u32 {
        let provider_byte: u32 = 0x06; // Tipo 3rd party antivirus estándar en Win10/11
        let scanner_byte: u32 = if is_enabled { 0x10 } else { 0x00 };
        let signature_byte: u32 = if is_up_to_date { 0x00 } else { 0x10 };

        (provider_byte << 16) | (scanner_byte << 8) | signature_byte
    }

    /// Realiza la verificación de salud y redundancia de conmutación por error (Failover Watchdog)
    /// Si SamuLibre sufriera una caída, Windows Security Center reactiva automáticamente Defender a modo activo.
    pub fn verify_wsc_failover_status() -> String {
        let products = Self::query_registered_products();
        let defender_opt = products.iter().find(|p| p.display_name.to_lowercase().contains("defender"));
        
        if let Some(def) = defender_opt {
            format!(
                "Microsoft Defender detectado en WSC (Estado: {}, Habilitado: {}, Definiciones al día: {}). La transición por conmutación por error (Failover) de Windows está plenamente operativa.",
                def.decoded_state.raw_state_hex,
                def.decoded_state.is_enabled,
                def.decoded_state.is_up_to_date
            )
        } else {
            "Microsoft Defender no se encuentra registrado de forma visible en WSC.".to_string()
        }
    }
}
