use crate::types::{FirewallRule, NetProtocol, RuleAction, TrafficDirection, WfpEngineStatus};
use anyhow::{anyhow, Result};
use std::net::IpAddr;
use tracing::{info, warn};

#[cfg(target_os = "windows")]
use windows::{
    core::{GUID, PWSTR},
    Win32::Foundation::{ERROR_SUCCESS, HANDLE},
    Win32::NetworkManagement::WindowsFilteringPlatform::*,
    Win32::System::Rpc::RPC_C_AUTHN_WINNT,
};

/// GUID único del proveedor WFP de SamuLibre
#[cfg(target_os = "windows")]
const SAMULIBRE_WFP_PROVIDER_GUID: GUID = GUID::from_u128(0x9a4c7e12_4f3b_4d8a_b612_7c8e9f012345);

/// GUID único de la subcapa WFP de SamuLibre (coexiste con Windows Defender Firewall sin alterarlo)
#[cfg(target_os = "windows")]
const SAMULIBRE_WFP_SUBLAYER_GUID: GUID = GUID::from_u128(0x9a4c7e12_4f3b_4d8a_b612_7c8e9f012346);

#[cfg(target_os = "windows")]
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Controlador nativo de Windows Filtering Platform (WFP) en modo usuario.
/// No requiere controlador de kernel propio ni TESTSIGNING; opera directamente
/// contra el Base Filtering Engine (BFE) firmado por Microsoft.
pub struct WfpController {
    #[cfg(target_os = "windows")]
    engine_handle: Option<HANDLE>,
    status: WfpEngineStatus,
}

unsafe impl Send for WfpController {}
unsafe impl Sync for WfpController {}

impl WfpController {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "windows")]
            engine_handle: None,
            status: WfpEngineStatus {
                available: cfg!(target_os = "windows"),
                initialized: false,
                elevated: false,
                provider_registered: false,
                sublayer_registered: false,
                active_filter_count: 0,
                net_events_subscribed: false,
                last_error: None,
                mode_description: if cfg!(target_os = "windows") {
                    "WFP User-Mode API (BFE)".to_string()
                } else {
                    "No disponible (plataforma no Windows)".to_string()
                },
            },
        }
    }

    pub fn status(&self) -> WfpEngineStatus {
        self.status.clone()
    }

    /// Inicializa la sesión WFP, registra el proveedor y la subcapa propia de SamuLibre.
    /// No modifica ni desactiva Windows Defender Firewall.
    pub fn initialize(&mut self) -> Result<()> {
        #[cfg(target_os = "windows")]
        unsafe {
            if self.engine_handle.is_some() {
                return Ok(());
            }

            let mut session_name = to_wide_null("SamuLibre Network Defense Session");
            let mut session = FWPM_SESSION0::default();
            session.displayData.name = PWSTR(session_name.as_mut_ptr());
            // Usamos sesión dinámica: si el proceso cae abruptamente no deja filtros huérfanos bloqueando red,
            // mientras que el servicio Windows SamuLibreWatcher restaura las políticas al iniciar.
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;

            let mut handle = HANDLE::default();
            let res = FwpmEngineOpen0(
                None,
                RPC_C_AUTHN_WINNT,
                None,
                Some(&session),
                &mut handle,
            );

            if res != ERROR_SUCCESS.0 {
                let is_access_denied = res == 5 || res == 0x8032000D; // ERROR_ACCESS_DENIED / FWP_E_ACCESS_DENIED
                self.status.initialized = false;
                self.status.elevated = !is_access_denied;
                let msg = if is_access_denied {
                    "Permisos insuficientes para abrir BFE/WFP (requiere Administrador o Servicio LocalSystem)".to_string()
                } else {
                    format!("FwpmEngineOpen0 falló con código 0x{:08X}", res)
                };
                self.status.last_error = Some(msg.clone());
                warn!("WFP initialize: {}", msg);
                return Err(anyhow!(msg));
            }

            self.engine_handle = Some(handle);
            self.ensure_provider_and_sublayer(handle)?;
            if !self.status.provider_registered || !self.status.sublayer_registered {
                self.status.initialized = false;
                self.status.elevated = false;
                let msg = "WFP BFE abierto, pero registrar Proveedor/Subcapa requiere Administrador o Servicio LocalSystem".to_string();
                self.status.last_error = Some(msg.clone());
                warn!("WFP initialize: {}", msg);
                return Err(anyhow!(msg));
            }

            self.status.initialized = true;
            self.status.elevated = true;
            self.status.last_error = None;
            self.refresh_filter_count();
            info!("Motor WFP de SamuLibre inicializado correctamente en BFE.");
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("WFP solo está disponible en Windows"))
        }
    }

    #[cfg(target_os = "windows")]
    unsafe fn ensure_provider_and_sublayer(&mut self, handle: HANDLE) -> Result<()> {
        let mut prov_name = to_wide_null("SamuLibre Network Defense Provider");
        let mut prov_desc = to_wide_null("Proveedor oficial de filtrado WFP de SamuLibre (coexiste con Windows Defender Firewall)");
        let mut provider = FWPM_PROVIDER0::default();
        provider.providerKey = SAMULIBRE_WFP_PROVIDER_GUID;
        provider.displayData.name = PWSTR(prov_name.as_mut_ptr());
        provider.displayData.description = PWSTR(prov_desc.as_mut_ptr());

        let res_prov = FwpmProviderAdd0(handle, &provider, None);
        // FWP_E_ALREADY_EXISTS = 0x80320009
        if res_prov == ERROR_SUCCESS.0 || res_prov == 0x80320009 {
            self.status.provider_registered = true;
        } else {
            warn!("FwpmProviderAdd0 retornó 0x{:08X}", res_prov);
        }

        let mut sub_name = to_wide_null("SamuLibre Network Defense SubLayer");
        let mut sub_desc = to_wide_null("Subcapa de políticas de aplicaciones, DNS y Tor Secure Mode");
        let mut sublayer = FWPM_SUBLAYER0::default();
        sublayer.subLayerKey = SAMULIBRE_WFP_SUBLAYER_GUID;
        sublayer.displayData.name = PWSTR(sub_name.as_mut_ptr());
        sublayer.displayData.description = PWSTR(sub_desc.as_mut_ptr());
        sublayer.providerKey = &SAMULIBRE_WFP_PROVIDER_GUID as *const GUID as *mut GUID;
        sublayer.weight = 0x7FFF;

        let res_sub = FwpmSubLayerAdd0(handle, &sublayer, None);
        if res_sub == ERROR_SUCCESS.0 || res_sub == 0x80320009 {
            self.status.sublayer_registered = true;
        } else {
            warn!("FwpmSubLayerAdd0 retornó 0x{:08X}", res_sub);
        }

        Ok(())
    }

    /// Aplica una regla de firewall real en WFP (IPv4 y/o IPv6, Entrada y/o Salida).
    /// Devuelve los IDs de filtros creados en el BFE.
    pub fn apply_rule(&mut self, rule: &FirewallRule) -> Result<Vec<u64>> {
        if !rule.enabled {
            return Ok(Vec::new());
        }

        #[cfg(target_os = "windows")]
        unsafe {
            let handle = match self.engine_handle {
                Some(h) => h,
                None => return Err(anyhow!("Motor WFP no inicializado")),
            };

            let mut filter_ids = Vec::new();
            let action_type = match rule.action {
                RuleAction::Allow => FWP_ACTION_PERMIT,
                RuleAction::Block | RuleAction::TorOnly => FWP_ACTION_BLOCK,
            };

            let mut layers = Vec::new();
            if rule.ipv4 {
                match rule.direction {
                    TrafficDirection::Outbound => layers.push((FWPM_LAYER_ALE_AUTH_CONNECT_V4, false)),
                    TrafficDirection::Inbound => layers.push((FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false)),
                    TrafficDirection::Both => {
                        layers.push((FWPM_LAYER_ALE_AUTH_CONNECT_V4, false));
                        layers.push((FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, false));
                    }
                }
            }
            if rule.ipv6 {
                match rule.direction {
                    TrafficDirection::Outbound => layers.push((FWPM_LAYER_ALE_AUTH_CONNECT_V6, true)),
                    TrafficDirection::Inbound => layers.push((FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, true)),
                    TrafficDirection::Both => {
                        layers.push((FWPM_LAYER_ALE_AUTH_CONNECT_V6, true));
                        layers.push((FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, true));
                    }
                }
            }

            // Obtener AppId si se especificó ruta de ejecutable
            let mut app_blob_ptr: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
            if let Some(ref app_path) = rule.app_path {
                let wide_path = to_wide_null(app_path);
                let res_app = FwpmGetAppIdFromFileName0(
                    windows::core::PCWSTR(wide_path.as_ptr()),
                    &mut app_blob_ptr,
                );
                if res_app != ERROR_SUCCESS.0 {
                    warn!("FwpmGetAppIdFromFileName0 falló para '{}' (0x{:08X})", app_path, res_app);
                    app_blob_ptr = std::ptr::null_mut();
                }
            }

            for (layer_key, is_v6) in layers {
                let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::new();

                if !app_blob_ptr.is_null() {
                    let mut cond = FWPM_FILTER_CONDITION0::default();
                    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    cond.matchType = FWP_MATCH_EQUAL;
                    cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                    cond.conditionValue.Anonymous.byteBlob = app_blob_ptr;
                    conditions.push(cond);
                }

                // Protocolo
                let proto_num: Option<u8> = match rule.protocol {
                    NetProtocol::Tcp => Some(6),
                    NetProtocol::Udp => Some(17),
                    NetProtocol::Icmp => Some(if is_v6 { 58 } else { 1 }),
                    NetProtocol::Any => None,
                };
                if let Some(p) = proto_num {
                    let mut cond = FWPM_FILTER_CONDITION0::default();
                    cond.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                    cond.matchType = FWP_MATCH_EQUAL;
                    cond.conditionValue.r#type = FWP_UINT8;
                    cond.conditionValue.Anonymous.uint8 = p;
                    conditions.push(cond);
                }

                // Puerto remoto
                if let Some(port) = rule.remote_port {
                    let mut cond = FWPM_FILTER_CONDITION0::default();
                    cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    cond.matchType = FWP_MATCH_EQUAL;
                    cond.conditionValue.r#type = FWP_UINT16;
                    cond.conditionValue.Anonymous.uint16 = port;
                    conditions.push(cond);
                }

                // Puerto local
                if let Some(lport) = rule.local_port {
                    let mut cond = FWPM_FILTER_CONDITION0::default();
                    cond.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
                    cond.matchType = FWP_MATCH_EQUAL;
                    cond.conditionValue.r#type = FWP_UINT16;
                    cond.conditionValue.Anonymous.uint16 = lport;
                    conditions.push(cond);
                }

                // IP remota (si coincide con la familia IPv4/IPv6 de la capa)
                let mut v4_mask = FWP_V4_ADDR_AND_MASK::default();
                let mut v6_mask = FWP_V6_ADDR_AND_MASK::default();
                if let Some(ref ip_str) = rule.remote_ip {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        match (ip, is_v6) {
                            (IpAddr::V4(v4), false) => {
                                v4_mask.addr = u32::from_be_bytes(v4.octets());
                                v4_mask.mask = 0xFFFFFFFF;
                                let mut cond = FWPM_FILTER_CONDITION0::default();
                                cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                                cond.matchType = FWP_MATCH_EQUAL;
                                cond.conditionValue.r#type = FWP_V4_ADDR_MASK;
                                cond.conditionValue.Anonymous.v4AddrMask = &mut v4_mask;
                                conditions.push(cond);
                            }
                            (IpAddr::V6(v6), true) => {
                                v6_mask.addr = v6.octets();
                                v6_mask.prefixLength = 128;
                                let mut cond = FWPM_FILTER_CONDITION0::default();
                                cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                                cond.matchType = FWP_MATCH_EQUAL;
                                cond.conditionValue.r#type = FWP_V6_ADDR_MASK;
                                cond.conditionValue.Anonymous.v6AddrMask = &mut v6_mask;
                                conditions.push(cond);
                            }
                            _ => {
                                // Familia IP no coincide con esta capa, omitir esta capa
                                continue;
                            }
                        }
                    }
                }

                let mut filter_name = to_wide_null(&format!("SamuLibre_{}", rule.name));
                let mut filter = FWPM_FILTER0::default();
                filter.displayData.name = PWSTR(filter_name.as_mut_ptr());
                filter.providerKey = &SAMULIBRE_WFP_PROVIDER_GUID as *const GUID as *mut GUID;
                filter.layerKey = layer_key;
                filter.subLayerKey = SAMULIBRE_WFP_SUBLAYER_GUID;
                filter.action.r#type = action_type;
                filter.weight.r#type = FWP_UINT8;
                filter.weight.Anonymous.uint8 = if action_type == FWP_ACTION_PERMIT { 10 } else { 5 };
                filter.numFilterConditions = conditions.len() as u32;
                if !conditions.is_empty() {
                    filter.filterCondition = conditions.as_mut_ptr();
                }

                let mut filter_id: u64 = 0;
                let res = FwpmFilterAdd0(handle, &filter, None, Some(&mut filter_id));
                if res == ERROR_SUCCESS.0 {
                    filter_ids.push(filter_id);
                } else {
                    warn!("FwpmFilterAdd0 falló para '{}' con 0x{:08X}", rule.name, res);
                }
            }

            if !app_blob_ptr.is_null() {
                FwpmFreeMemory0(&mut (app_blob_ptr as *mut std::ffi::c_void));
            }

            self.refresh_filter_count();
            Ok(filter_ids)
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = rule;
            Ok(Vec::new())
        }
    }

    /// Aplica filtros de aislamiento estricto para Tor Secure Mode:
    /// 1. Permite a `app_path` conectar únicamente a `127.0.0.1:socks_port` (y control_port si > 0) con peso alto (15).
    /// 2. Bloquea todo el resto del tráfico IPv4 e IPv6 saliente para `app_path` con peso 10 (Fail-Closed).
    pub fn apply_tor_app_isolation(
        &mut self,
        app_path: &str,
        socks_port: u16,
        control_port: u16,
        block_ipv6: bool,
    ) -> Result<Vec<u64>> {
        #[cfg(target_os = "windows")]
        unsafe {
            let handle = match self.engine_handle {
                Some(h) => h,
                None => return Err(anyhow!("Motor WFP no inicializado")),
            };

            let wide_path = to_wide_null(app_path);
            let mut app_blob_ptr: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
            let res_app = FwpmGetAppIdFromFileName0(
                windows::core::PCWSTR(wide_path.as_ptr()),
                &mut app_blob_ptr,
            );
            if res_app != ERROR_SUCCESS.0 || app_blob_ptr.is_null() {
                return Err(anyhow!(
                    "No se pudo resolver AppId WFP para '{}' (0x{:08X})",
                    app_path,
                    res_app
                ));
            }

            let mut created_ids = Vec::new();

            // 1. PERMITIR 127.0.0.1:socks_port (y control_port) con peso 15
            for port in [socks_port, control_port] {
                if port == 0 {
                    continue;
                }
                let mut v4_mask = FWP_V4_ADDR_AND_MASK {
                    addr: 0x7F000001, // 127.0.0.1
                    mask: 0xFFFFFFFF,
                };
                let mut conds = [
                    FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_ALE_APP_ID,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_BYTE_BLOB_TYPE,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                byteBlob: app_blob_ptr,
                            },
                        },
                    },
                    FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_V4_ADDR_MASK,
                            Anonymous: FWP_CONDITION_VALUE0_0 {
                                v4AddrMask: &mut v4_mask,
                            },
                        },
                    },
                    FWPM_FILTER_CONDITION0 {
                        fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                        matchType: FWP_MATCH_EQUAL,
                        conditionValue: FWP_CONDITION_VALUE0 {
                            r#type: FWP_UINT16,
                            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
                        },
                    },
                ];

                let mut name = to_wide_null(&format!("SamuLibre_Tor_Allow_Loopback_{}", port));
                let mut filter = FWPM_FILTER0::default();
                filter.displayData.name = PWSTR(name.as_mut_ptr());
                filter.providerKey = &SAMULIBRE_WFP_PROVIDER_GUID as *const GUID as *mut GUID;
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                filter.subLayerKey = SAMULIBRE_WFP_SUBLAYER_GUID;
                filter.action.r#type = FWP_ACTION_PERMIT;
                filter.weight.r#type = FWP_UINT8;
                filter.weight.Anonymous.uint8 = 15;
                filter.numFilterConditions = conds.len() as u32;
                filter.filterCondition = conds.as_mut_ptr();

                let mut fid = 0u64;
                if FwpmFilterAdd0(handle, &filter, None, Some(&mut fid)) == ERROR_SUCCESS.0 {
                    created_ids.push(fid);
                }
            }

            // 2. BLOQUEAR todo otro tráfico saliente IPv4 para app_path (peso 10)
            {
                let mut cond = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_APP_ID,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_BLOB_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            byteBlob: app_blob_ptr,
                        },
                    },
                };
                let mut name = to_wide_null("SamuLibre_Tor_Block_Direct_V4");
                let mut filter = FWPM_FILTER0::default();
                filter.displayData.name = PWSTR(name.as_mut_ptr());
                filter.providerKey = &SAMULIBRE_WFP_PROVIDER_GUID as *const GUID as *mut GUID;
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                filter.subLayerKey = SAMULIBRE_WFP_SUBLAYER_GUID;
                filter.action.r#type = FWP_ACTION_BLOCK;
                filter.weight.r#type = FWP_UINT8;
                filter.weight.Anonymous.uint8 = 10;
                filter.numFilterConditions = 1;
                filter.filterCondition = &mut cond;

                let mut fid = 0u64;
                if FwpmFilterAdd0(handle, &filter, None, Some(&mut fid)) == ERROR_SUCCESS.0 {
                    created_ids.push(fid);
                }
            }

            // 3. BLOQUEAR todo tráfico saliente IPv6 para app_path (peso 10)
            if block_ipv6 {
                let mut cond = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_APP_ID,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_BLOB_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            byteBlob: app_blob_ptr,
                        },
                    },
                };
                let mut name = to_wide_null("SamuLibre_Tor_Block_Direct_V6");
                let mut filter = FWPM_FILTER0::default();
                filter.displayData.name = PWSTR(name.as_mut_ptr());
                filter.providerKey = &SAMULIBRE_WFP_PROVIDER_GUID as *const GUID as *mut GUID;
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
                filter.subLayerKey = SAMULIBRE_WFP_SUBLAYER_GUID;
                filter.action.r#type = FWP_ACTION_BLOCK;
                filter.weight.r#type = FWP_UINT8;
                filter.weight.Anonymous.uint8 = 10;
                filter.numFilterConditions = 1;
                filter.filterCondition = &mut cond;

                let mut fid = 0u64;
                if FwpmFilterAdd0(handle, &filter, None, Some(&mut fid)) == ERROR_SUCCESS.0 {
                    created_ids.push(fid);
                }
            }

            FwpmFreeMemory0(&mut (app_blob_ptr as *mut std::ffi::c_void));
            self.refresh_filter_count();
            Ok(created_ids)
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (app_path, socks_port, control_port, block_ipv6);
            Ok(Vec::new())
        }
    }

    /// Elimina un filtro específico de WFP por ID
    pub fn remove_filter(&mut self, filter_id: u64) -> Result<()> {
        #[cfg(target_os = "windows")]
        unsafe {
            if let Some(handle) = self.engine_handle {
                let res = FwpmFilterDeleteById0(handle, filter_id);
                if res != ERROR_SUCCESS.0 && res != 0x80320003 {
                    // FWP_E_FILTER_NOT_FOUND
                    warn!("FwpmFilterDeleteById0({}) retornó 0x{:08X}", filter_id, res);
                }
                self.refresh_filter_count();
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = filter_id;
        }
        Ok(())
    }

    pub fn remove_filters(&mut self, filter_ids: &[u64]) {
        for &id in filter_ids {
            let _ = self.remove_filter(id);
        }
    }

    /// Limpia únicamente los filtros pertenecientes al proveedor/subcapa de SamuLibre
    pub fn clear_all_samulibre_filters(&mut self) -> Result<usize> {
        #[cfg(target_os = "windows")]
        unsafe {
            let handle = match self.engine_handle {
                Some(h) => h,
                None => return Ok(0),
            };

            let mut template = FWPM_FILTER_ENUM_TEMPLATE0::default();
            template.providerKey = &SAMULIBRE_WFP_PROVIDER_GUID as *const GUID as *mut GUID;

            let mut enum_handle = HANDLE::default();
            if FwpmFilterCreateEnumHandle0(handle, Some(&template), &mut enum_handle) != ERROR_SUCCESS.0 {
                return Ok(0);
            }

            let mut entries_ptr: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut num_returned: u32 = 0;
            let mut removed = 0usize;

            if FwpmFilterEnum0(handle, enum_handle, 512, &mut entries_ptr, &mut num_returned) == ERROR_SUCCESS.0
                && !entries_ptr.is_null()
            {
                let slice = std::slice::from_raw_parts(entries_ptr, num_returned as usize);
                for &f_ptr in slice {
                    if !f_ptr.is_null() {
                        let fid = (*f_ptr).filterId;
                        if FwpmFilterDeleteById0(handle, fid) == ERROR_SUCCESS.0 {
                            removed += 1;
                        }
                    }
                }
                FwpmFreeMemory0(&mut (entries_ptr as *mut std::ffi::c_void));
            }

            FwpmFilterDestroyEnumHandle0(handle, enum_handle);
            self.refresh_filter_count();
            Ok(removed)
        }

        #[cfg(not(target_os = "windows"))]
        Ok(0)
    }

    #[cfg(target_os = "windows")]
    unsafe fn refresh_filter_count(&mut self) {
        let Some(handle) = self.engine_handle else {
            self.status.active_filter_count = 0;
            return;
        };
        let mut template = FWPM_FILTER_ENUM_TEMPLATE0::default();
        template.providerKey = &SAMULIBRE_WFP_PROVIDER_GUID as *const GUID as *mut GUID;
        let mut enum_handle = HANDLE::default();
        if FwpmFilterCreateEnumHandle0(handle, Some(&template), &mut enum_handle) != ERROR_SUCCESS.0 {
            return;
        }
        let mut entries_ptr: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut num_returned: u32 = 0;
        if FwpmFilterEnum0(handle, enum_handle, 512, &mut entries_ptr, &mut num_returned) == ERROR_SUCCESS.0 {
            self.status.active_filter_count = num_returned as usize;
            if !entries_ptr.is_null() {
                FwpmFreeMemory0(&mut (entries_ptr as *mut std::ffi::c_void));
            }
        }
        FwpmFilterDestroyEnumHandle0(handle, enum_handle);
    }
}

impl Drop for WfpController {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        unsafe {
            if let Some(handle) = self.engine_handle.take() {
                let _ = FwpmEngineClose0(handle);
            }
        }
    }
}
