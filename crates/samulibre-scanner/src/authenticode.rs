use samulibre_types::AuthenticodeSummary;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

static AUTHENTICODE_CACHE: OnceLock<Mutex<HashMap<String, AuthenticodeSummary>>> = OnceLock::new();

fn cache() -> &'static Mutex<HashMap<String, AuthenticodeSummary>> {
    AUTHENTICODE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Verifica criptográficamente la firma Authenticode del archivo mediante `WinVerifyTrust`
/// y extrae el nombre del publicador real mediante `CryptQueryObject` (con caché por SHA-256).
pub fn verify_authenticode_cached(
    path: &Path,
    sha256: &str,
    has_embedded_security_dir: bool,
) -> AuthenticodeSummary {
    if !has_embedded_security_dir {
        return AuthenticodeSummary {
            is_signed: false,
            is_valid_chain: false,
            publisher: None,
            status_detail: "Sin firma Authenticode embebida".to_string(),
        };
    }

    if !sha256.is_empty() {
        if let Ok(guard) = cache().lock() {
            if let Some(cached) = guard.get(sha256) {
                return cached.clone();
            }
        }
    }

    let summary = verify_authenticode_os(path);

    if !sha256.is_empty() {
        if let Ok(mut guard) = cache().lock() {
            if guard.len() > 20_000 {
                guard.clear();
            }
            guard.insert(sha256.to_string(), summary.clone());
        }
    }

    summary
}

#[cfg(target_os = "windows")]
fn verify_authenticode_os(path: &Path) -> AuthenticodeSummary {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    struct WinTrustFileInfo {
        cb_struct: u32,
        pcwsz_file_path: *const u16,
        h_file: *mut c_void,
        pg_known_subject: *const Guid,
    }

    #[repr(C)]
    struct WinTrustCatalogInfo {
        cb_struct: u32,
        dw_catalog_version: u32,
        pcwsz_catalog_file_path: *const u16,
        pcwsz_member_tag: *const u16,
        pcwsz_member_file_path: *const u16,
        h_member_file: *mut c_void,
        pb_calculated_file_hash: *mut u8,
        cb_calculated_file_hash: u32,
        pc_catalog_context: *const c_void,
        h_cat_admin: *mut c_void,
    }

    #[repr(C)]
    union WinTrustUnion {
        p_file: *mut WinTrustFileInfo,
        p_catalog: *mut WinTrustCatalogInfo,
    }

    #[repr(C)]
    struct WinTrustData {
        cb_struct: u32,
        p_policy_callback_data: *mut c_void,
        p_sip_client_data: *mut c_void,
        dw_ui_choice: u32,
        fdw_revocation_checks: u32,
        dw_union_choice: u32,
        u: WinTrustUnion,
        dw_state_action: u32,
        h_wv_state_data: *mut c_void,
        pwsz_url_reference: *const u16,
        dw_prov_flags: u32,
        dw_ui_context: u32,
        p_signature_settings: *mut c_void,
    }

    #[repr(C)]
    struct CatalogInfo {
        cb_struct: u32,
        wsz_catalog_file: [u16; 260],
    }

    #[link(name = "wintrust")]
    extern "system" {
        fn WinVerifyTrust(
            hwnd: *mut c_void,
            pg_action_id: *mut Guid,
            p_wvt_data: *mut c_void,
        ) -> i32;
        fn CryptCATAdminAcquireContext(
            ph_cat_admin: *mut *mut c_void,
            pg_subsystem: *const Guid,
            dw_flags: u32,
        ) -> i32;
        fn CryptCATAdminReleaseContext(h_cat_admin: *mut c_void, dw_flags: u32) -> i32;
        fn CryptCATAdminCalcHashFromFileHandle(
            h_file: *mut c_void,
            pcb_hash: *mut u32,
            pb_hash: *mut u8,
            dw_flags: u32,
        ) -> i32;
        fn CryptCATAdminEnumCatalogFromHash(
            h_cat_admin: *mut c_void,
            pb_hash: *mut u8,
            cb_hash: u32,
            dw_flags: u32,
            ph_prev_cat_info: *mut *mut c_void,
        ) -> *mut c_void;
        fn CryptCATCatalogInfoFromContext(
            h_cat_info: *mut c_void,
            ps_cat_info: *mut CatalogInfo,
            dw_flags: u32,
        ) -> i32;
        fn CryptCATAdminReleaseCatalogContext(
            h_cat_admin: *mut c_void,
            h_cat_info: *mut c_void,
            dw_flags: u32,
        ) -> i32;
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptQueryObject(
            dw_object_type: u32,
            pv_object: *const c_void,
            dw_expected_content_type_flags: u32,
            dw_expected_format_type_flags: u32,
            dw_flags: u32,
            pdw_msg_and_cert_encoding_type: *mut u32,
            pdw_content_type: *mut u32,
            pdw_format_type: *mut u32,
            ph_cert_store: *mut *mut c_void,
            ph_msg: *mut *mut c_void,
            ppv_context: *mut *const c_void,
        ) -> i32;
        fn CertEnumCertificatesInStore(
            h_cert_store: *mut c_void,
            p_prev_cert_context: *const c_void,
        ) -> *const c_void;
        fn CertGetNameStringW(
            p_cert_context: *const c_void,
            dw_type: u32,
            dw_flags: u32,
            pv_type_para: *mut c_void,
            psz_name_string: *mut u16,
            cch_name_string: u32,
        ) -> u32;
        fn CertFreeCertificateContext(p_cert_context: *const c_void) -> i32;
        fn CertCloseStore(h_cert_store: *mut c_void, dw_flags: u32) -> i32;
        fn CryptMsgClose(h_crypt_msg: *mut c_void) -> i32;
    }

    const WTD_UI_NONE: u32 = 2;
    const WTD_REVOKE_NONE: u32 = 0;
    const WTD_CHOICE_FILE: u32 = 1;
    const WTD_CHOICE_CATALOG: u32 = 2;
    const WTD_STATEACTION_VERIFY: u32 = 1;
    const WTD_STATEACTION_CLOSE: u32 = 2;
    // WTD_CACHE_ONLY_URL_RETRIEVAL evita latencia de red CRL/OCSP durante escaneos masivos
    const WTD_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_1000;
    const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    let mut action_guid = Guid {
        data1: 0x00AA_C56B,
        data2: 0xCD44,
        data3: 0x11D0,
        data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    };

    let mut file_info = WinTrustFileInfo {
        cb_struct: std::mem::size_of::<WinTrustFileInfo>() as u32,
        pcwsz_file_path: wide_path.as_ptr(),
        h_file: null_mut(),
        pg_known_subject: null(),
    };

    let mut trust_data = WinTrustData {
        cb_struct: std::mem::size_of::<WinTrustData>() as u32,
        p_policy_callback_data: null_mut(),
        p_sip_client_data: null_mut(),
        dw_ui_choice: WTD_UI_NONE,
        fdw_revocation_checks: WTD_REVOKE_NONE,
        dw_union_choice: WTD_CHOICE_FILE,
        u: WinTrustUnion {
            p_file: &mut file_info,
        },
        dw_state_action: WTD_STATEACTION_VERIFY,
        h_wv_state_data: null_mut(),
        pwsz_url_reference: null(),
        dw_prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dw_ui_context: 0,
        p_signature_settings: null_mut(),
    };

    let status = unsafe {
        WinVerifyTrust(
            null_mut(),
            &mut action_guid,
            (&mut trust_data as *mut WinTrustData).cast::<c_void>(),
        )
    };

    trust_data.dw_state_action = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            null_mut(),
            &mut action_guid,
            (&mut trust_data as *mut WinTrustData).cast::<c_void>(),
        );
    }

    if status == 0 {
        let publisher = extract_publisher_name(&wide_path);
        let status_detail = match &publisher {
            Some(pub_name) => {
                format!("Firma Authenticode verificada (WinVerifyTrust OK): {}", pub_name)
            }
            None => "Firma Authenticode verificada (WinVerifyTrust OK)".to_string(),
        };
        return AuthenticodeSummary {
            is_signed: true,
            is_valid_chain: true,
            publisher,
            status_detail,
        };
    }

    // Si no tiene firma embebida PKCS#7, consultar el Catálogo de Windows (.cat en System32\CatRoot)
    if (status as u32) == TRUST_E_NOSIGNATURE {
        if let Some(cat_summary) = verify_via_windows_catalog(path, &wide_path, &mut action_guid) {
            return cat_summary;
        }
    }

    let publisher = extract_publisher_name(&wide_path);
    return AuthenticodeSummary {
        is_signed: true,
        is_valid_chain: false,
        publisher,
        status_detail: format!(
            "Firma Authenticode presente pero NO confiable o inválida (WinVerifyTrust=0x{:08X})",
            status as u32
        ),
    };

    fn verify_via_windows_catalog(
        path: &Path,
        wide_path: &[u16],
        action_guid: &mut Guid,
    ) -> Option<AuthenticodeSummary> {
        use std::os::windows::io::AsRawHandle;

        let file = std::fs::File::open(path).ok()?;
        let h_file = file.as_raw_handle() as *mut c_void;

        let mut h_cat_admin: *mut c_void = null_mut();
        if unsafe { CryptCATAdminAcquireContext(&mut h_cat_admin, null(), 0) } == 0
            || h_cat_admin.is_null()
        {
            return None;
        }

        let mut hash_len: u32 = 64;
        let mut hash_buf = vec![0u8; hash_len as usize];
        let calc_ok = unsafe {
            CryptCATAdminCalcHashFromFileHandle(
                h_file,
                &mut hash_len,
                hash_buf.as_mut_ptr(),
                0,
            )
        };
        if calc_ok == 0 {
            unsafe { CryptCATAdminReleaseContext(h_cat_admin, 0) };
            return None;
        }
        hash_buf.truncate(hash_len as usize);

        let h_cat_info = unsafe {
            CryptCATAdminEnumCatalogFromHash(
                h_cat_admin,
                hash_buf.as_mut_ptr(),
                hash_len,
                0,
                null_mut(),
            )
        };
        if h_cat_info.is_null() {
            unsafe { CryptCATAdminReleaseContext(h_cat_admin, 0) };
            return None;
        }

        let mut cat_info = CatalogInfo {
            cb_struct: std::mem::size_of::<CatalogInfo>() as u32,
            wsz_catalog_file: [0u16; 260],
        };
        let info_ok = unsafe { CryptCATCatalogInfoFromContext(h_cat_info, &mut cat_info, 0) };
        if info_ok == 0 {
            unsafe {
                CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
                CryptCATAdminReleaseContext(h_cat_admin, 0);
            }
            return None;
        }

        let tag_wide: Vec<u16> = hash_buf
            .iter()
            .flat_map(|b| format!("{:02X}", b).encode_utf16().collect::<Vec<u16>>())
            .chain(std::iter::once(0))
            .collect();

        let mut wci = WinTrustCatalogInfo {
            cb_struct: std::mem::size_of::<WinTrustCatalogInfo>() as u32,
            dw_catalog_version: 0,
            pcwsz_catalog_file_path: cat_info.wsz_catalog_file.as_ptr(),
            pcwsz_member_tag: tag_wide.as_ptr(),
            pcwsz_member_file_path: wide_path.as_ptr(),
            h_member_file: h_file,
            pb_calculated_file_hash: hash_buf.as_mut_ptr(),
            cb_calculated_file_hash: hash_len,
            pc_catalog_context: null(),
            h_cat_admin: null_mut(),
        };

        let mut wtd = WinTrustData {
            cb_struct: std::mem::size_of::<WinTrustData>() as u32,
            p_policy_callback_data: null_mut(),
            p_sip_client_data: null_mut(),
            dw_ui_choice: WTD_UI_NONE,
            fdw_revocation_checks: WTD_REVOKE_NONE,
            dw_union_choice: WTD_CHOICE_CATALOG,
            u: WinTrustUnion {
                p_catalog: &mut wci,
            },
            dw_state_action: WTD_STATEACTION_VERIFY,
            h_wv_state_data: null_mut(),
            pwsz_url_reference: null(),
            dw_prov_flags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            dw_ui_context: 0,
            p_signature_settings: null_mut(),
        };

        let cat_status = unsafe {
            WinVerifyTrust(
                null_mut(),
                action_guid,
                (&mut wtd as *mut WinTrustData).cast::<c_void>(),
            )
        };
        wtd.dw_state_action = WTD_STATEACTION_CLOSE;
        unsafe {
            WinVerifyTrust(
                null_mut(),
                action_guid,
                (&mut wtd as *mut WinTrustData).cast::<c_void>(),
            );
            CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
            CryptCATAdminReleaseContext(h_cat_admin, 0);
        }

        if cat_status == 0 {
            let cat_len = cat_info
                .wsz_catalog_file
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(cat_info.wsz_catalog_file.len());
            let publisher = extract_publisher_name(&cat_info.wsz_catalog_file[..=cat_len]);
            let detail = match &publisher {
                Some(p) => format!("Firma verificada vía Catálogo de Windows: {}", p),
                None => "Firma verificada vía Catálogo de Windows (WinVerifyTrust OK)".to_string(),
            };
            Some(AuthenticodeSummary {
                is_signed: true,
                is_valid_chain: true,
                publisher,
                status_detail: detail,
            })
        } else {
            None
        }
    }

    fn extract_publisher_name(wide_path: &[u16]) -> Option<String> {
        const CERT_QUERY_OBJECT_FILE: u32 = 1;
        const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED: u32 = 1 << 10;
        const CERT_QUERY_FORMAT_FLAG_BINARY: u32 = 1 << 1;
        const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;

        let mut encoding = 0u32;
        let mut content_type = 0u32;
        let mut format_type = 0u32;
        let mut h_store: *mut c_void = null_mut();
        let mut h_msg: *mut c_void = null_mut();

        let ok = unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                wide_path.as_ptr().cast::<c_void>(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                &mut encoding,
                &mut content_type,
                &mut format_type,
                &mut h_store,
                &mut h_msg,
                null_mut(),
            )
        };

        if ok == 0 || h_store.is_null() {
            if !h_msg.is_null() {
                unsafe { CryptMsgClose(h_msg) };
            }
            return None;
        }

        let mut best_name: Option<String> = None;
        let mut prev_cert: *const c_void = null();

        // Tomar el primer certificado hoja no-CA / no genérico de timestamping
        loop {
            let cert = unsafe { CertEnumCertificatesInStore(h_store, prev_cert) };
            if cert.is_null() {
                break;
            }
            let mut buf = [0u16; 256];
            let len = unsafe {
                CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    null_mut(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                )
            };
            if len > 1 {
                let name = String::from_utf16_lossy(&buf[..(len as usize - 1)])
                    .trim()
                    .to_string();
                let lower = name.to_ascii_lowercase();
                let is_ca_or_tsa = lower.contains("root")
                    || lower.contains("authority")
                    || lower.contains("timestamp")
                    || lower.contains("tsa")
                    || lower.contains("intermediate");
                if !name.is_empty() && !is_ca_or_tsa {
                    best_name = Some(name);
                    unsafe { CertFreeCertificateContext(cert) };
                    break;
                } else if best_name.is_none() && !name.is_empty() {
                    best_name = Some(name);
                }
            }
            prev_cert = cert;
        }

        unsafe {
            CertCloseStore(h_store, 0);
            if !h_msg.is_null() {
                CryptMsgClose(h_msg);
            }
        }

        best_name
    }
}

#[cfg(not(target_os = "windows"))]
fn verify_authenticode_os(_path: &Path) -> AuthenticodeSummary {
    AuthenticodeSummary {
        is_signed: true,
        is_valid_chain: false,
        publisher: None,
        status_detail: "Verificación Authenticode nativa disponible solo en Windows".to_string(),
    }
}
