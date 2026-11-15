#[cfg(target_os = "windows")]
pub mod native {
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hKey: isize,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut isize,
        ) -> i32;

        fn RegQueryValueExW(
            hKey: isize,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;

        fn RegEnumKeyExW(
            hKey: isize,
            dwIndex: u32,
            lpName: *mut u16,
            lpcchName: *mut u32,
            lpReserved: *mut u32,
            lpClass: *mut u16,
            lpcchClass: *mut u32,
            lpftLastWriteTime: *mut u64,
        ) -> i32;

        fn RegCloseKey(hKey: isize) -> i32;
    }

    const HKEY_LOCAL_MACHINE: isize = 0x80000002u32 as isize;
    const KEY_READ: u32 = 0x20019;
    const ERROR_SUCCESS: i32 = 0;
    const ERROR_NO_MORE_ITEMS: i32 = 259;

    fn to_wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Abre una clave bajo HKLM en modo solo lectura
    pub struct RegKey {
        handle: isize,
    }

    impl RegKey {
        pub fn open_hklm(sub_key: &str) -> Option<Self> {
            let wide = to_wide_null(sub_key);
            let mut handle: isize = 0;
            let status = unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    wide.as_ptr(),
                    0,
                    KEY_READ,
                    &mut handle as *mut isize,
                )
            };
            if status == ERROR_SUCCESS && handle != 0 {
                Some(RegKey { handle })
            } else {
                None
            }
        }

        pub fn get_string(&self, name: &str) -> Option<String> {
            let wide_name = to_wide_null(name);
            let mut val_type: u32 = 0;
            let mut data_len: u32 = 0;

            // Primer pase para obtener tamaño
            let status = unsafe {
                RegQueryValueExW(
                    self.handle,
                    wide_name.as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    std::ptr::null_mut(),
                    &mut data_len,
                )
            };
            if status != ERROR_SUCCESS || data_len == 0 {
                return None;
            }

            let mut buf = vec![0u8; data_len as usize];
            let status = unsafe {
                RegQueryValueExW(
                    self.handle,
                    wide_name.as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    buf.as_mut_ptr(),
                    &mut data_len,
                )
            };
            if status != ERROR_SUCCESS {
                return None;
            }

            // UTF-16 a String
            let u16_slice = unsafe {
                std::slice::from_raw_parts(buf.as_ptr() as *const u16, (data_len as usize) / 2)
            };
            let mut s = String::from_utf16_lossy(u16_slice);
            if s.ends_with('\0') {
                s.pop();
            }
            Some(s)
        }

        pub fn get_u32(&self, name: &str) -> Option<u32> {
            let wide_name = to_wide_null(name);
            let mut val_type: u32 = 0;
            let mut val: u32 = 0;
            let mut data_len: u32 = 4;

            let status = unsafe {
                RegQueryValueExW(
                    self.handle,
                    wide_name.as_ptr(),
                    std::ptr::null_mut(),
                    &mut val_type,
                    &mut val as *mut u32 as *mut u8,
                    &mut data_len,
                )
            };
            if status == ERROR_SUCCESS {
                Some(val)
            } else {
                None
            }
        }

        /// Enumera todas las subclaves de esta clave
        pub fn enum_subkeys(&self) -> Vec<String> {
            let mut subkeys = Vec::new();
            let mut index = 0u32;
            let mut name_buf = [0u16; 512];

            loop {
                let mut name_len = name_buf.len() as u32;
                let status = unsafe {
                    RegEnumKeyExW(
                        self.handle,
                        index,
                        name_buf.as_mut_ptr(),
                        &mut name_len,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };

                if status == ERROR_NO_MORE_ITEMS {
                    break;
                }
                if status == ERROR_SUCCESS {
                    let s = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                    subkeys.push(s);
                }
                index += 1;
                if index > 20000 {
                    break; // Límite de seguridad
                }
            }
            subkeys
        }
    }

    impl Drop for RegKey {
        fn drop(&mut self) {
            if self.handle != 0 {
                unsafe {
                    RegCloseKey(self.handle);
                }
            }
        }
    }

    /// Lee paquetes CBS directamente de HKLM sin ejecutar PowerShell
    pub fn read_cbs_packages_direct() -> Vec<(String, u32, String)> {
        let mut results = Vec::new();
        let sub_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages";
        if let Some(key) = RegKey::open_hklm(sub_path) {
            let subkeys = key.enum_subkeys();
            for sub_name in subkeys {
                if sub_name.contains("KB") {
                    let child_path = format!(r"{}\{}", sub_path, sub_name);
                    if let Some(child_key) = RegKey::open_hklm(&child_path) {
                        let state = child_key.get_u32("CurrentState").unwrap_or(0);
                        let client = child_key
                            .get_string("InstallClient")
                            .unwrap_or_else(|| "CBS".to_string());
                        results.push((sub_name, state, client));
                    }
                }
            }
        }
        results
    }
}
