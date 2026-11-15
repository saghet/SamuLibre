use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Detalle explicable de un indicador de riesgo heurístico detectado en el binario PE
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeuristicIndicator {
    pub code: String,
    pub weight: u32,
    pub category: String,
    pub description: String,
}

/// Informe completo del análisis estructural PE y veredicto heurístico explicable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAnalysisReport {
    pub is_valid_pe: bool,
    pub is_64bit: bool,
    pub compile_timestamp: u32,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub subsystem: String,
    pub number_of_sections: usize,
    pub sections: Vec<PeSectionInfo>,
    pub imported_dlls: Vec<String>,
    pub suspicious_apis_detected: Vec<String>,
    pub has_authenticode_signature: bool,
    pub is_dotnet: bool,
    pub heuristic_score: u32, // 0 a 100
    pub is_suspicious: bool,
    pub indicators: Vec<HeuristicIndicator>,
    pub primary_reason: Option<String>,
}

/// Metadatos forenses de una sección del archivo PE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub characteristics: u32,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_wx: bool, // Writable AND Executable (Peligro: Shellcode/Unpacker)
    pub entropy: f64,
}

/// Analizador e Inspector Heurístico de Estructuras PE (Portable Executable)
pub struct PeAnalyzer;

impl PeAnalyzer {
    const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
    const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // "PE\0\0"
    #[allow(dead_code)]
    const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
    #[allow(dead_code)]
    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    #[allow(dead_code)]
    const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

    const SCN_MEM_EXECUTE: u32 = 0x20000000;
    #[allow(dead_code)]
    const SCN_MEM_READ: u32 = 0x40000000;
    const SCN_MEM_WRITE: u32 = 0x80000000;

    /// Analiza un búfer de bytes como un archivo ejecutable Portable Executable
    pub fn analyze(data: &[u8]) -> Option<PeAnalysisReport> {
        if data.len() < 0x40 {
            return None;
        }

        // 1. Validar DOS Header
        let dos_magic = u16::from_le_bytes(data[0..2].try_into().ok()?);
        if dos_magic != Self::IMAGE_DOS_SIGNATURE {
            return None;
        }

        let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
        if e_lfanew + 24 > data.len() {
            return None;
        }

        // 2. Validar PE Signature
        let pe_sig = u32::from_le_bytes(data[e_lfanew..e_lfanew + 4].try_into().ok()?);
        if pe_sig != Self::IMAGE_NT_SIGNATURE {
            return None;
        }

        // 3. COFF File Header
        let file_header_offset = e_lfanew + 4;
        let _machine = u16::from_le_bytes(data[file_header_offset..file_header_offset + 2].try_into().ok()?);
        let num_sections = u16::from_le_bytes(data[file_header_offset + 2..file_header_offset + 4].try_into().ok()?) as usize;
        let time_date_stamp = u32::from_le_bytes(data[file_header_offset + 4..file_header_offset + 8].try_into().ok()?);
        let size_of_opt_header = u16::from_le_bytes(data[file_header_offset + 16..file_header_offset + 18].try_into().ok()?) as usize;

        // 4. Optional Header
        let opt_header_offset = file_header_offset + 20;
        if opt_header_offset + size_of_opt_header > data.len() || size_of_opt_header < 28 {
            return None;
        }

        let opt_magic = u16::from_le_bytes(data[opt_header_offset..opt_header_offset + 2].try_into().ok()?);
        let is_64bit = opt_magic == 0x020b; // PE32+

        let entry_point_rva = u32::from_le_bytes(data[opt_header_offset + 16..opt_header_offset + 20].try_into().ok()?);

        let (image_base, subsystem_raw, security_dir_rva, security_dir_size, import_dir_rva) = if is_64bit {
            if opt_header_offset + 112 > data.len() {
                return None;
            }
            let base = u64::from_le_bytes(data[opt_header_offset + 24..opt_header_offset + 32].try_into().ok()?);
            let sub = u16::from_le_bytes(data[opt_header_offset + 68..opt_header_offset + 70].try_into().ok()?);
            // Data directories in PE32+ start at offset 112
            let data_dirs_offset = opt_header_offset + 112;
            let import_rva = if data_dirs_offset + 16 <= opt_header_offset + size_of_opt_header {
                u32::from_le_bytes(data[data_dirs_offset + 8..data_dirs_offset + 12].try_into().unwrap_or([0; 4]))
            } else { 0 };

            let (sec_rva, sec_sz) = if data_dirs_offset + 36 <= opt_header_offset + size_of_opt_header {
                // Security Directory is entry index 4 (offset 4 * 8 = 32 bytes)
                (
                    u32::from_le_bytes(data[data_dirs_offset + 32..data_dirs_offset + 36].try_into().unwrap_or([0; 4])),
                    u32::from_le_bytes(data[data_dirs_offset + 36..data_dirs_offset + 40].try_into().unwrap_or([0; 4])),
                )
            } else { (0, 0) };

            (base, sub, sec_rva, sec_sz, import_rva)
        } else {
            if opt_header_offset + 96 > data.len() {
                return None;
            }
            let base = u32::from_le_bytes(data[opt_header_offset + 28..opt_header_offset + 32].try_into().ok()?) as u64;
            let sub = u16::from_le_bytes(data[opt_header_offset + 68..opt_header_offset + 70].try_into().ok()?);
            let data_dirs_offset = opt_header_offset + 96;
            let import_rva = if data_dirs_offset + 16 <= opt_header_offset + size_of_opt_header {
                u32::from_le_bytes(data[data_dirs_offset + 8..data_dirs_offset + 12].try_into().unwrap_or([0; 4]))
            } else { 0 };

            let (sec_rva, sec_sz) = if data_dirs_offset + 36 <= opt_header_offset + size_of_opt_header {
                (
                    u32::from_le_bytes(data[data_dirs_offset + 32..data_dirs_offset + 36].try_into().unwrap_or([0; 4])),
                    u32::from_le_bytes(data[data_dirs_offset + 36..data_dirs_offset + 40].try_into().unwrap_or([0; 4])),
                )
            } else { (0, 0) };

            (base, sub, sec_rva, sec_sz, import_rva)
        };

        let subsystem = match subsystem_raw {
            1 => "Native/Driver",
            2 => "Windows GUI",
            3 => "Windows CUI (Console)",
            7 => "POSIX",
            _ => "Unknown",
        }.to_string();

        let has_authenticode_signature = security_dir_rva > 0 && security_dir_size > 0;

        // 5. Parse Section Headers
        let section_table_offset = opt_header_offset + size_of_opt_header;
        let mut sections = Vec::new();
        let mut total_score: u32 = 0;
        let mut indicators = Vec::new();

        let known_packer_sections = [
            "upx0", "upx1", "upx2", ".aspack", ".adata", ".vmp0", ".vmp1", "themida", "fsg!", "mew", ".mpress", ".packer"
        ];

        for i in 0..num_sections.min(96) {
            let offset = section_table_offset + i * 40;
            if offset + 40 > data.len() {
                break;
            }

            let raw_name_bytes = &data[offset..offset + 8];
            let name_end = raw_name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let section_name = String::from_utf8_lossy(&raw_name_bytes[..name_end]).trim().to_string();

            let virtual_size = u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4]));
            let virtual_address = u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap_or([0; 4]));
            let raw_size = u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap_or([0; 4]));
            let raw_pointer = u32::from_le_bytes(data[offset + 20..offset + 24].try_into().unwrap_or([0; 4]));
            let characteristics = u32::from_le_bytes(data[offset + 36..offset + 40].try_into().unwrap_or([0; 4]));

            let is_executable = (characteristics & Self::SCN_MEM_EXECUTE) != 0;
            let is_writable = (characteristics & Self::SCN_MEM_WRITE) != 0;
            let is_wx = is_executable && is_writable;

            // Calcular entropía sobre el contenido real de la sección
            let sec_start = raw_pointer as usize;
            let sec_len = raw_size as usize;
            let section_entropy = if sec_start < data.len() && sec_len > 0 {
                let actual_end = (sec_start + sec_len).min(data.len());
                calculate_entropy(&data[sec_start..actual_end])
            } else {
                0.0
            };

            let name_lower = section_name.to_lowercase();

            // EVALUACIÓN HEURÍSTICA:
            // Regla A: Sección WX (Writable + Executable) -> Por sí sola (ej. Cygwin/MSYS2/DRM/JIT)
            // tiene peso moderado (20 < umbral Medio 35) para no condenar sin correlación de inyección/entropía/EP.
            if is_wx && raw_size > 0 {
                indicators.push(HeuristicIndicator {
                    code: "HEUR_PE_WX_SECTION".to_string(),
                    weight: 20,
                    category: "Evasion/Shellcode".to_string(),
                    description: format!("Sección '{}' posee permisos simultáneos de Escritura y Ejecución (WX)", section_name),
                });
                total_score += 20;
            }

            // Regla B: Nombres de sección de empaquetadores reconocidos
            if known_packer_sections.iter().any(|&p| name_lower.contains(p)) {
                indicators.push(HeuristicIndicator {
                    code: "HEUR_PE_KNOWN_PACKER".to_string(),
                    weight: 30,
                    category: "Obfuscation".to_string(),
                    description: format!("Nombre de sección '{}' corresponde a empaquetador conocido (UPX/VMProtect/Themida)", section_name),
                });
                total_score += 30;
            }

            // Regla C: Sección .text con entropía anormalmente alta (> 7.25)
            // (A diferencia de .rsrc, código ejecutable comprimido indica empaquetado/cifrado de malware)
            if (name_lower == ".text" || name_lower == "code") && section_entropy > 7.25 {
                indicators.push(HeuristicIndicator {
                    code: "HEUR_PE_HIGH_TEXT_ENTROPY".to_string(),
                    weight: 25,
                    category: "Crypter/Polymorphic".to_string(),
                    description: format!("Sección de código '{}' presenta entropía extrema ({:.2} > 7.25), indicando cifrado", section_name, section_entropy),
                });
                total_score += 25;
            }

            // Regla D: Discrepancia masiva entre VirtualSize y RawSize (Unpacking stub)
            // Ignorar alineación normal a página de memoria (<= 64 KB) de secciones pequeñas como .tls/.data
            if virtual_size > 65536 && raw_size > 0 && (virtual_size > raw_size * 5) {
                indicators.push(HeuristicIndicator {
                    code: "HEUR_PE_VIRTUAL_RAW_DISCREPANCY".to_string(),
                    weight: 20,
                    category: "UnpackerStub".to_string(),
                    description: format!("Sección '{}' tiene VirtualSize ({}) > 5x RawSize ({}), patrón de expansión en memoria", section_name, virtual_size, raw_size),
                });
                total_score += 20;
            }

            sections.push(PeSectionInfo {
                name: section_name,
                virtual_size,
                virtual_address,
                raw_size,
                raw_pointer,
                characteristics,
                is_executable,
                is_writable,
                is_wx,
                entropy: section_entropy,
            });
        }

        // 6. Extracción de Importaciones (IAT) y Detección de APIs Críticas
        let (imported_dlls, suspicious_apis) = extract_imports_and_suspicious_apis(data, import_dir_rva, &sections);

        // Detectar ensamblados .NET / CLR (entry 14 = COM Descriptor en DataDirectory o mscoree.dll)
        let data_dirs_offset = if is_64bit { opt_header_offset + 112 } else { opt_header_offset + 96 };
        let com_desc_rva = if data_dirs_offset + 120 <= opt_header_offset + size_of_opt_header {
            u32::from_le_bytes(data[data_dirs_offset + 112..data_dirs_offset + 116].try_into().unwrap_or([0; 4]))
        } else {
            0
        };
        let is_dotnet = com_desc_rva > 0 || imported_dlls.iter().any(|d| d.eq_ignore_ascii_case("mscoree.dll"));

        // Regla E: Combinación clásica de Inyección / Process Hollowing
        let has_alloc = suspicious_apis.iter().any(|api| api.contains("VirtualAllocEx"));
        let has_write = suspicious_apis.iter().any(|api| api.contains("WriteProcessMemory"));
        let has_thread = suspicious_apis.iter().any(|api| api.contains("CreateRemoteThread") || api.contains("QueueUserAPC") || api.contains("SetThreadContext"));

        if has_alloc && has_write && has_thread {
            indicators.push(HeuristicIndicator {
                code: "HEUR_PE_PROCESS_INJECTION_CLUSTER".to_string(),
                weight: 40,
                category: "ProcessInjection".to_string(),
                description: "Conjunto completo de APIs para Process Hollowing / Inyección Remota (VirtualAllocEx + WriteProcessMemory + ThreadControl)".to_string(),
            });
            total_score += 40;
        }

        // Regla F: APIs de anti-debugging y evasión
        let has_anti_debug = suspicious_apis.iter().any(|api| api.contains("IsDebuggerPresent") || api.contains("CheckRemoteDebuggerPresent"));
        if has_anti_debug {
            indicators.push(HeuristicIndicator {
                code: "HEUR_PE_ANTI_DEBUGGING".to_string(),
                weight: 15,
                category: "Evasion".to_string(),
                description: "Presencia de llamadas nativas para detección y evasión de depuradores".to_string(),
            });
            total_score += 15;
        }

        // Regla G: Evasión por resolución dinámica exclusiva (LoadLibrary + GetProcAddress sin otras importaciones)
        let has_dynamic_load = suspicious_apis.iter().any(|api| api.contains("LoadLibrary")) && suspicious_apis.iter().any(|api| api.contains("GetProcAddress"));
        if has_dynamic_load && imported_dlls.len() <= 2 {
            indicators.push(HeuristicIndicator {
                code: "HEUR_PE_MINIMAL_DYNAMIC_RESOLVER".to_string(),
                weight: 20,
                category: "Obfuscation".to_string(),
                description: "Binario oculta su tabla de importaciones resolviendo todas sus APIs dinámicamente en tiempo de ejecución".to_string(),
            });
            total_score += 20;
        }

        // CALIBRACIÓN DE SCORE Y PREVENCIÓN DE FALSOS POSITIVOS:
        // Si el binario posee una firma digital Authenticode válida y no tiene inyección activa ni WX,
        // o si es un ejecutable empacado legítimo firmado (ej. Rufus con UPX), reducimos el riesgo heurístico.
        if has_authenticode_signature {
            let has_wx = indicators.iter().any(|i| i.code == "HEUR_PE_WX_SECTION");
            if !indicators.iter().any(|i| i.code == "HEUR_PE_PROCESS_INJECTION_CLUSTER") {
                total_score = total_score.saturating_sub(50);
            } else if !has_wx {
                // Herramientas legítimas firmadas (debuggers, MSBuild FileTracker, profilers) usan APIs de proceso sin WX
                total_score = total_score.saturating_sub(30);
            }
        }

        let final_score = total_score.min(100);
        let is_suspicious = final_score >= 65;
        let primary_reason = if is_suspicious {
            indicators.first().map(|i| format!("{}: {}", i.code, i.description))
        } else {
            None
        };

        Some(PeAnalysisReport {
            is_valid_pe: true,
            is_64bit,
            compile_timestamp: time_date_stamp,
            entry_point_rva,
            image_base,
            subsystem,
            number_of_sections: sections.len(),
            sections,
            imported_dlls,
            suspicious_apis_detected: suspicious_apis,
            has_authenticode_signature,
            is_dotnet,
            heuristic_score: final_score,
            is_suspicious,
            indicators,
            primary_reason,
        })
    }
}

/// Convierte una Dirección Virtual Relativa (RVA) a un desplazamiento en el archivo (File Offset)
fn rva_to_file_offset(rva: u32, sections: &[PeSectionInfo]) -> Option<usize> {
    for sec in sections {
        if rva >= sec.virtual_address && rva < sec.virtual_address + sec.virtual_size.max(sec.raw_size) {
            let offset_into_sec = rva - sec.virtual_address;
            return Some((sec.raw_pointer + offset_into_sec) as usize);
        }
    }
    None
}

/// Extrae nombres de DLLs e identifica APIs sospechosas de la Import Directory Table
fn extract_imports_and_suspicious_apis(
    data: &[u8],
    import_rva: u32,
    sections: &[PeSectionInfo],
) -> (Vec<String>, Vec<String>) {
    let mut dlls = HashSet::new();
    let mut suspicious_apis = Vec::new();

    if import_rva == 0 {
        return (Vec::new(), Vec::new());
    }

    let mut dir_offset = match rva_to_file_offset(import_rva, sections) {
        Some(off) => off,
        None => return (Vec::new(), Vec::new()),
    };

    let suspicious_watchlist = [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC",
        "SetThreadContext", "ResumeThread", "NtQueueApcThread",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "CryptUnprotectData", "GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
        "CryptEncrypt", "BCryptEncrypt", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
        "MiniDumpWriteDump", "AdjustTokenPrivileges"
    ];

    // Iterar IMAGE_IMPORT_DESCRIPTOR (cada uno tiene 20 bytes)
    for _ in 0..128 {
        if dir_offset + 20 > data.len() {
            break;
        }

        let original_first_thunk = u32::from_le_bytes(data[dir_offset..dir_offset + 4].try_into().unwrap_or([0; 4]));
        let name_rva = u32::from_le_bytes(data[dir_offset + 12..dir_offset + 16].try_into().unwrap_or([0; 4]));
        let first_thunk = u32::from_le_bytes(data[dir_offset + 16..dir_offset + 20].try_into().unwrap_or([0; 4]));

        // Estructura nula termina la tabla
        if name_rva == 0 && first_thunk == 0 {
            break;
        }

        if let Some(name_offset) = rva_to_file_offset(name_rva, sections) {
            if name_offset < data.len() {
                let max_len = (data.len() - name_offset).min(64);
                let dll_end = data[name_offset..name_offset + max_len]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(max_len);
                let dll_name = String::from_utf8_lossy(&data[name_offset..name_offset + dll_end]).to_string();
                if !dll_name.is_empty() {
                    dlls.insert(dll_name.to_lowercase());
                }
            }
        }

        // Inspeccionar Thunks para nombres de funciones importadas
        let thunk_rva = if original_first_thunk != 0 { original_first_thunk } else { first_thunk };
        if let Some(mut thunk_offset) = rva_to_file_offset(thunk_rva, sections) {
            for _ in 0..256 {
                if thunk_offset + 4 > data.len() {
                    break;
                }
                let thunk_val = u32::from_le_bytes(data[thunk_offset..thunk_offset + 4].try_into().unwrap_or([0; 4]));
                if thunk_val == 0 {
                    break;
                }

                // Si el bit más significativo no está activo, apunta a IMAGE_IMPORT_BY_NAME
                if (thunk_val & 0x80000000) == 0 {
                    if let Some(func_name_offset) = rva_to_file_offset(thunk_val + 2, sections) {
                        if func_name_offset < data.len() {
                            let max_len = (data.len() - func_name_offset).min(64);
                            let end = data[func_name_offset..func_name_offset + max_len]
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(max_len);
                            let func_name = String::from_utf8_lossy(&data[func_name_offset..func_name_offset + end]);
                            for &watched in &suspicious_watchlist {
                                if func_name.eq_ignore_ascii_case(watched) {
                                    suspicious_apis.push(watched.to_string());
                                }
                            }
                        }
                    }
                }
                thunk_offset += 4;
            }
        }

        dir_offset += 20;
    }

    let mut dll_list: Vec<String> = dlls.into_iter().collect();
    dll_list.sort();
    (dll_list, suspicious_apis)
}

/// Calcula la entropía de Shannon (0.0 a 8.0)
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len_f = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_parser_rejects_non_pe() {
        let text = b"This is just a plain text file, not a portable executable.";
        assert!(PeAnalyzer::analyze(text).is_none());
    }

    #[test]
    fn test_synthetic_pe_wx_detection() {
        // Generar estructura mínima válida de PE con sección WX
        let mut fake_pe = vec![0u8; 1024];
        fake_pe[0] = b'M';
        fake_pe[1] = b'Z';
        fake_pe[0x3C] = 0x80; // e_lfanew = 128

        let pe_off = 128;
        fake_pe[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        fake_pe[pe_off + 4..pe_off + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        fake_pe[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes()); // 1 sección
        fake_pe[pe_off + 20..pe_off + 22].copy_from_slice(&0x00E0u16.to_le_bytes()); // Opt header size = 224

        // Opt header (PE32+)
        let opt_off = pe_off + 24;
        fake_pe[opt_off..opt_off + 2].copy_from_slice(&0x020bu16.to_le_bytes()); // PE32+

        // Section header
        let sec_off = opt_off + 224;
        fake_pe[sec_off..sec_off + 8].copy_from_slice(b"UPX0\0\0\0\0");
        fake_pe[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        fake_pe[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        fake_pe[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes()); // RawSize
        fake_pe[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes()); // RawPointer
        // Characteristics: Writable (0x80000000) + Executable (0x20000000) = WX
        fake_pe[sec_off + 36..sec_off + 40].copy_from_slice(&(0x80000000u32 | 0x20000000u32).to_le_bytes());

        let report = PeAnalyzer::analyze(&fake_pe).expect("Debe parsear PE sintético");
        assert!(report.is_valid_pe);
        assert!(report.is_64bit);
        assert_eq!(report.sections.len(), 1);
        assert!(report.sections[0].is_wx, "Debe detectar sección WX");
        assert!(report.heuristic_score >= 50, "Debe sumar UPX (30) + WX (20)");
        assert!(report.indicators.iter().any(|i| i.code == "HEUR_PE_WX_SECTION"));
    }
}
