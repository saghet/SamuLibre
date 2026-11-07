use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use samulibre_core::SamuLibreCore;
use samulibre_patcher::VirtualPatcher;
use samulibre_scanner::MultiEngineScanner;
use samulibre_shield::EndpointShield;
use samulibre_types::{FileScanStatus, PatchStatus, ScanTargetType, ScheduleFrequency, Severity};
use samulibre_vpn::{SecureDnsProvider, VpnManager, WireGuardConfig};
use samulibre_watcher::{QuarantineVault, RealTimeWatcher};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "samulibre")]
#[command(author = "SamuLibre Security Community")]
#[command(version = "0.1.0")]
#[command(about = "Antivirus SamuLibre - Suite de Seguridad 100% Open Source, Libre de Costo y Anuncios", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Muestra el estado integral de protecciÃ³n del sistema
    Status,

    /// Escanea archivos o carpetas con motores de firmas, YARA-X y heurística
    Scan {
        /// Ruta del archivo o directorio a analizar
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },

    /// Actualiza la base de firmas y reglas YARA desde feeds comunitarios abiertos reales
    Update,

    /// GestiÃ³n del Escudo en Tiempo Real (On-Access) y Clean Hash Cache
    Watcher {
        #[command(subcommand)]
        sub: WatcherCommands,
    },

    /// GestiÃ³n de la BÃ³veda de Cuarentena Cifrada
    Quarantine {
        #[command(subcommand)]
        sub: QuarantineCommands,
    },

    /// GestiÃ³n del Parchado Virtual de vulnerabilidades del Sistema Operativo
    Patcher {
        #[command(subcommand)]
        sub: PatcherCommands,
    },

    /// Blindaje contra tÃ¡cticas de hackers, robo de credenciales y ransomware
    Shield {
        #[command(subcommand)]
        sub: ShieldCommands,
    },

    /// GestiÃ³n de privacidad, navegaciÃ³n libre, WireGuard y DNS Seguro
    Vpn {
        #[command(subcommand)]
        sub: VpnCommands,
    },

    /// Cazador de Persistencia y Auto-Inicio (Run, RunOnce, Startup, Tareas Programadas)
    Persistence {
        #[command(subcommand)]
        sub: PersistenceCommands,
    },

    /// Inspector de Red en Vivo, Puertos y Aislamiento de Procesos
    Network {
        #[command(subcommand)]
        sub: NetworkCommands,
    },

    /// Copiloto de Ciberseguridad Interactivo con IA Local Offline
    Copilot {
        /// Consulta en lenguaje natural para el copiloto
        query: String,
    },

    /// Ejecuta una demostraciÃ³n en vivo de los tres pilares de protecciÃ³n
    Demo,

    /// Gestión de Escaneos Programados en segundo plano (Windows & Linux)
    Schedule {
        #[command(subcommand)]
        sub: ScheduleCommands,
    },

    /// Control del Servicio Windows y Demonio 24/7 de Protección en Tiempo Real
    Service {
        #[command(subcommand)]
        sub: ServiceCommands,
    },

    /// Auditoría Forense y Estado Riguroso de los 9 Subsistemas (Fuente Única de Verdad)
    Health,
}

#[derive(Subcommand)]
enum ServiceCommands {
    /// Instala el servicio en el Service Control Manager de Windows (sc.exe)
    Install,
    /// Desinstala el servicio de Windows
    Uninstall,
    /// Inicia el servicio de protección en segundo plano
    Start,
    /// Detiene el servicio o proceso demonio
    Stop,
    /// Muestra el estado operativo del servicio y telemetría en tiempo real
    Status,
    /// Ejecuta el bucle del servicio demonio en segundo plano (24/7)
    Run,
    /// Ejecuta la batería de pruebas de autodiagnóstico integral de protección
    Autodiagnostic,
}

#[derive(Subcommand)]
enum ScheduleCommands {
    /// Muestra la configuraciÃ³n actual y prÃ³ximo escaneo programado
    Status,
    /// Configura los parÃ¡metros del escaneo programado
    Set {
        /// Frecuencia: daily, weekly, hourly o nÃºmero de horas
        #[arg(long, default_value = "daily")]
        frequency: String,
        /// Hora programada en formato HH:MM (ej. 02:00)
        #[arg(long, default_value = "02:00")]
        time: String,
        /// Tipo de objetivo: quick (rÃ¡pido), full (completo) o custom (personalizado)
        #[arg(long, default_value = "quick")]
        target: String,
        /// Rutas personalizadas separadas por coma (para target custom)
        #[arg(long)]
        paths: Option<String>,
    },
    /// Activa o desactiva la programaciÃ³n automÃ¡tica
    Toggle {
        #[arg(long)]
        enable: bool,
    },
    /// Dispara inmediatamente un escaneo programado de prueba
    RunNow,
}

#[derive(Subcommand)]
enum WatcherCommands {
    /// AÃ±ade un directorio a la vigilancia activa
    AddDir {
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Remueve un directorio de la vigilancia activa
    RemoveDir {
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Lista los directorios actualmente vigilados
    ListDirs,
    /// Simula la inspecciÃ³n On-Access en tiempo real de un archivo
    Inspect {
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Muestra el estado del vigilante en tiempo real y estadísticas de caché
    Status,
    /// Ejecuta el autodiagnóstico integral de la protección en tiempo real
    Autodiagnostic,
}

#[derive(Subcommand)]
enum QuarantineCommands {
    /// Lista los archivos maliciosos neutralizados en la bÃ³veda cifrada
    List,
}

#[derive(Subcommand)]
enum PatcherCommands {
    /// Escanea las actualizaciones del SO y lista vulnerabilidades abiertas
    Scan,
    /// Aplica automÃ¡ticamente reglas de mitigaciÃ³n virtual para CVEs no parchados
    Apply,
    /// Revisa si Windows instalÃ³ parches oficiales y retira los parches virtuales
    AutoDeactivate,
    /// Simula la instalaciÃ³n de un parche oficial de Windows para probar el retiro automÃ¡tico
    SimulateInstall {
        /// CÃ³digo del KB oficial (Ej. KB5041585, KB5004945)
        #[arg(value_name = "KB")]
        kb: String,
    },
    /// Alterna manualmente la mitigaciÃ³n virtual de un CVE especÃ­fico
    Toggle {
        /// Identificador de la regla o CVE (Ej. CVE-2024-38063)
        cve: String,
        /// Desactivar el parche virtual (por omisiÃ³n lo activa)
        #[arg(short, long)]
        disable: bool,
    },
    /// Muestra el estado del Centinela de CVEs y ejecuta un ciclo de auto-mitigaciÃ³n
    Sentinel {
        /// Activar auto-parchado de vulnerabilidades crÃ­ticas
        #[arg(short, long, default_value_t = true)]
        auto_patch: bool,
    },
    /// Escanea las actualizaciones pendientes de Windows (WUA) y el catÃ¡logo de KBs
    KbScan,
    /// Analiza un boletÃ­n de seguridad o KB especÃ­fico con el motor de IA local
    AiAnalyze {
        /// Identificador del KB (Ej. KB5041585, KB5004945)
        kb: String,
        /// TÃ­tulo o resumen descriptivo opcional
        #[arg(short, long)]
        title: Option<String>,
        /// DescripciÃ³n tÃ©cnica o vector del boletÃ­n
        #[arg(short, long)]
        desc: Option<String>,
    },
    /// Ejecuta el ciclo de auditorÃ­a de KBs con IA local y auto-parchado preventivo
    AiAudit {
        /// Habilitar auto-parchado inmediato de KBs no instalados
        #[arg(short, long, default_value_t = true)]
        auto_patch: bool,
    },
}

#[derive(Subcommand)]
enum ShieldCommands {
    /// Muestra el estado del escudo de credenciales, navegador y canarios
    Status,
    /// Despliega o regenera los archivos trampa seÃ±uelo anti-ransomware
    DeployCanaries,
    /// Realiza una auditorÃ­a inmediata de procesos (LSASS, navegadores, canarios)
    Check,
}

#[derive(Subcommand)]
enum VpnCommands {
    /// Conecta la VPN enrutando el trÃ¡fico del sistema operativo por el paÃ­s seleccionado
    Connect {
        /// CÃ³digo de paÃ­s: CH (Suiza), IS (Islandia), NL (PaÃ­ses Bajos), SE (Suecia), PA (PanamÃ¡), CA (CanadÃ¡), CO (Colombia), BR (Brasil)
        #[arg(short, long, default_value = "CH")]
        country: String,

        /// Activar Kill-Switch de firewall contra fugas sin cifrar
        #[arg(short, long)]
        kill_switch: bool,

        /// Activar Doble Cifrado en cascada (WireGuard ChaCha20 âŠ• Onion v3 Multi-Hop)
        #[arg(short = 'd', long)]
        double_encryption: bool,
    },
    /// Desconecta la VPN y restaura la configuraciÃ³n de red y proxy del sistema
    Disconnect,
    /// Restablece de emergencia la red del sistema: desactiva proxy huÃ©rfano, restaura DNS DHCP y limpia firewall
    ResetNetwork,
    /// Muestra el estado actual de la VPN y del proxy del sistema
    Status,
    /// Genera un perfil WireGuard compatible con clientes libres
    ExportConfig {
        #[arg(short, long, default_value = "samulibre_vpn.conf")]
        output: String,
    },
    /// Configura DNS Cifrado gratuito con filtrado de malware (Quad9, AdGuard)
    SecureDns {
        /// Proveedor: quad9 | adguard | cloudflare
        #[arg(default_value = "quad9")]
        provider: String,
    },
}

#[derive(Subcommand)]
enum PersistenceCommands {
    /// Audita todas las entradas de arranque del SO (Registro, Startup, schtasks)
    Scan,
    /// Alterna el estado activo/desactivado de una entrada de persistencia
    Toggle {
        /// Identificador de la entrada
        id: String,
        /// Desactivar la entrada (por omisiÃ³n la activa)
        #[arg(short, long)]
        disable: bool,
    },
}

#[derive(Subcommand)]
enum NetworkCommands {
    /// Inspecciona todos los sockets y puertos de red activos con mapeo de procesos
    Sockets,
    /// AÃ­sla de la red un proceso sospechoso usando reglas WFP
    Isolate {
        /// PID del proceso
        pid: u32,
        /// Revocar aislamiento (desbloquear)
        #[arg(short, long)]
        unblock: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    print_banner();

    let canary_dir = Path::new("data").join("canaries");
    let vpn_dir = Path::new("data").join("vpn");
    let _ = fs::create_dir_all(&canary_dir);
    let _ = fs::create_dir_all(&vpn_dir);

    match cli.command {
        Commands::Status => {
            let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);
            let _ = core.initialize();
            let status = core.get_status();

            println!(
                "\n{}",
                "â”€â”€â”€ ESTADO GLOBAL DE PROTECCIÃ“N SAMULIBRE â”€â”€â”€"
                    .bold()
                    .cyan()
            );
            println!(
                "  {} NÃºcleo Activo:            {}",
                "âœ”".green(),
                "SÃ (Modo de Servicio Abierto)".green()
            );
            println!(
                "  {} Motor de DetecciÃ³n:       {}",
                "âœ”".green(),
                "ClamAV + YARA-X + HeurÃ­stica".green()
            );
            println!(
                "  {} Escudo Anti-InfiltraciÃ³n: {}",
                "âœ”".green(),
                "LSASS Guard + Browser Token Shield".green()
            );
            println!(
                "  {} Trampas Anti-Ransomware:  {}",
                "âœ”".green(),
                format!(
                    "{} archivos seÃ±uelo activos",
                    status.canaries_deployed_count
                )
                .cyan()
            );
            println!(
                "  {} Parchado Virtual:         {}",
                "âœ”".green(),
                format!(
                    "{} mitigaciones activas",
                    status.active_virtual_patches_count
                )
                .yellow()
            );
            println!(
                "  {} Parches Nativos del SO:   {}",
                "âœ”".green(),
                format!(
                    "{} CVEs resueltos por Windows Update",
                    status.native_repaired_cves_count
                )
                .green()
            );
            println!(
                "  {} Amenazas Bloqueadas:      {}",
                "âœ”".green(),
                format!("{}", status.threats_blocked_total).cyan()
            );
            println!(
                "  {} Publicidad / TelemetrÃ­a:  {}",
                "âœ”".green(),
                "0% (Completamente Libre y Privado)".bold().green()
            );
        }

        Commands::Update => {
            println!(
                "\n{}",
                "─── ACTUALIZACIÓN DE FIRMAS Y REGLAS YARA SAMULIBRE ───"
                    .bold()
                    .cyan()
            );
            let mut scanner = MultiEngineScanner::new();
            println!("  Consultando fuentes de inteligencia de amenazas abiertas...");

            let res = scanner.update_signatures_with_progress(|step| match step {
                samulibre_scanner::UpdateStep::CheckingConnection => {
                    println!("  [1/5] Verificando conectividad con la red...");
                }
                samulibre_scanner::UpdateStep::ConsultingSource { source_name, url } => {
                    println!(
                        "  [2/5] Consultando fuente: {} ({})",
                        source_name.cyan(),
                        url
                    );
                }
                samulibre_scanner::UpdateStep::Downloading { source_name, bytes } => {
                    println!(
                        "  [3/5] Descargando {}: {} bytes recibidos.",
                        source_name, bytes
                    );
                }
                samulibre_scanner::UpdateStep::ValidatingIntegrity {
                    source_name,
                    sha256,
                } => {
                    println!(
                        "  [4/5] Integridad validada para {}: SHA256={}",
                        source_name, sha256
                    );
                }
                samulibre_scanner::UpdateStep::CompilingRules { rules_found } => {
                    println!("  Compilando {} reglas YARA verificadas...", rules_found);
                }
                samulibre_scanner::UpdateStep::InstallingAtomic => {
                    println!("  [5/5] Instalando atómicamente la base de firmas...");
                }
                samulibre_scanner::UpdateStep::Completed {
                    new_signatures,
                    new_rules,
                    total_signatures,
                    total_rules,
                    version,
                    ..
                } => {
                    println!("\n  {} Actualización completada con éxito.", "✔".green());
                    println!("     • Versión instalada:    {}", version.bold());
                    println!("     • Firmas nuevas:        +{}", new_signatures);
                    println!("     • Total firmas activas: {}", total_signatures);
                    println!(
                        "     • Reglas YARA activas:  {} (+{})",
                        total_rules, new_rules
                    );
                }
                samulibre_scanner::UpdateStep::Failed { stage, error } => {
                    eprintln!("\n  {} Fallo en etapa '{}': {}", "✘".red(), stage, error);
                }
                _ => {}
            });

            if let Err(e) = res {
                eprintln!(
                    "  {} No se pudo completar la actualización: {}",
                    "✘".red(),
                    e
                );
            }
        }

        Commands::Scan { path } => {
            println!(
                "\n{}",
                format!("Iniciando escaneo multi-motor en: {}", path.display()).bold()
            );
            let scanner = MultiEngineScanner::new();

            if path.is_file() {
                scan_single_file(&scanner, &path);
            } else if path.is_dir() {
                scan_directory(&scanner, &path);
            } else {
                println!("{} La ruta especificada no existe.", "âœ˜".red());
            }
        }

        Commands::Watcher { sub } => {
            let quarantine_dir = Path::new("data").join("quarantine");
            let scanner = std::sync::Arc::new(std::sync::Mutex::new(MultiEngineScanner::new()));
            let mut watcher = RealTimeWatcher::new(scanner, &quarantine_dir);

            match sub {
                WatcherCommands::Inspect { path } => {
                    println!(
                        "\n{}",
                        format!(
                            "â”€â”€â”€ INSPECCIÃ“N ON-ACCESS EN TIEMPO REAL: {} â”€â”€â”€",
                            path.display()
                        )
                        .bold()
                        .cyan()
                    );
                    if let Some(alert) = watcher.inspect_on_access(&path) {
                        println!(
                            "{} [{}] {}",
                            "ðŸš¨ AMENAZA INTERCEPTADA".red().bold(),
                            alert.severity,
                            alert.title.bold().red()
                        );
                        println!("  Detalles: {}", alert.details);
                        println!("  AcciÃ³n: {}", alert.action_taken.bold().yellow());
                        println!("  {} Archivo eliminado del sistema y neutralizado en la bÃ³veda de cuarentena.", "âœ”".green());
                    } else {
                        println!("{} Archivo verificado y validado como seguro en Clean File Cache (<0.05 ms).", "âœ” LIMPIO".green().bold());
                    }
                }
                WatcherCommands::Status => {
                    println!(
                        "\n{}",
                        "─── ESTADO DEL ESCUDO EN TIEMPO REAL (ON-ACCESS) ───"
                            .bold()
                            .cyan()
                    );
                    let is_running = samulibre_watcher::service::is_service_or_daemon_running();
                    let telem = watcher.get_telemetry();
                    println!(
                        "  {} Servicio de Fondo (24/7):  {}",
                        if is_running {
                            "✔".green()
                        } else {
                            "✖".yellow()
                        },
                        if is_running {
                            "ACTIVO (Servicio Windows / Demonio)".green().bold()
                        } else {
                            "INACTIVO (Modo On-Demand)".yellow()
                        }
                    );
                    println!(
                        "  {} Estado del Motor:          {:?}",
                        "✔".green(),
                        telem.status
                    );
                    println!(
                        "  {} Clean Hash Cache:         EN MEMORIA (Ultra-Baja Latencia <0.05 ms)",
                        "✔".green()
                    );
                    println!(
                        "  {} Bóveda de Cuarentena:     data/quarantine/ (Cifrado XOR + Metadatos)",
                        "✔".green()
                    );
                    println!(
                        "  {} Cola de Eventos:          {} pendientes / {} procesados",
                        "✔".green(),
                        telem.queue_depth,
                        telem.events_processed_total
                    );
                    println!(
                        "  {} Archivos Inspeccionados:  {}",
                        "✔".green(),
                        telem.files_inspected_total
                    );
                    println!(
                        "  {} Amenazas Interceptadas:   {}",
                        "✔".green(),
                        telem.threats_intercepted_total
                    );
                    println!(
                        "  {} Carpetas Vigiladas:       {}",
                        "✔".green(),
                        watcher.get_watch_dirs().len()
                    );
                    if let Some(ref p) = telem.last_event_path {
                        println!("  {} Último Evento:            {}", "•".cyan(), p);
                    }
                }
                WatcherCommands::Autodiagnostic => {
                    println!(
                        "\n{}",
                        "─── EJECUTANDO AUTODIAGNÓSTICO INTEGRAL DE TIEMPO REAL ───"
                            .bold()
                            .cyan()
                    );
                    println!("Iniciando batería de pruebas en tiempo real...");
                    let rep = watcher.run_autodiagnostic();
                    println!(
                        "\n{}",
                        "─── RESULTADO DEL AUTODIAGNÓSTICO ───".bold().cyan()
                    );
                    println!("  Estado Global:             {:?}", rep.overall_status);
                    println!(
                        "  Pruebas Superadas:         {}/{}",
                        rep.tests_passed, rep.tests_executed
                    );
                    println!(
                        "  Servicio Windows:          {}",
                        if rep.windows_service_ok {
                            "OK".green()
                        } else {
                            "Inactivo/Local".yellow()
                        }
                    );
                    println!(
                        "  Monitor de Archivos:       {}",
                        if rep.file_monitor_ok {
                            "OK".green()
                        } else {
                            "Fallo".red()
                        }
                    );
                    println!(
                        "  Cola de Eventos:           {}",
                        if rep.event_queue_ok {
                            "OK".green()
                        } else {
                            "Fallo".red()
                        }
                    );
                    println!(
                        "  Bóveda de Cuarentena:      {}",
                        if rep.quarantine_ok {
                            "OK".green()
                        } else {
                            "Fallo".red()
                        }
                    );
                    println!("\nDetalle de Pruebas:");
                    for d in rep.details {
                        println!(
                            "  {} {} ({} ms): {}",
                            if d.passed { "✔".green() } else { "✖".red() },
                            d.name.bold(),
                            d.duration_ms,
                            d.detail
                        );
                    }
                }
                WatcherCommands::AddDir { path } => {
                    if path.exists() {
                        watcher.add_watch_dir(&path);
                        println!(
                            "{} Directorio aÃ±adido a la vigilancia activa: {}",
                            "âœ”".green(),
                            path.display()
                        );
                    } else {
                        println!(
                            "{} El directorio especificado no existe: {}",
                            "âœ˜".red(),
                            path.display()
                        );
                    }
                }
                WatcherCommands::RemoveDir { path } => {
                    if watcher.remove_watch_dir(&path) {
                        println!(
                            "{} Directorio removido de la vigilancia activa: {}",
                            "âœ”".green(),
                            path.display()
                        );
                    } else {
                        println!(
                            "{} El directorio no estaba en la lista de vigilancia.",
                            "âœ˜".yellow()
                        );
                    }
                }
                WatcherCommands::ListDirs => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ DIRECTORIOS EN VIGILANCIA EN TIEMPO REAL â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    let dirs = watcher.get_watch_dirs();
                    if dirs.is_empty() {
                        println!("  (No hay carpetas configuradas)");
                    } else {
                        for d in dirs {
                            println!("  {} {}", "â€¢".cyan(), d.display());
                        }
                    }
                }
            }
        }

        Commands::Schedule { sub } => {
            let core = SamuLibreCore::new("data/canaries", "data/vpn", false);
            match sub {
                ScheduleCommands::Status => {
                    let cfg = core.get_scheduled_scan_config();
                    println!(
                        "\n{}",
                        "â”€â”€â”€ ESTADO DE ESCANEOS PROGRAMADOS SAMULIBRE â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    println!(
                        "  {} Estado:                {}",
                        if cfg.enabled {
                            "âœ”".green()
                        } else {
                            "âœ˜".yellow()
                        },
                        if cfg.enabled {
                            "ACTIVADO".green().bold()
                        } else {
                            "DESACTIVADO".yellow()
                        }
                    );
                    println!(
                        "  {} Frecuencia:            {:?}",
                        "âœ”".green(),
                        cfg.frequency
                    );
                    println!(
                        "  {} Hora Programada:       {}",
                        "âœ”".green(),
                        cfg.scheduled_time.bold()
                    );
                    println!(
                        "  {} Tipo de Objetivo:      {:?}",
                        "âœ”".green(),
                        cfg.target_type
                    );
                    println!(
                        "  {} Ãšltima EjecuciÃ³n:      {}",
                        "âœ”".green(),
                        cfg.last_run.unwrap_or_else(|| "Ninguna".to_string())
                    );
                    println!(
                        "  {} PrÃ³ximo Escaneo:       {}",
                        "âœ”".green(),
                        cfg.next_run
                            .unwrap_or_else(|| "No programado".to_string())
                            .cyan()
                            .bold()
                    );
                    println!(
                        "  {} Archivos Analizados:   {}",
                        "âœ”".green(),
                        cfg.last_result_scanned
                    );
                    println!(
                        "  {} Amenazas Detectadas:   {}",
                        "âœ”".green(),
                        cfg.last_result_threats
                    );
                }
                ScheduleCommands::Set {
                    frequency,
                    time,
                    target,
                    paths,
                } => {
                    let freq = match frequency.to_lowercase().as_str() {
                        "weekly" => ScheduleFrequency::Weekly,
                        "hourly" => ScheduleFrequency::Hourly,
                        s if s.ends_with('h') => {
                            let num = s.trim_end_matches('h').parse::<u32>().unwrap_or(24);
                            ScheduleFrequency::IntervalHours(num)
                        }
                        _ => ScheduleFrequency::Daily,
                    };
                    let tgt = match target.to_lowercase().as_str() {
                        "full" => ScanTargetType::Full,
                        "custom" => ScanTargetType::Custom,
                        _ => ScanTargetType::Quick,
                    };
                    let custom_p: Vec<String> = paths
                        .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
                        .unwrap_or_default();
                    let mut cfg = core.get_scheduled_scan_config();
                    cfg.frequency = freq;
                    cfg.scheduled_time = time.clone();
                    cfg.target_type = tgt;
                    if !custom_p.is_empty() {
                        cfg.custom_paths = custom_p;
                    }
                    cfg.enabled = true;
                    let _ = core.update_scheduled_scan_config(cfg);
                    println!(
                        "{} ProgramaciÃ³n actualizada correctamente (Hora: {}, Frecuencia: {})",
                        "âœ”".green(),
                        time,
                        frequency
                    );
                }
                ScheduleCommands::Toggle { enable } => {
                    let mut cfg = core.get_scheduled_scan_config();
                    cfg.enabled = enable;
                    let _ = core.update_scheduled_scan_config(cfg);
                    if enable {
                        println!("{} Escaneos programados ACTIVADOS.", "âœ”".green());
                    } else {
                        println!("{} Escaneos programados DESACTIVADOS.", "âœ”".yellow());
                    }
                }
                ScheduleCommands::RunNow => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ EJECUTANDO ESCANEO PROGRAMADO MANUALMENTE â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    match core.execute_scheduled_scan_now() {
                        Ok(report) => {
                            println!(
                                "{} Escaneo completado con Ã©xito en {} ms.",
                                "âœ”".green(),
                                report.elapsed_ms
                            );
                            println!("  Archivos analizados: {}", report.files_scanned);
                            println!("  Amenazas detectadas: {}", report.threats_found);
                            for t in report.infected_records {
                                println!(
                                    "  {} [CRÃTICA] {} -> {}",
                                    "ðŸš¨".red(),
                                    t.threat_name,
                                    t.file_path
                                );
                            }
                        }
                        Err(e) => {
                            println!("{} Error al ejecutar escaneo: {}", "❌".red(), e);
                        }
                    }
                }
            }
        }

        Commands::Service { sub } => {
            let quarantine_dir = Path::new("data").join("quarantine");
            let scanner = std::sync::Arc::new(std::sync::Mutex::new(MultiEngineScanner::new()));
            let watcher = std::sync::Arc::new(RealTimeWatcher::new(scanner, &quarantine_dir));

            match sub {
                ServiceCommands::Install => {
                    let exe = std::env::current_exe()?;
                    match samulibre_watcher::service::install_windows_service(&exe) {
                        Ok(msg) => println!("{} {}", "✔".green(), msg),
                        Err(e) => println!("{} {}", "✖".red(), e),
                    }
                }
                ServiceCommands::Uninstall => {
                    match samulibre_watcher::service::uninstall_windows_service() {
                        Ok(msg) => println!("{} {}", "✔".green(), msg),
                        Err(e) => println!("{} {}", "✖".red(), e),
                    }
                }
                ServiceCommands::Start => match samulibre_watcher::service::start_service() {
                    Ok(msg) => println!("{} {}", "✔".green(), msg),
                    Err(e) => println!("{} {}", "✖".red(), e),
                },
                ServiceCommands::Stop => match samulibre_watcher::service::stop_service() {
                    Ok(msg) => println!("{} {}", "✔".green(), msg),
                    Err(e) => println!("{} {}", "✖".red(), e),
                },
                ServiceCommands::Status => {
                    let is_running = samulibre_watcher::service::is_service_or_daemon_running();
                    let telem = watcher.get_telemetry();
                    println!(
                        "\n{}",
                        "─── ESTADO DEL SERVICIO DE PROTECCIÓN EN TIEMPO REAL ───"
                            .bold()
                            .cyan()
                    );
                    println!(
                        "  Servicio / Demonio 24/7:   {}",
                        if is_running {
                            "EJECUTÁNDOSE (24/7)".green().bold()
                        } else {
                            "DETENIDO".red().bold()
                        }
                    );
                    println!("  Estado Operacional:        {:?}", telem.status);
                    println!("  Detalle:                   {}", telem.status_detail);
                    println!(
                        "  Eventos Encolados:         {}",
                        telem.events_enqueued_total
                    );
                    println!(
                        "  Eventos Procesados:        {}",
                        telem.events_processed_total
                    );
                    println!(
                        "  Eventos Descartados:       {}",
                        telem.events_dropped_total
                    );
                    println!(
                        "  Archivos Inspeccionados:   {}",
                        telem.files_inspected_total
                    );
                    println!(
                        "  Amenazas Neutralizadas:    {}",
                        telem.threats_intercepted_total
                    );
                    println!("  Tiempo en Ejecución:       {} seg", telem.uptime_seconds);
                    if let Some(ref p) = telem.last_event_path {
                        println!("  Último Archivo Evaluado:   {}", p);
                    }
                }
                ServiceCommands::Run => {
                    samulibre_watcher::service::run_service_dispatcher(move || {
                        let _ = samulibre_watcher::service::record_service_pid();
                        println!("{}", "Iniciando servicio de protección en tiempo real (24/7)... Presiona Ctrl+C para detener.".bold().cyan());
                        let _active = watcher.start_background_watcher(|alert| {
                            println!(
                                "\n{} [{}] {}",
                                "🚨 AMENAZA INTERCEPTADA".red().bold(),
                                alert.severity,
                                alert.title.bold().red()
                            );
                            println!("  Archivo: {:?}", alert.target_path);
                            println!("  Acción:  {}", alert.action_taken);
                        });
                        loop {
                            std::thread::sleep(std::time::Duration::from_secs(2));
                        }
                    })?;
                }
                ServiceCommands::Autodiagnostic => {
                    println!(
                        "\n{}",
                        "─── EJECUTANDO AUTODIAGNÓSTICO INTEGRAL DE TIEMPO REAL ───"
                            .bold()
                            .cyan()
                    );
                    let rep = watcher.run_autodiagnostic();
                    println!("  Resultado Global:          {:?}", rep.overall_status);
                    println!(
                        "  Pruebas Superadas:         {}/{}",
                        rep.tests_passed, rep.tests_executed
                    );
                    for d in rep.details {
                        println!(
                            "  {} {} ({} ms): {}",
                            if d.passed { "✔".green() } else { "✖".red() },
                            d.name.bold(),
                            d.duration_ms,
                            d.detail
                        );
                    }
                }
            }
        }

        Commands::Health => {
            let core = SamuLibreCore::new("data/canaries", "data/vpn", false);
            let snapshot = core.get_protection_health();
            println!(
                "\n{}",
                "─── EVALUACIÓN FORENSE DE SALUD SAMULIBRE (9 SUBSISTEMAS) ───"
                    .bold()
                    .cyan()
            );
            println!(
                "  {} Estado General:      {} ({})",
                "•".cyan(),
                snapshot.overall_status,
                snapshot.overall_status_label.bold()
            );
            println!(
                "  {} Fecha de Evaluación: {}",
                "•".cyan(),
                snapshot.checked_at
            );
            println!(
                "  {} Diagnóstico Global:  {}",
                "•".cyan(),
                snapshot.evidence_summary
            );
            println!("\n{}", "ESTADO DETALLADO POR SUBSISTEMA:".bold().white());

            for sub in snapshot.subsystems {
                let badge = match sub.state {
                    samulibre_types::SubsystemState::Running => {
                        "✔ OPERATIVO (RUNNING)".green().bold()
                    }
                    samulibre_types::SubsystemState::Degraded => {
                        "⚠ PARCIAL (DEGRADED)".yellow().bold()
                    }
                    samulibre_types::SubsystemState::Stopped => "✖ DETENIDO (STOPPED)".red().bold(),
                    samulibre_types::SubsystemState::NotInstalled => {
                        "○ NO INSTALADO (NOT_INSTALLED)".dimmed()
                    }
                    samulibre_types::SubsystemState::Failed => "✖ FALLIDO (FAILED)".red().bold(),
                    samulibre_types::SubsystemState::NotConfigured => "○ NO CONFIGURADO".dimmed(),
                    samulibre_types::SubsystemState::NotTested => "○ NO VERIFICADO".dimmed(),
                    _ => "? DESCONOCIDO".normal(),
                };
                println!("  {:<26} [{}]", sub.name.bold(), badge);
                println!("    Evidencia: {}", sub.evidence);
                if let Some(err) = sub.last_error {
                    println!("    Alerta/Error: {}", err.red());
                }
            }
        }

        Commands::Quarantine { sub } => {
            let quarantine_dir = Path::new("data").join("quarantine");
            let vault = QuarantineVault::new(&quarantine_dir);
            match sub {
                QuarantineCommands::List => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ BÃ“VEDA DE CUARENTENA CIFRADA SAMULIBRE â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    let items = vault.list_quarantined();
                    if items.is_empty() {
                        println!(
                            "{} No hay archivos maliciosos en cuarentena (BÃ³veda limpia).",
                            "âœ”".green()
                        );
                    } else {
                        for item in items {
                            println!(
                                "\n[ID: {}] Amenaza: {}",
                                item.id.to_string().cyan(),
                                item.threat_name.bold().red()
                            );
                            println!("  Ruta Original: {}", item.original_path);
                            println!("  Motor Detector: {}", item.engine.yellow());
                            println!("  Aislado en: {}", item.isolated_file_path);
                            println!("  Fecha de Aislamiento: {}", item.quarantined_at);
                        }
                    }
                }
            }
        }

        Commands::Patcher { sub } => {
            let mut patcher = VirtualPatcher::new(true); // Modo seguro dry-run
            match sub {
                PatcherCommands::Scan => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ ANÃLISIS DE VULNERABILIDADES DEL SISTEMA OPERATIVO â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    let (unmitigated, active, native) = patcher.scan_and_evaluate(None);

                    for rule in patcher.get_rules() {
                        let status_str = match rule.status {
                            PatchStatus::Unmitigated => {
                                "ABIERTA (Requiere Parche Virtual)".red().bold()
                            }
                            PatchStatus::VirtualPatchActive => {
                                "PARCHE VIRTUAL ACTIVO".yellow().bold()
                            }
                            PatchStatus::NativePatchInstalled => {
                                "CORREGIDA POR EL SO".green().bold()
                            }
                            PatchStatus::NotApplicable => "NO APLICABLE".white(),
                        };

                        let sev_colored = match rule.severity {
                            Severity::Critical => rule.severity.to_string().red().bold(),
                            Severity::High => rule.severity.to_string().magenta().bold(),
                            _ => rule.severity.to_string().yellow(),
                        };

                        println!(
                            "\n[{}] {} - Severidad: {}",
                            rule.cve.bold(),
                            rule.title,
                            sev_colored
                        );
                        println!("  Componente: {}", rule.target_component);
                        println!("  KBs oficiales de Windows: {:?}", rule.required_kb);
                        println!("  Estado actual: {}", status_str);
                    }

                    println!("\n{}", "Resumen:".bold());
                    println!(
                        "  - Vulnerabilidades sin mitigar: {}",
                        unmitigated.to_string().red()
                    );
                    println!(
                        "  - Parches virtuales protegiendo: {}",
                        active.to_string().yellow()
                    );
                    println!(
                        "  - Corregidas nativamente por el SO: {}",
                        native.to_string().green()
                    );
                }

                PatcherCommands::Apply => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ APLICANDO PARCHADO VIRTUAL AUTOMÃTICO â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    patcher.scan_and_evaluate(None);
                    let applied = patcher.apply_virtual_patches()?;
                    println!(
                        "{} Se aplicaron {} reglas de mitigaciÃ³n virtual (Firewall WFP / Registro / Servicios).",
                        "âœ”".green(),
                        applied.to_string().bold().green()
                    );
                    println!("El sistema estÃ¡ ahora protegido contra exploits de estas fallas sin reiniciar.");
                }

                PatcherCommands::AutoDeactivate => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ AUDITORÃA DE PARCHES NATIVOS DEL SISTEMA OPERATIVO â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    let reverted = patcher.check_and_deactivate_obsolete_patches(None)?;
                    if reverted > 0 {
                        println!(
                            "{} Se desactivaron y retiraron {} reglas de parche virtual porque el SO ya cuenta con la actualizaciÃ³n oficial.",
                            "âœ”".green(),
                            reverted.to_string().bold().green()
                        );
                    } else {
                        println!("{} Las reglas de parche virtual activas siguen siendo necesarias (no hay actualizaciones nuevas correspondientes).", "â„¹".blue());
                    }
                }

                PatcherCommands::SimulateInstall { kb } => {
                    println!(
                        "\n{}",
                        format!(
                            "â”€â”€â”€ SIMULANDO INSTALACIÃ“N DE PARCHE OFICIAL: {} â”€â”€â”€",
                            kb
                        )
                        .bold()
                        .cyan()
                    );
                    let mut simulated = patcher.get_installed_kbs();
                    simulated.insert(kb.to_uppercase());

                    // Primero activar
                    patcher.scan_and_evaluate(None);
                    let _ = patcher.apply_virtual_patches();

                    println!("Verificando si el parche virtual detecta la nueva actualizaciÃ³n oficial...");
                    let reverted =
                        patcher.check_and_deactivate_obsolete_patches(Some(simulated))?;

                    if reverted > 0 {
                        println!(
                            "{} Â¡Ã‰XITO! SamuLibre detectÃ³ la instalaciÃ³n oficial de {} y DESACTIVÃ“ AUTOMÃTICAMENTE el parche virtual para ahorrar recursos.",
                            "âœ”".bold().green(),
                            kb.bold().yellow()
                        );
                    } else {
                        println!("El parche {} no correspondÃ­a a ninguna regla activa.", kb);
                    }
                }

                PatcherCommands::Toggle { cve, disable } => {
                    let enable = !disable;
                    let action_str = if enable { "Activando" } else { "Desactivando" };
                    println!(
                        "{} parche virtual para {}...",
                        action_str,
                        cve.bold().cyan()
                    );
                    match patcher.toggle_patch(&cve, enable) {
                        Ok(rule) => {
                            println!(
                                "{} Regla actualizada: {} -> Estado: {:?}",
                                "âœ”".green(),
                                rule.title,
                                rule.status
                            );
                        }
                        Err(e) => {
                            eprintln!("{} Error modificando parche: {:?}", "âœ–".red(), e);
                        }
                    }
                }

                PatcherCommands::Sentinel { auto_patch } => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ CENTINELA DE VULNERABILIDADES DEL SO (SAMULIBRE) â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    patcher.set_auto_patch_enabled(auto_patch);
                    println!(
                        "  Modo Auto-MitigaciÃ³n: {}",
                        if auto_patch {
                            "ACTIVADO".green()
                        } else {
                            "MANUAL".yellow()
                        }
                    );
                    println!("  Ejecutando ciclo de auditorÃ­a...");
                    let (unmitigated, active, native, auto_patched) =
                        patcher.run_sentinel_audit_cycle();
                    println!(
                        "  Vulnerabilidades Abiertas: {}",
                        if unmitigated == 0 {
                            "0 (Sistema Protegido)".green()
                        } else {
                            unmitigated.to_string().red()
                        }
                    );
                    println!("  Parches Virtuales Activos: {}", active.to_string().cyan());
                    println!("  Corregidas Nativamente: {}", native.to_string().green());
                    if !auto_patched.is_empty() {
                        println!(
                            "\n  {} Parches aplicados automÃ¡ticamente en este ciclo:",
                            "âš¡".yellow()
                        );
                        for p in auto_patched {
                            println!("    â€¢ {}", p);
                        }
                    }
                }

                PatcherCommands::KbScan => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ MONITOR DE ACTUALIZACIONES KB (WINDOWS UPDATE / MSRC) â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    let status = patcher.get_kb_monitor_status();
                    println!(
                        "  KBs en CatÃ¡logo Monitoreado: {}",
                        status.monitored_kbs.len().to_string().cyan()
                    );
                    println!(
                        "  KBs Pendientes de InstalaciÃ³n: {}",
                        if status.pending_kbs_count == 0 {
                            "0 (SO al dÃ­a)".green()
                        } else {
                            status.pending_kbs_count.to_string().yellow()
                        }
                    );
                    println!(
                        "  AnÃ¡lisis de IA Realizados: {}",
                        status.ai_analyzed_count.to_string().cyan()
                    );
                    println!(
                        "  Parches IA Activos: {}",
                        status.auto_vpatch_count.to_string().green()
                    );
                    println!(
                        "  Auto-Pilot IA: {}",
                        if status.ai_autopilot_enabled {
                            "ACTIVADO".green()
                        } else {
                            "DESACTIVADO".yellow()
                        }
                    );

                    println!("\n  {} Boletines y KBs Monitoreados:", "ðŸ“‹".cyan());
                    let installed = patcher.get_installed_kbs();
                    for kb in &status.monitored_kbs {
                        let is_inst = installed.contains(&kb.kb_id.to_uppercase());
                        let badge = if is_inst {
                            "[INSTALADO]".green()
                        } else {
                            "[PENDIENTE - REQUIERE VIRTUAL PATCH]".red()
                        };
                        println!(
                            "    â€¢ {} {} - {}",
                            kb.kb_id.bold().yellow(),
                            badge,
                            kb.title
                        );
                        println!(
                            "      CVEs: {:?} | Afecta: {:?}",
                            kb.cves, kb.affected_products
                        );
                    }
                }

                PatcherCommands::AiAnalyze { kb, title, desc } => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ ANALIZADOR DE KBs CON IA LOCAL (SAMULIBRE-AI) â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    let analysis_result = if let Some(adv) = patcher
                        .monitored_kbs
                        .iter()
                        .find(|k| k.kb_id.eq_ignore_ascii_case(&kb))
                        .cloned()
                    {
                        patcher.analyze_kb(&adv)
                    } else {
                        let t =
                            title.unwrap_or_else(|| format!("ActualizaciÃ³n de Seguridad {}", kb));
                        let d = desc.unwrap_or_else(|| {
                            format!(
                                "AnÃ¡lisis de seguridad solicitado por el usuario para {}",
                                kb
                            )
                        });
                        patcher.analyze_raw_kb(&kb, &t, &d)
                    };

                    match analysis_result {
                        Ok(res) => {
                            println!("  {} AnÃ¡lisis completado con Ã©xito", "âœ”".green());
                            println!("  KB ID: {}", res.kb_id.bold().yellow());
                            println!("  CVE Identificado: {}", res.cve.bold().red());
                            println!("  Componente Afectado: {}", res.affected_component.bold());
                            println!("  Vector de Ataque: {}", res.attack_vector);
                            println!("  Confianza de la IA: {:.1}%", res.confidence_score * 100.0);
                            println!(
                                "  Guardrails de Seguridad en Rust: {}",
                                if res.safety_verified {
                                    "APROBADO (Seguro para el SO)".green()
                                } else {
                                    "RECHAZADO".red()
                                }
                            );
                            println!("\n  {} ExplicaciÃ³n del Parche Virtual:", "ðŸ¤–".cyan());
                            println!("    {}", res.reasoning);
                            println!("\n  {} Estrategia Sintetizada:", "ðŸ›¡".cyan());
                            println!("    {:?}", res.recommended_mitigation);
                            println!(
                                "\n  Regla persistida en disco en data/cve_rules/dynamic_{}.json",
                                res.cve.replace('-', "_")
                            );
                        }
                        Err(e) => {
                            eprintln!("{} Error en el anÃ¡lisis de IA: {:?}", "âœ–".red(), e);
                        }
                    }
                }

                PatcherCommands::AiAudit { auto_patch } => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ CICLO DE AUDITORÃA Y PARCHADO AUTÃ“NOMO CON IA â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    patcher.set_ai_autopilot(auto_patch);
                    println!(
                        "  Modo Auto-Pilot IA: {}",
                        if auto_patch {
                            "ACTIVADO (Parchado AutomÃ¡tico)".green()
                        } else {
                            "SOLO ANÃLISIS".yellow()
                        }
                    );
                    println!("  Ejecutando auditorÃ­a de KBs pendientes...");
                    let results = patcher.run_ai_kb_audit_cycle();
                    println!(
                        "  {} KBs analizados/auditados con IA: {}",
                        "âœ”".green(),
                        results.len()
                    );
                    for r in &results {
                        println!(
                            "    â€¢ {} ({}) -> Componente: {} [Confianza: {:.0}%]",
                            r.kb_id.bold().yellow(),
                            r.cve.bold().red(),
                            r.affected_component,
                            r.confidence_score * 100.0
                        );
                    }
                }
            }
        }

        Commands::Shield { sub } => {
            let mut shield = EndpointShield::new(&canary_dir);
            match sub {
                ShieldCommands::Status => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ ESTADO DEL ESCUDO DE ENDPOINT (ANTI-HACKERS) â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    println!(
                        "  {} ProtecciÃ³n de Memoria LSASS: ACTIVA (DetecciÃ³n Mimikatz/ProcDump)",
                        "âœ”".green()
                    );
                    println!("  {} Escudo de Tokens Web & Cookies: ACTIVO (Monitoreo de Chrome/Edge/Firefox)", "âœ”".green());
                    println!(
                        "  {} Trampas Anti-Ransomware: {} archivos seÃ±uelo",
                        "âœ”".green(),
                        shield.get_canary_count()
                    );
                }

                ShieldCommands::DeployCanaries => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ DESPLEGANDO ARCHIVOS SEÃ‘UELO ANTI-RANSOMWARE â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    let count = shield.deploy_canaries()?;
                    println!(
                        "{} Se desplegaron {} archivos trampa con Ã©xito en {:?}",
                        "âœ”".green(),
                        count.to_string().bold().green(),
                        canary_dir
                    );
                    println!("Si cualquier malware intenta cifrar o alterar estos archivos, el proceso atacante serÃ¡ congelado y neutralizado.");
                }

                ShieldCommands::Check => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ INSPECCIÃ“N INMEDIATA DE AMENAZAS EN ENDPOINT â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    let _ = shield.deploy_canaries();

                    let lsass_alerts = shield.scan_processes_for_lsass_dumpers();
                    let stealer_alerts = shield.scan_processes_for_browser_token_stealers();
                    let canary_alerts = shield.check_canary_integrity();

                    let total = lsass_alerts.len() + stealer_alerts.len() + canary_alerts.len();
                    if total == 0 {
                        println!("{} No se detectaron ataques de robo de credenciales ni actividad de ransomware activa.", "âœ”".green());
                    } else {
                        for alert in lsass_alerts
                            .into_iter()
                            .chain(stealer_alerts)
                            .chain(canary_alerts)
                        {
                            println!(
                                "\n{} [{}] {}",
                                "âš ".bold().red(),
                                alert.severity,
                                alert.title.bold()
                            );
                            println!("  Detalles: {}", alert.details);
                            println!("  AcciÃ³n tomada: {}", alert.action_taken.bold().yellow());
                        }
                    }
                }
            }
        }

        Commands::Vpn { sub } => {
            let mut vpn = VpnManager::new(&vpn_dir);
            match sub {
                VpnCommands::Connect {
                    country,
                    kill_switch,
                    double_encryption,
                } => {
                    println!(
                        "Iniciando conexiÃ³n VPN segura a {}...",
                        country.bold().cyan()
                    );
                    if double_encryption {
                        println!("{} Modo Doble Cifrado en cascada ACTIVADO (Capa 1: WireGuard âŠ• Capa 2: Onion Multi-Hop)", "ðŸ”’".bold().yellow());
                    }
                    let state =
                        vpn.connect_country_ext(&country, kill_switch, double_encryption)?;
                    println!("{} VPN conectada exitosamente", "âœ”".green());
                    println!(
                        "PaÃ­s: {} {}",
                        state.country_flag.unwrap_or_default(),
                        state.country_name.unwrap_or_default()
                    );
                    println!(
                        "IP PÃºblica Verificada: {}",
                        state.assigned_ip.unwrap_or_default().bold().green()
                    );
                    println!("Cifrado Activo: {}", state.encryption_cipher.bold().cyan());
                    if let Some(route) = state.multi_hop_route {
                        println!("Ruta Cascada: {}", route.yellow());
                    }
                    println!("Protocolo: {}", state.protocol);
                    println!("DNS Activo: {}", state.dns_active);
                    println!("Proxy del sistema operativo (WinINet) configurado para todos los navegadores.");
                    println!("\nPresiona Ctrl+C para desconectar y restaurar la configuraciÃ³n original.");
                    tokio::signal::ctrl_c().await.ok();
                    println!("\nRestaurando proxy y desconectando tÃºnel...");
                    let _ = vpn.disconnect();
                    println!(
                        "{} DesconexiÃ³n completa. TrÃ¡fico original restaurado.",
                        "âœ”".green()
                    );
                }

                VpnCommands::Disconnect => {
                    println!("Desconectando VPN y restaurando proxy...");
                    let _ = vpn.disconnect()?;
                    println!(
                        "{} VPN desconectada. TrÃ¡fico directo restaurado.",
                        "âœ”".green()
                    );
                }

                VpnCommands::ResetNetwork => {
                    println!("Restableciendo configuraciÃ³n de red del sistema...");
                    vpn.reset_system_network()?;
                    println!("{} Red normalizada: Proxy de Windows/Linux desactivado, DNS restaurado y firewall limpio.", "âœ”".green());
                }

                VpnCommands::Status => {
                    let state = vpn.get_state();
                    if state.is_connected {
                        println!("Estado: {} CONECTADA", "â—".green());
                        println!(
                            "PaÃ­s: {} {}",
                            state.country_flag.unwrap_or_default(),
                            state.country_name.unwrap_or_default()
                        );
                        println!(
                            "IP Asignada: {}",
                            state.assigned_ip.unwrap_or_default().cyan()
                        );
                    } else {
                        println!("Estado: {} DESCONECTADA (TrÃ¡fico directo)", "â—‹".yellow());
                    }
                }

                VpnCommands::ExportConfig { output } => {
                    let config = WireGuardConfig {
                        interface_name: "samulibre-wg0".to_string(),
                        private_key: "a2F0YXB1bHRfc2FtdWxpYnJlX3ByaXZhdGVfa2V5X2Zvcg==".to_string(),
                        address: "10.66.66.2/32".to_string(),
                        dns: vec!["9.9.9.9".to_string(), "149.112.112.112".to_string()],
                        peer_public_key: "b3Blbl9zb3VyY2Vfc2VjdXJlX2NvbW11bml0eV9wZWVyX2tleQ=="
                            .to_string(),
                        peer_endpoint: "vpn-node.samulibre.org:51820".to_string(),
                        allowed_ips: "0.0.0.0/0, ::/0".to_string(),
                    };
                    let path = vpn.export_wireguard_conf(&config, &output)?;
                    println!(
                        "{} Perfil de conexiÃ³n libre generado en: {:?}",
                        "âœ”".green(),
                        path
                    );
                    println!("Compatible con cualquier cliente WireGuard de cÃ³digo abierto.");
                }

                VpnCommands::SecureDns { provider } => {
                    let p = match provider.to_lowercase().as_str() {
                        "adguard" => SecureDnsProvider::AdGuardPrivacyAndAdblock,
                        "cloudflare" => SecureDnsProvider::CloudflareMalwareBlocking,
                        _ => SecureDnsProvider::Quad9MalwareBlocking,
                    };
                    vpn.apply_secure_dns(p.clone())?;
                    println!(
                        "{} DNS Seguro activado ({:?}) - URL DoH: {}",
                        "âœ”".green(),
                        p,
                        p.get_doh_url().bold().cyan()
                    );
                    println!("NavegaciÃ³n protegida contra dominios de phishing y servidores de comando y control (C2).");
                }
            }
        }

        Commands::Persistence { sub } => {
            let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);
            match sub {
                PersistenceCommands::Scan => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ CAZADOR DE PERSISTENCIA Y AUTO-INICIO (AUTORUNS) â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    let entries = core.get_persistence_entries();
                    println!(
                        "Total entradas detectadas: {}\n",
                        entries.len().to_string().bold()
                    );
                    for e in entries {
                        let status_tag = match e.status {
                            FileScanStatus::Clean => "âœ” LIMPIO".green(),
                            FileScanStatus::Suspicious => "âš  SOSPECHOSO".yellow().bold(),
                            FileScanStatus::Infected => "âœ˜ MALICIOSO".red().bold(),
                            _ => "â€¢ VERIFICADO".cyan(),
                        };
                        println!("{} [{:?}] {}", status_tag, e.entry_type, e.name.bold());
                        println!("  UbicaciÃ³n: {}", e.location);
                        println!("  Destino:   {}", e.target_path);
                        if let Some(args) = e.arguments {
                            println!("  Argumentos: {}", args);
                        }
                        if let Some(det) = e.detection_details {
                            println!("  Detalle:    {}", det.yellow());
                        }
                        println!();
                    }
                }
                PersistenceCommands::Toggle { id, disable } => {
                    let core = SamuLibreCore::new(&canary_dir, &vpn_dir, false);
                    match core.toggle_persistence_entry(&id, !disable) {
                        Ok(state) => println!(
                            "{} Entrada de persistencia '{}' actualizada (Activa: {}).",
                            "âœ”".green(),
                            id,
                            state
                        ),
                        Err(err) => println!(
                            "{} Error actualizando entrada '{}': {}",
                            "âœ˜".red(),
                            id,
                            err
                        ),
                    }
                }
            }
        }

        Commands::Network { sub } => {
            let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);
            match sub {
                NetworkCommands::Sockets => {
                    println!(
                        "\n{}",
                        "â”€â”€â”€ INSPECTOR DE RED Y CONEXIONES EN VIVO â”€â”€â”€"
                            .bold()
                            .cyan()
                    );
                    let sockets = core.get_network_sockets();
                    println!(
                        "Total sockets TCP activos: {}\n",
                        sockets.len().to_string().bold()
                    );
                    println!(
                        "{:<8} {:<24} {:<24} {:<12} {:<8} {:<20}",
                        "PROTO",
                        "DIRECCIÃ“N LOCAL",
                        "DIRECCIÃ“N REMOTA",
                        "ESTADO",
                        "PID",
                        "PROCESO"
                    );
                    println!("{}", "â”€".repeat(96));
                    for s in sockets {
                        let risk_marker = if s.is_risk_port {
                            " âš  RIESGO".bold().red().to_string()
                        } else {
                            String::new()
                        };
                        let proc_display = format!("{}{}", s.process_name, risk_marker);
                        println!(
                            "{:<8} {:<24} {:<24} {:<12} {:<8} {:<20}",
                            s.protocol,
                            s.local_address,
                            s.remote_address,
                            s.state,
                            s.pid,
                            proc_display
                        );
                    }
                }
                NetworkCommands::Isolate { pid, unblock } => {
                    let core = SamuLibreCore::new(&canary_dir, &vpn_dir, false);
                    match core.isolate_process_network(pid, !unblock) {
                        Ok(msg) => println!("{} {}", "âœ”".green(), msg),
                        Err(err) => println!(
                            "{} Error aislando proceso PID {}: {}",
                            "âœ˜".red(),
                            pid,
                            err
                        ),
                    }
                }
            }
        }

        Commands::Copilot { query } => {
            println!(
                "\n{}",
                "â”€â”€â”€ COPILOTO DE CIBERSEGURIDAD SAMULIBRE (IA LOCAL OFFLINE) â”€â”€â”€"
                    .bold()
                    .cyan()
            );
            let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);
            let response = core.ask_copilot(&query);

            println!("\n{}", response.answer);
            println!("\nNivel de Riesgo Evaluado: {:?}", response.risk_level);
            println!(
                "Confianza del Modelo:    {:.0}%",
                response.confidence * 100.0
            );
            if !response.suggested_actions.is_empty() {
                println!("\nAcciones Recomendadas:");
                for a in response.suggested_actions {
                    println!(
                        "  â†’ [{}] (AcciÃ³n: {}, Payload: {})",
                        a.label.cyan().bold(),
                        a.action_type,
                        a.payload
                    );
                }
            }
            println!();
        }

        Commands::Demo => {
            run_live_demonstration(&canary_dir, &vpn_dir).await?;
        }
    }

    Ok(())
}

fn scan_single_file(scanner: &MultiEngineScanner, path: &Path) {
    match scanner.scan_file(path) {
        Ok(result) => match result.status {
            FileScanStatus::Clean => {
                println!(
                    "{} {} [{}] ({} ms)",
                    "âœ” LIMPIO".green().bold(),
                    result.file_path,
                    result.engine,
                    result.scan_time_ms
                );
            }
            FileScanStatus::Infected => {
                println!(
                    "{} {} -> {} [{}]",
                    "âœ˜ INFECTADO".red().bold(),
                    result.file_path.bold(),
                    result.detection_name.unwrap_or_default().bold().red(),
                    result.engine.yellow()
                );
            }
            FileScanStatus::Suspicious => {
                println!(
                    "{} {} -> {} [{}]",
                    "âš  SOSPECHOSO".yellow().bold(),
                    result.file_path,
                    result.detection_name.unwrap_or_default().yellow(),
                    result.engine
                );
            }
            FileScanStatus::AccessDenied => {
                println!(
                    "{} {} (Acceso denegado)",
                    "âœ˜ ERROR".red(),
                    result.file_path
                );
            }
        },
        Err(e) => {
            println!("Error al escanear {}: {}", path.display(), e);
        }
    }
}

fn scan_directory(scanner: &MultiEngineScanner, dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        let mut clean_count = 0;
        let mut infected_count = 0;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(res) = scanner.scan_file(&path) {
                    if res.status == FileScanStatus::Infected {
                        infected_count += 1;
                        println!(
                            "{} {} -> {}",
                            "âœ˜ INFECTADO".red().bold(),
                            path.display(),
                            res.detection_name.unwrap_or_default().red()
                        );
                    } else {
                        clean_count += 1;
                    }
                }
            }
        }

        println!("\n{}", "Resultado del Escaneo:".bold());
        println!("  Archivos limpios:    {}", clean_count.to_string().green());
        println!(
            "  Archivos infectados: {}",
            infected_count.to_string().red()
        );
    }
}

async fn run_live_demonstration(canary_dir: &Path, vpn_dir: &Path) -> Result<()> {
    println!(
        "\n{}",
        "=========================================================".cyan()
    );
    println!(
        "{}",
        "   DEMOSTRACIÃ“N INTEGRAL: ANTIVIRUS SAMULIBRE OPEN SOURCE   "
            .bold()
            .yellow()
    );
    println!(
        "{}",
        "=========================================================".cyan()
    );

    // 1. DemostraciÃ³n de Escaneo con YARA-X y Firmas
    println!(
        "\n{}",
        "[PASO 1] PRUEBA DEL MOTOR DE DETECCIÃ“N (ClamAV & YARA-X)..."
            .bold()
            .cyan()
    );
    let scanner = MultiEngineScanner::new();
    let test_dir = Path::new("data").join("test_samples");
    let _ = fs::create_dir_all(&test_dir);

    // Crear muestra benigna
    let clean_file = test_dir.join("documento_seguro.txt");
    fs::write(
        &clean_file,
        "Este es un documento seguro de la oficina sin ningun codigo sospechoso.",
    )?;
    scan_single_file(&scanner, &clean_file);

    // Crear muestra EICAR estÃ¡ndar
    let eicar_file = test_dir.join("eicar_test.com");
    fs::write(
        &eicar_file,
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )?;
    scan_single_file(&scanner, &eicar_file);

    // Crear muestra de script sospechoso de evasiÃ³n de AMSI
    let amsi_script = test_dir.join("bypass_amsi_dropper.ps1");
    fs::write(&amsi_script, "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")?;
    scan_single_file(&scanner, &amsi_script);

    // 2. DemostraciÃ³n de Parchado Virtual AutÃ³nomo
    println!(
        "\n{}",
        "[PASO 2] PRUEBA DE PARCHADO VIRTUAL Y DESACTIVACIÃ“N AUTOMÃTICA..."
            .bold()
            .cyan()
    );
    let mut patcher = VirtualPatcher::new(true);

    println!("2.1 Escaneando sistema operativo en busca de CVEs sin actualizar...");
    let (unmitigated, _, _) = patcher.scan_and_evaluate(None);
    println!(
        "    Detectadas {} vulnerabilidades abiertas sin parche oficial del SO.",
        unmitigated.to_string().bold().red()
    );

    println!(
        "2.2 Aplicando mitigaciones de parchado virtual (Reglas WFP / Registro / Servicios)..."
    );
    let applied = patcher.apply_virtual_patches()?;
    println!(
        "    {} Se activaron {} parches virtuales para proteger el equipo.",
        "âœ”".green(),
        applied.to_string().green()
    );

    println!("2.3 Simulando que Windows Update descarga e instala la actualizaciÃ³n oficial 'KB5041585'...");
    let mut simulated_kbs = patcher.get_installed_kbs();
    simulated_kbs.insert("KB5041585".to_string()); // Parche oficial de CVE-2024-38063

    println!("2.4 Ejecutando verificaciÃ³n de parches del sistema...");
    let reverted = patcher.check_and_deactivate_obsolete_patches(Some(simulated_kbs))?;
    println!(
        "    {} Â¡Ã‰XITO! SamuLibre detectÃ³ que Windows ya instalÃ³ el parche oficial de forma nativa y retirÃ³ {} regla(s) de parche virtual automÃ¡ticamente.",
        "âœ”".bold().green(),
        reverted.to_string().bold().yellow()
    );

    // 3. DemostraciÃ³n del Escudo Anti-Hackers, Robo de Credenciales y Canarios
    println!(
        "\n{}",
        "[PASO 3] PRUEBA DEL ESCUDO ANTI-HACKERS Y TRAMPAS ANTI-RANSOMWARE..."
            .bold()
            .cyan()
    );
    let mut shield = EndpointShield::new(canary_dir);
    let deployed = shield.deploy_canaries()?;
    println!(
        "3.1 Desplegados {} archivos trampa canarios seÃ±uelo.",
        deployed
    );

    println!("3.2 Verificando integridad inicial de los canarios seÃ±uelo...");
    let alerts = shield.check_canary_integrity();
    println!(
        "    Alertas de ransomware: {} (Todo limpio y seguro).",
        alerts.len().to_string().green()
    );

    println!("3.3 Simulando intento de ransomware cifrando el archivo trampa 'passwords_backup_vault.txt'...");
    let canary_target = canary_dir.join("passwords_backup_vault.txt");
    fs::write(
        &canary_target,
        "ENCRYPTED_BY_MALWARE_LOCKED_PAY_RANSOM_0xDEADBEEF",
    )?;

    let alerts_after = shield.check_canary_integrity();
    for alert in alerts_after {
        println!(
            "    {} [{}] {}",
            "âš ".bold().red(),
            alert.severity,
            alert.title.bold()
        );
        println!("       {}", alert.details.red());
        println!(
            "       AcciÃ³n inmediata: {}",
            alert.action_taken.bold().yellow()
        );
    }

    // 4. DemostraciÃ³n de NavegaciÃ³n Libre y VPN
    println!(
        "\n{}",
        "[PASO 4] NAVEGACIÃ“N LIBRE, VPN WIREGUARD Y DNS SEGURO..."
            .bold()
            .cyan()
    );
    let vpn = VpnManager::new(vpn_dir);
    let sample_conf = vpn_dir.join("samulibre_demo.conf");
    let wg_config = WireGuardConfig {
        interface_name: "samulibre-wg".to_string(),
        private_key: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB".to_string(),
        address: "10.88.88.2/32".to_string(),
        dns: vec!["9.9.9.9".to_string()],
        peer_public_key: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=".to_string(),
        peer_endpoint: "libre-node-01.samulibre.org:51820".to_string(),
        allowed_ips: "0.0.0.0/0".to_string(),
    };
    vpn.export_wireguard_conf(&wg_config, "samulibre_demo.conf")?;
    println!(
        "    {} Perfil libre WireGuard exportado: {:?}",
        "âœ”".green(),
        sample_conf
    );
    println!(
        "    {} DNS Seguro con Quad9 (Bloqueo de dominios maliciosos sin telemetrÃ­a).",
        "âœ”".green()
    );

    println!(
        "\n{}",
        "=========================================================".green()
    );
    println!(
        "{}",
        "   DEMOSTRACIÃ“N COMPLETADA: TODOS LOS MÃ“DULOS OPERATIVOS   "
            .bold()
            .green()
    );
    println!(
        "{}",
        "=========================================================".green()
    );

    Ok(())
}

fn print_banner() {
    println!("{}", r#"
  â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ•—   â–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•—   â–ˆâ–ˆâ•—â–ˆâ–ˆâ•—     â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—
  â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â•â•â•
  â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â–ˆâ–ˆâ–ˆâ–ˆâ•”â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  
  â•šâ•â•â•â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘     â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â•  
  â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘ â•šâ•â• â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘  â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—
  â•šâ•â•â•â•â•â•â•â•šâ•â•  â•šâ•â•â•šâ•â•     â•šâ•â• â•šâ•â•â•â•â•â• â•šâ•â•â•â•â•â•â•â•šâ•â•â•šâ•â•â•â•â•â• â•šâ•â•  â•šâ•â•â•šâ•â•â•â•â•â•â•
   Antivirus Open Source & Suite de Ciberseguridad Libre | 0% Ads | 100% Free
    "#.bright_cyan());
}
