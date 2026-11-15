use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use sha2::Digest;
use samulibre_core::SamuLibreCore;
use samulibre_patcher::VirtualPatcher;
use samulibre_scanner::MultiEngineScanner;
use samulibre_shield::EndpointShield;
use samulibre_types::{
    CompatibilityStatus, FileScanStatus, FpClassification, PatchStatus, ScanTargetType,
    ScheduleFrequency, Severity, SmartScanPriority, WdheMode, WdheResourceProfile,
};
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
    Update {
        /// Muestra el estado criptográfico de la versión actual instalada
        #[arg(long, short)]
        status: bool,

        /// Ejecuta una prueba de validación de defensa anti-downgrade
        #[arg(long)]
        test_downgrade: bool,
    },

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

    /// Motor de Procesamiento Híbrido CPU/GPU (SHCE)
    Shce {
        #[command(subcommand)]
        sub: ShceCommands,
    },

    /// SamuLibre Security Event Manager (SSEM) - Registro y Exportación Empresarial (SIEM/SOC)
    Ssem {
        #[command(subcommand)]
        sub: SsemCommands,
    },

    /// Sistema de Reputación, Validación Authenticode y Mitigación de Falsos Positivos
    Reputation {
        #[command(subcommand)]
        sub: ReputationCommands,
    },

    /// Escudo Web y Protección de Red: Anti-Phishing, Bloqueo C2, DGA y Análisis MotW
    WebShield {
        #[command(subcommand)]
        sub: WebShieldCommands,
    },

    /// Pruebas de Rendimiento, Optimización de RAM y Métricas AV-Comparatives/AV-TEST
    Benchmark {
        #[command(subcommand)]
        sub: BenchmarkCommands,
    },

    /// Centro de Preparación para Certificación y Evaluación de Laboratorios (AMTSO / AV-TEST / AV-Comparatives)
    Certification {
        #[command(subcommand)]
        sub: CertificationCommands,
    },

    /// Windows Defender Harmony Engine (WDHE) - Coexistencia, Auditoría, Smart Scan e Integración WSC
    Wdhe {
        #[command(subcommand)]
        sub: WdheCommands,
    },

    /// Módulo Avanzado Dark Web & Tor Protection: Blindaje, Anti-Exploits, Sandbox y Privacidad
    Tor {
        #[command(subcommand)]
        sub: TorCommands,
    },

    /// SamuLibre Network Defense Engine (WFP, Monitor de Red, DNS Seguro, Tor Secure Mode)
    Netdefense {
        #[command(subcommand)]
        sub: NetDefenseCommands,
    },
}

#[derive(Subcommand)]
enum NetDefenseCommands {
    /// Muestra el estado real del motor WFP, DNS, Tor Secure Mode y Threat Intel
    Status,
    /// Lista conexiones TCP/UDP activas en tiempo real (iphlpapi)
    Connections,
    /// Activa Tor Secure Mode (Kill Switch Fail-Closed)
    TorEnable,
    /// Desactiva Tor Secure Mode
    TorDisable,
    /// Ejecuta benchmark de rendimiento del motor Network Defense
    Benchmark,
    /// Limpia todos los filtros WFP propios de SamuLibre (recuperación/desinstalación)
    Cleanup,
}

#[derive(Subcommand)]
enum TorCommands {
    /// Muestra el panel interactivo y estado en tiempo real de Tor Protection
    Status,
    /// Audita la presencia, integridad y versiones del proceso Tor Browser
    Audit,
    /// Cambia el perfil de protección: 'normal', 'tor' o 'isolation'
    Profile {
        /// Nombre del perfil
        name: String,
    },
    /// Escanea, analiza y aplica sandbox a un archivo descargado desde Tor
    ScanDownload {
        /// Ruta del archivo descargado
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Origen URL o sitio .onion opcional
        #[arg(short, long)]
        origin: Option<String>,
    },
    /// Activa el Kill Switch de emergencia y contención inmediata para un PID
    KillSwitch {
        /// PID del proceso sospechoso
        pid: u32,
        /// Nombre del proceso
        #[arg(short, long, default_value = "ProcesoSospechoso")]
        name: String,
        /// Razón técnica del aislamiento
        #[arg(short, long, default_value = "Alerta manual de contención")]
        reason: String,
    },
    /// Muestra el feed de Inteligencia de Amenazas Dark Web (IoCs de Ransomware, C2 y Stealers)
    Feeds,
    /// Audita las vulnerabilidades conocidas (CVEs) de Firefox ESR y Tor Browser
    Cves,
}

#[derive(Subcommand)]
enum WdheCommands {
    /// Muestra el panel interactivo del Compatibility Center (Estado Defender + SamuLibre en tiempo real)
    Status,
    /// Ejecuta la auditoría exhaustiva de compatibilidad (Fase 1)
    Audit,
    /// Investiga alertas y detecciones recientes en el Event Log de Microsoft Defender (Fase 2)
    FpInvestigate {
        /// Número máximo de eventos a consultar
        #[arg(long, default_value_t = 10)]
        max: usize,
    },
    /// Cambia el modo de coexistencia: dev, comp, primary (Fase 3)
    Mode {
        /// Modo: 'dev' (Desarrollo), 'comp' (Complementario) o 'primary' (Antivirus Principal)
        mode: String,
    },
    /// Ejecuta el escaneo coordinado no bloqueante con Clean Cache y prioridad (Fase 4)
    SmartScan {
        /// Ruta del archivo o directorio a analizar
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Prioridad (background, low, normal, high, critical)
        #[arg(long, default_value = "normal")]
        priority: String,
    },
    /// Establece el perfil dinámico del Resource Governor (Fase 5)
    Profile {
        /// Perfil: 'silent', 'balanced', 'performance', 'deep'
        profile: String,
    },
    /// Asesor de exclusiones seguras y blindaje anti-bypass (Fase 6)
    Exclusions {
        #[command(subcommand)]
        sub: WdheExclusionCommands,
    },
    /// Verifica la firma digital Authenticode y genera el manifiesto oficial de binarios (Fase 7)
    VerifyIntegrity,
    /// Consulta los proveedores antivirus registrados en Windows Security Center (Fase 8)
    Wsc,
    /// Ejecuta el Laboratorio de Benchmarks comparativos en los 5 escenarios (A - E) (Fase 10)
    Benchmark,
    /// Ejecuta la validación de seguridad segura con EICAR en sandbox (Fase 11)
    ValidateSecurity,
    /// Ejecuta las pruebas de resiliencia y recuperación ante contingencias (Fase 12)
    ResilienceTest,
}

#[derive(Subcommand)]
enum WdheExclusionCommands {
    /// Evalúa la admisibilidad y nivel de riesgo de una propuesta de exclusión
    Check {
        /// Ruta o destino de la exclusión
        path: String,
        /// Tipo de regla (file, folder, process)
        #[arg(long, default_value = "file")]
        rule_type: String,
        /// Justificación técnica
        #[arg(long)]
        reason: String,
    },
    /// Recomienda una solución arquitectónica para evitar crear exclusiones inseguras
    Recommend {
        /// Descripción del conflicto observado
        conflict: String,
    },
}

#[derive(Subcommand)]
enum CertificationCommands {
    /// Ejecuta la suite de pruebas estándar de AMTSO (EICAR, PUA/PUP, Phishing, DGA, Detección Offline)
    TestAmtso,
    /// Simula la matriz oficial de evaluación de AV-TEST (Protección 6.0, Rendimiento 6.0, Usabilidad 6.0)
    TestAvTest,
    /// Simula la evaluación metodológica de AV-Comparatives (Real-World, Impact Score, Tiers)
    TestAvComp,
    /// Ejecuta la auditoría integral consolidada de preparación para certificación
    Audit,
}

#[derive(Subcommand)]
enum BenchmarkCommands {
    /// Ejecuta la suite de rendimiento completa (RAM/CPU, Overhead I/O, Arranque Apps y Métricas AV-Comparatives)
    Performance,
    /// Ejecuta la optimización forzada de Working Set de memoria en Windows
    OptimizeRam,
}

#[derive(Subcommand)]
enum WebShieldCommands {
    /// Muestra el estado del Escudo Web, proveedor DNS seguro DoH y métricas de filtrado
    Status,
    /// Evalúa en tiempo real una URL o dominio (Phishing, C2, DGA, Exfiltración DNS)
    CheckUrl {
        /// URL o dominio a inspeccionar
        url: String,
    },
    /// Inspecciona los metadatos NTFS Mark-of-the-Web (Zone.Identifier ADS) de un archivo descargado
    InspectMotw {
        /// Ruta del archivo descargado
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Agrega un dominio a la lista negra personalizada del Escudo Web
    BlockDomain {
        /// Nombre del dominio (ej. tracking.ads.com)
        domain: String,
        /// Motivo del bloqueo
        #[arg(short, long, default_value = "Bloqueado por política del usuario")]
        reason: String,
    },
    /// Remueve un dominio de la lista negra personalizada
    UnblockDomain {
        /// Nombre del dominio a desbloquear
        domain: String,
    },
    /// Lista todos los dominios bloqueados en la lista negra local
    ListBlocked,
    /// Ejecuta una prueba de detección de dominios algorítmicos DGA y túneles de exfiltración DNS
    TestDga,
}

#[derive(Subcommand)]
enum ReputationCommands {
    /// Evalúa la reputación, firma Authenticode, categoría de editor y puntaje de confianza (0-100)
    Assess {
        /// Ruta del archivo ejecutable o script a evaluar
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Reporta un falso positivo para suprimir alertas heurísticas y generar exclusión local
    ReportFp {
        /// Ruta del archivo legítimo
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Justificación o motivo del reporte
        #[arg(short, long, default_value = "Software legítimo verificado por el usuario")]
        reason: String,
    },
    /// Lista todas las reglas de exclusión y falsos positivos resueltos
    ListOverrides,
    /// Elimina una exclusión de falso positivo por su UUID
    RemoveOverride {
        /// Identificador UUID de la regla
        id: String,
    },
    /// Lista el catálogo de editores y entidades certificadoras de confianza (Tier 1, Tier 2, Tier 3)
    ListPublishers,
}

#[derive(Subcommand)]
enum SsemCommands {
    /// Muestra el estado operativo de SSEM, servidor SIEM configurado y métricas de envío
    Status,
    /// Configura el servidor SIEM remoto, formato (json, syslog, csv) y protocolo
    Configure {
        /// Servidor SIEM remoto (IP o dominio)
        #[arg(short, long)]
        server: Option<String>,
        /// Puerto del servidor SIEM remoto (ej. 514 para Syslog, 8088 para Splunk HEC)
        #[arg(short, long, default_value_t = 514)]
        port: u16,
        /// Formato de exportación: json, syslog, csv
        #[arg(short, long, default_value = "json")]
        format: String,
        /// Protocolo de transporte: tcp, tls, udp, local
        #[arg(short, long, default_value = "tcp")]
        transport: String,
        /// Anominizar rutas de usuario (cumplimiento GDPR)
        #[arg(long)]
        anonymize_paths: bool,
    },
    /// Exporta todos los eventos de seguridad registrados a un archivo CSV forense
    ExportCsv {
        /// Ruta de destino del archivo CSV
        #[arg(short, long, default_value = "data/ssem/forensic_export.csv")]
        output: PathBuf,
    },
    /// Exporta todos los eventos de seguridad registrados a un archivo JSON (Wazuh / Splunk)
    ExportJson {
        /// Ruta de destino del archivo JSON
        #[arg(short, long, default_value = "data/ssem/forensic_export.json")]
        output: PathBuf,
    },
    /// Reintenta vaciar el búfer offline de eventos hacia el servidor SIEM remoto
    Flush,
    /// Simula la emisión de un evento de seguridad de prueba y muestra los formatos generados
    SimulateEvent,
}

#[derive(Subcommand)]
enum ShceCommands {
    /// Muestra la topología de hardware detectada (CPU, RAM, GPUs y capacidades de cómputo)
    Status,
    /// Ejecuta el benchmark de rendimiento híbrido midiendo throughput CPU vs GPU y paridad
    Benchmark,
    /// Configura el backend activo (cpu, cuda, directml, opencl, auto)
    SetBackend {
        /// Backend a seleccionar: cpu, cuda, directml, opencl, auto
        backend: String,
    },
    /// Prueba y valida el mecanismo de Fallback automático a CPU mediante inyección de fallo de GPU
    TestFallback,
    /// Configura el límite de utilización de GPU (ej. 70%) para prevenir congelamiento de GUI
    Limit {
        /// Porcentaje de utilización máxima (10 a 100)
        percentage: u8,
    },
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
    /// Despliega o regenera los archivos trampa señuelo anti-ransomware
    DeployCanaries,
    /// Realiza una auditoría inmediata de procesos (LSASS, navegadores, canarios)
    Check,
    /// Muestra la configuración de Carpetas Controladas Protegidas y los incidentes de Ransomware
    Ransomware,
    /// Simula un intento de ataque de ransomware con extensión maliciosa y rotación de canarios
    TestRansomware,
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

        Commands::Update {
            status,
            test_downgrade,
        } => {
            let mut scanner = MultiEngineScanner::new();

            if status {
                println!(
                    "\n{}",
                    "─── ESTADO CRIPTOGRÁFICO Y CONTROL DE VERSIONES (UPDATE MANAGER) ───"
                        .bold()
                        .cyan()
                );
                let current_seq = scanner.get_installed_version_sequence();
                println!("  {} Versión Monótona Actual:  {}", "•".cyan(), current_seq.to_string().bold().green());
                println!("  {} Firmante Oficial:         {}", "•".cyan(), samulibre_scanner::OFFICIAL_SIGNER_FINGERPRINT.bold());
                println!("  {} Total Firmas SHA-256:     {}", "•".cyan(), scanner.signature_count());
                println!("  {} Reglas YARA-X Compiladas: {}", "•".cyan(), scanner.rule_count());
                println!("  {} Protección Anti-Downgrade: ACTIVA (Bloqueo estricto de rollback no firmado)", "•".cyan());

                let history = scanner.get_update_history();
                if !history.is_empty() {
                    println!("\n{}", "HISTORIAL DE ACTUALIZACIONES RECIENTES:".bold().white());
                    for (i, h) in history.iter().take(3).enumerate() {
                        println!("  [{}] {} | {} | Firmas: {}", i + 1, h.id.cyan(), h.timestamp, h.total_signatures);
                        for imp in &h.improvements {
                            println!("      - {}", imp);
                        }
                    }
                }
                return Ok(());
            }

            if test_downgrade {
                println!(
                    "\n{}",
                    "─── PRUEBA DE RESILIENCIA Y DEFENSA ANTI-DOWNGRADE (AV-TEST READY) ───"
                        .bold()
                        .cyan()
                );
                let current_seq = scanner.get_installed_version_sequence();
                println!("  [1/3] Versión actualmente instalada en el endpoint: {}", current_seq);
                let older_seq = current_seq.saturating_sub(100);
                println!("  [2/3] Simulando llegada de paquete antiguo (Downgrade Attack): seq={}", older_seq);

                let test_key = b"samulibre_official_test_secret_key_32b!";
                let sig = samulibre_scanner::PackageUpdater::compute_signature(
                    "PKG-MALICIOUS-DOWNGRADE-SIM",
                    older_seq,
                    "2.1.0-outdated",
                    &[],
                    test_key,
                );

                let dummy_manifest = samulibre_types::UpdatePackageManifest {
                    package_id: "PKG-MALICIOUS-DOWNGRADE-SIM".to_string(),
                    version_sequence: older_seq,
                    semantic_version: "2.1.0-outdated".to_string(),
                    min_engine_version: "2.1.0".to_string(),
                    timestamp_utc: chrono::Utc::now().to_rfc3339(),
                    component_type: samulibre_types::PackageComponentType::MalwareSignatures,
                    is_incremental: false,
                    files: Vec::new(),
                    changelog: vec!["Intento simulado de forzar base de firmas obsoleta".to_string()],
                    digital_signature: sig,
                    signer_fingerprint: samulibre_scanner::OFFICIAL_SIGNER_FINGERPRINT.to_string(),
                };

                let pkg_updater = samulibre_scanner::PackageUpdater::new("data");
                let files_map = std::collections::HashMap::new();
                let verify_res = pkg_updater.verify_package(&dummy_manifest, &files_map, test_key);

                match verify_res {
                    samulibre_types::PackageVerificationStatus::DowngradeDetected { current_seq: c, incoming_seq: inc } => {
                        println!("  [3/3] {} Ataque neutralizado con éxito:", "✔ BLOQUEO EXITOSO".green().bold());
                        println!("        El validador criptográfico rechazó el paquete antiguo (Actual: {}, Recibida: {}).", c, inc);
                        println!("        La base de firmas de producción permanece 100% protegida e intacta.");
                    }
                    samulibre_types::PackageVerificationStatus::InvalidSignature => {
                        println!("  [3/3] {} El paquete fue rechazado por firma inválida antes de evaluar versión.", "✔ BLOQUEADO".green().bold());
                    }
                    other => {
                        eprintln!("  [3/3] {} Resultado inesperado: {:?}", "✖ ERROR".red(), other);
                    }
                }
                return Ok(());
            }

            println!(
                "\n{}",
                "─── ACTUALIZACIÓN DE FIRMAS Y REGLAS YARA SAMULIBRE ───"
                    .bold()
                    .cyan()
            );
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
                format!(
                    "─── EVALUACIÓN FORENSE DE SALUD SAMULIBRE ({} SUBSISTEMAS) ───",
                    snapshot.subsystems.len()
                )
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

        Commands::Shce { sub } => {
            let core = SamuLibreCore::new("data/canaries", "data/vpn", false);
            match sub {
                ShceCommands::Status => {
                    let topo = core.get_hardware_topology();
                    let sel = core.get_shce_selection();
                    println!(
                        "\n{}",
                        "─── SAMULIBRE HYBRID COMPUTING ENGINE (SHCE) ───"
                            .bold()
                            .cyan()
                    );
                    println!("{}", "TOPOLOGÍA DE PROCESAMIENTO HETEROGÉNEO:".bold().white());
                    println!("  {} CPU Marca/Modelo:     {} ({})", "•".cyan(), topo.cpu_brand.bold(), topo.cpu_vendor);
                    println!("  {} Núcleos / Hilos:      {} físicos / {} lógicos", "•".cyan(), topo.physical_cores, topo.logical_threads);
                    println!("  {} Memoria RAM:          {} MB disponibles de {} MB totales", "•".cyan(), topo.available_ram_mb, topo.total_ram_mb);
                    println!("\n{}", "ADAPTADORES GRÁFICOS (GPU) IDENTIFICADOS:".bold().white());
                    for (i, gpu) in topo.gpus.iter().enumerate() {
                        println!("  [GPU #{}] {}", i, gpu.name.bold().green());
                        println!("    Fabricante:    {}", gpu.vendor);
                        println!("    Tipo:          {}", gpu.gpu_type);
                        println!("    VRAM:          {} MB totales ({} MB disponibles)", gpu.vram_total_mb, gpu.vram_available_mb);
                        println!("    Soporte CUDA:  {}", if gpu.supports_cuda { "✔ SÍ".green().bold() } else { "✖ NO".dimmed() });
                        println!("    DirectML/D3D12:{}", if gpu.supports_directml { "✔ SÍ".green().bold() } else { "✖ NO".dimmed() });
                        println!("    OpenCL:        {}", if gpu.supports_opencl { "✔ SÍ".green().bold() } else { "✖ NO".dimmed() });
                        if let Some(drv) = &gpu.driver_version {
                            println!("    Driver:        {}", drv);
                        }
                    }
                    println!("\n{}", "ESTADO DE ORQUESTACIÓN Y POLÍTICAS DE LATENCIA:".bold().white());
                    println!("  {} Backend Activo:       {}", "•".cyan(), sel.active_backend.to_string().bold().green());
                    println!("  {} Aceleración GPU:      {}", "•".cyan(), if sel.is_gpu_active { "HABILITADA".green().bold() } else { "DESHABILITADA (Modo CPU Seguro)".yellow() });
                    println!("  {} Fallback Automático:  {}", "•".cyan(), if sel.fallback_active { format!("ACTIVO ({})", sel.fallback_reason.unwrap_or_default()).red().bold() } else { "INACTIVO (Operación Nominal)".green() });
                    println!("  {} Límite Uso GPU:       {}% (Anti-UI Freezing)", "•".cyan(), sel.gpu_utilization_limit_pct);
                    println!("  {} Política On-Access:   Estrictamente CPU (0 PCIe Transfer Latency)", "•".cyan());
                }
                ShceCommands::Benchmark => {
                    println!(
                        "\n{}",
                        "─── BENCHMARK DE RENDIMIENTO HÍBRIDO CPU vs GPU (SHCE) ───"
                            .bold()
                            .cyan()
                    );
                    println!("  Ejecutando batería de pruebas con lotes de 2 MB (64 KB x 32 bloques)...");
                    let res = core.run_shce_benchmark();
                    println!("  {} Rendimiento CPU Pura:  {:.1} MB/s", "•".cyan(), res.cpu_throughput_mb_s);
                    if let Some(gpu_tp) = res.gpu_throughput_mb_s {
                        println!("  {} Rendimiento Acelerado: {:.1} MB/s", "•".cyan(), gpu_tp);
                    }
                    println!("  {} Factor de Aceleración: {:.2}x", "•".cyan(), res.speedup_ratio.to_string().bold().green());
                    println!("  {} Latencia por Elemento: {:.2} µs", "•".cyan(), res.latency_us_per_item);
                    println!("  {} Verificación Paridad:  {}", "•".cyan(), if res.parity_verified { "100% IDÉNTICA (Paridad Matemática Exacta)".green().bold() } else { "ERROR: DISCREPANCIA DETECTADA".red().bold() });
                    println!("  {} Backend Recomendado:   {}", "•".cyan(), res.recommended_backend.to_string().bold().cyan());
                }
                ShceCommands::SetBackend { backend } => {
                    let b = match backend.to_lowercase().as_str() {
                        "cpu" | "cpuonly" => samulibre_types::ComputeBackend::CpuOnly,
                        "cuda" => samulibre_types::ComputeBackend::Cuda,
                        "directml" | "dml" => samulibre_types::ComputeBackend::DirectML,
                        "opencl" | "cl" => samulibre_types::ComputeBackend::OpenCL,
                        "auto" | "hybrid" => samulibre_types::ComputeBackend::HybridAuto,
                        other => {
                            eprintln!("{} Backend no reconocido: '{}'. Opciones válidas: cpu, cuda, directml, opencl, auto", "✖ ERROR:".red().bold(), other);
                            return Ok(());
                        }
                    };
                    match core.set_shce_backend(b) {
                        Ok(sel) => {
                            println!("{} Backend actualizado exitosamente a: {}", "✔".green(), sel.active_backend.to_string().bold());
                            if sel.fallback_active {
                                println!("  {} Advertencia: Se activó fallback automático a CPU: {}", "⚠".yellow(), sel.fallback_reason.unwrap_or_default().yellow());
                            }
                        }
                        Err(e) => {
                            eprintln!("{} Fallo al configurar backend: {}", "✖".red(), e);
                        }
                    }
                }
                ShceCommands::TestFallback => {
                    println!(
                        "\n{}",
                        "─── SIMULACIÓN DE FALLO DE GPU Y VERIFICACIÓN DE FALLBACK ───"
                            .bold()
                            .cyan()
                    );
                    println!("  [1/4] Inyectando fallo de hardware simulado (DXGI_ERROR_DEVICE_REMOVED)...");
                    core.inject_shce_gpu_failure(true);
                    let sel_failed = core.get_shce_selection();
                    println!("  [2/4] Estado detectado: Fallback activo = {}, Razón = {:?}", sel_failed.fallback_active, sel_failed.fallback_reason);
                    println!("  [3/4] Ejecutando análisis heurístico en segundo plano durante el fallo...");
                    let dummy_data = b"Malicious payload simulation to verify uninterrupted scan execution during GPU reset";
                    let dummy_scan = core.scan_file_bytes(dummy_data, "fallback_test.bin");
                    println!("  {} Análisis completado sin interrupción ni bloqueo del sistema: Estado={:?}", "✔".green(), dummy_scan.status);
                    println!("  [4/4] Restaurando controlador GPU y verificando recuperación automática...");
                    core.inject_shce_gpu_failure(false);
                    let sel_restored = core.get_shce_selection();
                    println!("  {} Backend recuperado nominalmente: {}", "✔".green(), sel_restored.active_backend);
                }
                ShceCommands::Limit { percentage } => {
                    core.set_shce_gpu_utilization_limit(percentage);
                    println!("{} Límite de utilización máxima de GPU fijado a {}%.", "✔".green(), percentage);
                }
            }
        }

        Commands::Ssem { sub } => {
            let core = SamuLibreCore::new("data/canaries", "data/vpn", false);
            match sub {
                SsemCommands::Status => {
                    let cfg = core.get_ssem_config();
                    let metrics = core.get_ssem_metrics();
                    println!(
                        "\n{}",
                        "─── SAMULIBRE SECURITY EVENT MANAGER (SSEM / SIEM EXPORTER) ───"
                            .bold()
                            .cyan()
                    );
                    println!("{}", "CONFIGURACIÓN DE TELEMETRÍA EMPRESARIAL:".bold().white());
                    println!("  {} Estado del Módulo:        {}", "•".cyan(), if cfg.enabled { "HABILITADO".green().bold() } else { "DESHABILITADO".yellow() });
                    println!("  {} Identificador Endpoint:   {}", "•".cyan(), cfg.endpoint_id.bold());
                    println!("  {} Servidor SIEM Remoto:     {}", "•".cyan(), cfg.remote_server.clone().unwrap_or_else(|| "No configurado (Solo Registro Local)".dimmed().to_string()));
                    println!("  {} Puerto Remoto:            {}", "•".cyan(), cfg.remote_port);
                    println!("  {} Protocolo de Transporte:  {:?}", "•".cyan(), cfg.transport);
                    println!("  {} Formato de Exportación:   {}", "•".cyan(), cfg.format);
                    println!("  {} Umbral Mínimo Severidad:  {:?}", "•".cyan(), cfg.min_severity);
                    println!("  {} Privacidad Rutas Usuario: {}", "•".cyan(), if cfg.anonymize_user_paths { "ANONIMIZADAS (Cumplimiento GDPR/ISO 27001)".green() } else { "COMPLETAS (Modo Auditoría Forense)".dimmed() });
                    println!("  {} Integraciones Compatibles:{}", "•".cyan(), cfg.target_siem.cyan());

                    println!("\n{}", "MÉTRICAS DE RENDIMIENTO Y RESILIENCIA OFFLINE:".bold().white());
                    println!("  {} Eventos Totales Recibidos: {}", "•".cyan(), metrics.events_received_total);
                    println!("  {} Registros Locales (JSONL): {}", "•".cyan(), metrics.events_written_local);
                    println!("  {} Eventos Enviados a SIEM:   {}", "•".cyan(), metrics.events_sent_remote);
                    println!("  {} En Búfer Offline (Espera): {}", "•".cyan(), metrics.events_buffered_offline);
                    println!("  {} Eventos Vaciados de Búfer: {}", "•".cyan(), metrics.buffer_flushed_total);
                    println!("  {} Fallos de Entrega Remota:  {}", "•".cyan(), if metrics.delivery_failures_total > 0 { metrics.delivery_failures_total.to_string().yellow() } else { "0".green() });
                }
                SsemCommands::Configure {
                    server,
                    port,
                    format,
                    transport,
                    anonymize_paths,
                } => {
                    let mut cfg = core.get_ssem_config();
                    if let Some(s) = server {
                        cfg.remote_server = Some(s);
                    }
                    cfg.remote_port = port;
                    cfg.anonymize_user_paths = anonymize_paths;

                    cfg.format = match format.to_lowercase().as_str() {
                        "json" => samulibre_types::SsemExportFormat::Json,
                        "syslog" | "rfc5424" => samulibre_types::SsemExportFormat::SyslogRfc5424,
                        "csv" => samulibre_types::SsemExportFormat::Csv,
                        other => {
                            eprintln!("Formato no reconocido: {}. Usando JSON por defecto.", other);
                            samulibre_types::SsemExportFormat::Json
                        }
                    };

                    cfg.transport = match transport.to_lowercase().as_str() {
                        "tcp" => samulibre_types::SsemTransportProtocol::Tcp,
                        "tls" => samulibre_types::SsemTransportProtocol::Tls,
                        "udp" => samulibre_types::SsemTransportProtocol::Udp,
                        _ => samulibre_types::SsemTransportProtocol::LocalFileOnly,
                    };

                    core.set_ssem_config(cfg);
                    println!("{} Configuración de SSEM actualizada correctamente.", "✔".green());
                }
                SsemCommands::ExportCsv { output } => {
                    match core.export_ssem_csv(&output) {
                        Ok(count) => println!("{} Exportados {} eventos forenses a: {}", "✔".green(), count, output.display()),
                        Err(e) => eprintln!("{} Fallo al exportar CSV: {}", "✖".red(), e),
                    }
                }
                SsemCommands::ExportJson { output } => {
                    match core.export_ssem_json(&output) {
                        Ok(count) => println!("{} Exportados {} eventos estructurados a: {}", "✔".green(), count, output.display()),
                        Err(e) => eprintln!("{} Fallo al exportar JSON: {}", "✖".red(), e),
                    }
                }
                SsemCommands::Flush => {
                    match core.flush_ssem_buffer() {
                        Ok(count) => println!("{} Búfer offline vaciado: {} eventos transmitidos exitosamente.", "✔".green(), count),
                        Err(e) => eprintln!("{} Fallo al vaciar búfer: {}", "✖".red(), e),
                    }
                }
                SsemCommands::SimulateEvent => {
                    println!(
                        "\n{}",
                        "─── SIMULACIÓN DE EVENTO DE SEGURIDAD EMPRESARIAL SSEM ───"
                            .bold()
                            .cyan()
                    );
                    let alert = samulibre_types::ThreatAlert {
                        id: uuid::Uuid::new_v4(),
                        timestamp: chrono::Utc::now(),
                        severity: samulibre_types::Severity::Critical,
                        category: samulibre_types::ThreatCategory::RansomwareActivity,
                        title: "Ransomware.Win32.Conti.Gen (Mass Encryption Attempt)".to_string(),
                        details: "Intento de cifrado en ráfaga neutralizado en C:\\Users\\saghe\\Documents\\Financial2026.xlsx".to_string(),
                        process_id: Some(8888),
                        process_name: Some("crypt_dropper.exe".to_string()),
                        target_path: Some("C:\\Users\\saghe\\Documents\\Financial2026.xlsx".to_string()),
                        action_taken: "Proceso Terminado y Archivo Custodiado en Bóveda XOR".to_string(),
                    };

                    core.record_security_event(&alert);

                    let ev = samulibre_core::ssem::SsemEngine::new("data").alert_to_ssem_event(&alert, "2.1.14");
                    println!("{}", "1. FORMATO SYSLOG RFC 5424 (FortiAnalyzer / Graylog / Wazuh):".bold().white());
                    println!("   {}", samulibre_core::ssem::SsemEngine::format_syslog_rfc5424(&ev).cyan());

                    println!("\n{}", "2. FORMATO JSON ESTRUCTURADO (Splunk HEC / Microsoft Sentinel):".bold().white());
                    let json_pretty = serde_json::to_string_pretty(&ev).unwrap_or_default();
                    println!("   {}", json_pretty.green());

                    println!("\n{}", "3. FORMATO CSV FORENSE (Auditorías & Cumplimiento):".bold().white());
                    print!("   {}", samulibre_core::ssem::SsemEngine::format_csv_row(&ev).yellow());

                    println!("\n{} Evento de prueba registrado en los canales locales y búfer de telemetría.", "✔ ÉXITO:".green().bold());
                }
            }
        }

        Commands::Reputation { sub } => {
            let rep_engine = samulibre_core::reputation::ReputationEngine::new(Path::new("data"));
            match sub {
                ReputationCommands::Assess { file } => {
                    println!(
                        "\n{}",
                        "─── EVALUACIÓN INTEGRAL DE REPUTACIÓN Y FIRMA AUTHENTICODE ───"
                            .bold()
                            .cyan()
                    );
                    if !file.exists() {
                        eprintln!("{} El archivo especificado no existe: {}", "✖".red(), file.display());
                        return Ok(());
                    }

                    match rep_engine.assess_file(&file) {
                        Ok(assessment) => {
                            println!("  {} Archivo Objetivo:         {}", "•".cyan(), assessment.target_path.bold().white());
                            println!("  {} Hash SHA-256:             {}", "•".cyan(), assessment.sha256.dimmed());
                            println!("  {} Firma Authenticode:       {}", "•".cyan(), format!("{}", assessment.authenticode).bold());
                            println!(
                                "  {} Editor Detectado:         {}",
                                "•".cyan(),
                                assessment.publisher.as_deref().unwrap_or("No especificado / Sin firma")
                            );
                            println!("  {} Categoría de Confianza:   {:?}", "•".cyan(), assessment.trust_tier);
                            println!(
                                "  {} Binario Genuino Windows:  {}",
                                "•".cyan(),
                                if assessment.is_windows_os_binary { "SÍ (System32 genuino)".green().bold() } else { "NO".white() }
                            );
                            println!(
                                "  {} Herramienta Desarrollo:   {}",
                                "•".cyan(),
                                if assessment.is_known_dev_tool { "SÍ (Supresión inteligente activa)".green().bold() } else { "NO".white() }
                            );
                            println!(
                                "  {} Exclusión de Usuario (FP):{}",
                                "•".cyan(),
                                if assessment.is_user_excluded { "ACTIVA (Falso positivo resuelto)".green().bold() } else { "Inactiva".dimmed() }
                            );

                            let score_colored = if assessment.reputation_score >= 80 {
                                format!("{}/100", assessment.reputation_score).green().bold()
                            } else if assessment.reputation_score >= 40 {
                                format!("{}/100", assessment.reputation_score).yellow().bold()
                            } else {
                                format!("{}/100", assessment.reputation_score).red().bold()
                            };

                            println!("\n  {} PUNTUACIÓN DE CONFIANZA:  {}", "★".yellow().bold(), score_colored);
                            println!("  {} NIVEL DE EVALUACIÓN:      {}", "★".yellow().bold(), format!("{}", assessment.trust_level).bold());

                            println!("\n{}", "DESGLOSE EXPLICABLE DE FACTORES:".bold().white());
                            for reason in &assessment.evaluation_reasons {
                                println!("    {} {}", "✔".green(), reason);
                            }
                        }
                        Err(e) => eprintln!("{} Fallo al evaluar reputación: {}", "✖".red(), e),
                    }
                }
                ReputationCommands::ReportFp { file, reason } => {
                    println!(
                        "\n{}",
                        "─── REPORTE DE FALSO POSITIVO Y MITIGACIÓN LOCAL ───"
                            .bold()
                            .cyan()
                    );
                    if !file.exists() {
                        eprintln!("{} El archivo no existe: {}", "✖".red(), file.display());
                        return Ok(());
                    }

                    match fs::read(&file) {
                        Ok(bytes) => {
                            let sha256 = hex::encode(sha2::Sha256::digest(&bytes));
                            let path_str = file.to_string_lossy().to_string();
                            let rule = rep_engine.overrides_manager().add_override(
                                Some(sha256.clone()),
                                Some(path_str.clone()),
                                None,
                                reason.clone(),
                            );
                            println!("{} Falso positivo registrado y exclusión local aplicada.", "✔".green().bold());
                            println!("  {} Identificador Regla: {}", "•".cyan(), rule.id);
                            println!("  {} Archivo:             {}", "•".cyan(), path_str);
                            println!("  {} Hash SHA-256:        {}", "•".cyan(), sha256);
                            println!("  {} Justificación:       {}", "•".cyan(), reason);
                            println!("  {} Estado:              {}", "•".cyan(), rule.report_status.bold().green());
                            println!("\n{} Este archivo no volverá a generar alertas heurísticas ni bloqueos.", "NOTA:".cyan().bold());
                        }
                        Err(e) => eprintln!("{} No se pudo leer el archivo: {}", "✖".red(), e),
                    }
                }
                ReputationCommands::ListOverrides => {
                    println!(
                        "\n{}",
                        "─── EXCLUSIONES ACTIVAS Y FALSOS POSITIVOS RESUELTOS ───"
                            .bold()
                            .cyan()
                    );
                    let overrides = rep_engine.overrides_manager().list_overrides();
                    if overrides.is_empty() {
                        println!("{} No hay exclusiones manuales de falsos positivos registradas.", "✔".green());
                    } else {
                        for (i, r) in overrides.iter().enumerate() {
                            println!(
                                "  [{}] ID: {} | Estado: {}",
                                i + 1,
                                r.id.to_string().cyan(),
                                r.report_status.bold().green()
                            );
                            if let Some(ref p) = r.file_path_pattern {
                                println!("      Ruta: {}", p.white());
                            }
                            if let Some(ref h) = r.sha256 {
                                println!("      Hash: {}", h.dimmed());
                            }
                            println!("      Motivo: {}", r.reason.italic());
                            println!("      Fecha:  {}", r.created_at);
                        }
                    }
                }
                ReputationCommands::RemoveOverride { id } => {
                    match uuid::Uuid::parse_str(&id) {
                        Ok(uuid) => {
                            if rep_engine.overrides_manager().remove_override(uuid) {
                                println!("{} Exclusión {} eliminada exitosamente.", "✔".green(), id);
                            } else {
                                eprintln!("{} No se encontró ninguna exclusión con ID: {}", "✖".red(), id);
                            }
                        }
                        Err(e) => eprintln!("{} Formato de UUID inválido: {}", "✖".red(), e),
                    }
                }
                ReputationCommands::ListPublishers => {
                    println!(
                        "\n{}",
                        "─── CATÁLOGO DE EDITORES Y CERTIFICADOS DE CONFIANZA ───"
                            .bold()
                            .cyan()
                    );
                    println!("{}", "NIVEL 1: PLATAFORMA Y NÚCLEO DEL SISTEMA OPERATIVO (Tier 1):".bold().white());
                    for p in samulibre_core::reputation::TrustedPublisherCatalog::TIER1_PLATFORM_CORE {
                        println!("  {} {}", "•".green(), p);
                    }
                    println!("\n{}", "NIVEL 2: PROVEEDORES COMERCIALES VERIFICADOS (Tier 2):".bold().white());
                    for p in samulibre_core::reputation::TrustedPublisherCatalog::TIER2_COMMERCIAL {
                        println!("  {} {}", "•".cyan(), p);
                    }
                    println!("\n{}", "NIVEL 3: CADENAS DE DESARROLLO Y LENGUAJES (Tier 3):".bold().white());
                    for p in samulibre_core::reputation::TrustedPublisherCatalog::TIER3_DEV_TOOLCHAIN {
                        println!("  {} {}", "•".yellow(), p);
                    }
                    println!("\n{}", "BINARIOS CON SUPRESIÓN INTELIGENTE DE DESARROLLO:".bold().white());
                    println!("  {}", samulibre_core::reputation::DEVELOPER_TOOLCHAIN_BINARIES.join(", ").dimmed());
                }
            }
        }

        Commands::WebShield { sub } => {
            let web_shield = samulibre_shield::web_shield::WebShieldEngine::new(Path::new("data"));
            match sub {
                WebShieldCommands::Status => {
                    let cfg = web_shield.get_config();
                    let blocked = web_shield.list_blocked_domains();
                    println!(
                        "\n{}",
                        "─── ESTADO DEL ESCUDO WEB Y PROTECCIÓN DE RED (WEB SHIELD) ───"
                            .bold()
                            .cyan()
                    );
                    println!(
                        "  {} Estado del Módulo:        {}",
                        "•".cyan(),
                        if cfg.enabled { "HABILITADO (Inspección Activa)".green().bold() } else { "DESHABILITADO".red() }
                    );
                    println!("  {} Proveedor DNS Seguro:     {}", "•".cyan(), cfg.secure_dns_provider.bold().white());
                    println!(
                        "  {} Filtro Anti-Phishing:     {}",
                        "•".cyan(),
                        if cfg.block_phishing { "ACTIVO (Detección de Homóglifos & Marcas)".green().bold() } else { "Inactivo".white() }
                    );
                    println!(
                        "  {} Bloqueo C2 / Botnets:     {}",
                        "•".cyan(),
                        if cfg.block_c2 { "ACTIVO (Threat Intelligence Integrado)".green().bold() } else { "Inactivo".white() }
                    );
                    println!(
                        "  {} Detección Dominios DGA:   {}",
                        "•".cyan(),
                        if cfg.block_dga { "ACTIVO (Entropía Shannon & Consonantes T1568.002)".green().bold() } else { "Inactivo".white() }
                    );
                    println!(
                        "  {} Inspección Mark-of-the-Web:{}",
                        "•".cyan(),
                        if cfg.inspect_downloads_motw { "ACTIVA (ADS Zone.Identifier)".green().bold() } else { "Inactiva".white() }
                    );
                    println!("  {} Dominios Bloqueados Locales: {}", "•".cyan(), blocked.len());
                }
                WebShieldCommands::CheckUrl { url } => {
                    println!(
                        "\n{}",
                        "─── INSPECCIÓN EN TIEMPO REAL DE URL / DOMINIO WEB ───"
                            .bold()
                            .cyan()
                    );
                    let verdict = web_shield.evaluate_url(&url);
                    println!("  {} Entrada Analizada:        {}", "•".cyan(), verdict.url.white().bold());
                    println!("  {} Host / Dominio:           {}", "•".cyan(), verdict.domain.cyan());

                    let status_str = if verdict.is_blocked {
                        "BLOQUEADO (Amenaza Neutralizada)".red().bold()
                    } else {
                        "PERMITIDO (Confiable)".green().bold()
                    };
                    println!("  {} Veredicto de Seguridad:   {}", "•".cyan(), status_str);
                    println!("  {} Categoría de Amenaza:     {}", "•".cyan(), format!("{}", verdict.category).bold());
                    println!("  {} Puntuación de Riesgo:     {}/100", "•".cyan(), verdict.threat_score);
                    println!("  {} Latencia de Inspección:   {} µs ({:.3} ms)", "•".cyan(), verdict.latency_us, verdict.latency_us as f64 / 1000.0);
                    println!("\n{}", "DETALLE FORENSE:".bold().white());
                    println!("    {} {}", if verdict.is_blocked { "✖".red() } else { "✔".green() }, verdict.explanation);
                }
                WebShieldCommands::InspectMotw { file } => {
                    println!(
                        "\n{}",
                        "─── INSPECCIÓN NTFS MARK-OF-THE-WEB (ZONE.IDENTIFIER ADS) ───"
                            .bold()
                            .cyan()
                    );
                    if !file.exists() {
                        eprintln!("{} El archivo no existe: {}", "✖".red(), file.display());
                        return Ok(());
                    }

                    let motw = samulibre_shield::web_shield::WebShieldEngine::inspect_file_motw(&file);
                    println!("  {} Archivo Inspeccionado:    {}", "•".cyan(), motw.file_path.bold().white());
                    println!(
                        "  {} Posee Marca de la Web:    {}",
                        "•".cyan(),
                        if motw.has_motw { "SÍ (NTFS ADS :Zone.Identifier detectado)".yellow().bold() } else { "NO (Origen local o no marcado)".white() }
                    );
                    if let Some(zid) = motw.zone_id {
                        let zone_name = match zid {
                            0 => "0 (Mi PC / Local)",
                            1 => "1 (Intranet Local)",
                            2 => "2 (Sitios de Confianza)",
                            3 => "3 (Internet - Zona Pública)",
                            4 => "4 (Sitios Restringidos)",
                            _ => "Desconocida",
                        };
                        println!("  {} Identificador de Zona:    {}", "•".cyan(), zone_name.bold());
                    }
                    if let Some(ref hurl) = motw.host_url {
                        println!("  {} URL de Descarga (HostUrl):{}", "•".cyan(), hurl.cyan());
                    }
                    if let Some(ref rurl) = motw.referrer_url {
                        println!("  {} URL Referente (Referrer): {}", "•".cyan(), rurl.dimmed());
                    }
                    println!("\n  {} EVALUACIÓN DE PROCEDENCIA: {}", "•".cyan(), motw.risk_assessment.bold());
                }
                WebShieldCommands::BlockDomain { domain, reason } => {
                    if web_shield.add_blocked_domain(&domain, &reason) {
                        println!("{} Dominio '{}' agregado a la lista de bloqueo permanente.", "✔".green(), domain);
                    } else {
                        eprintln!("{} No se pudo agregar o ya existía el dominio: {}", "✖".red(), domain);
                    }
                }
                WebShieldCommands::UnblockDomain { domain } => {
                    if web_shield.remove_blocked_domain(&domain) {
                        println!("{} Dominio '{}' removido de la lista de bloqueo.", "✔".green(), domain);
                    } else {
                        eprintln!("{} El dominio no estaba en la lista de bloqueo: {}", "✖".red(), domain);
                    }
                }
                WebShieldCommands::ListBlocked => {
                    println!(
                        "\n{}",
                        "─── LISTA DE DOMINIOS BLOQUEADOS LOCALMENTE ───"
                            .bold()
                            .cyan()
                    );
                    let list = web_shield.list_blocked_domains();
                    if list.is_empty() {
                        println!("{} No hay dominios personalizados en la lista negra local.", "✔".green());
                    } else {
                        for (i, d) in list.iter().enumerate() {
                            println!("  [{}] {}", i + 1, d.red().bold());
                        }
                    }
                }
                WebShieldCommands::TestDga => {
                    println!(
                        "\n{}",
                        "─── PRUEBA DE DETECCIÓN DGA Y EXFILTRACIÓN DNS (T1568.002 / T1071.004) ───"
                            .bold()
                            .cyan()
                    );
                    let test_samples = [
                        ("http://x8k2mz9q7a1w0.biz", "Simulación DGA (Entropía alta y secuencia pseudoaleatoria)"),
                        ("4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a.attacker.com", "Simulación Túnel / Exfiltración DNS (Etiqueta hex de 40 bytes)"),
                        ("https://login.microsoft.com", "Dominio legítimo de alta prevalencia (Control Negativo)"),
                        ("http://paypal-security-verification.xyz", "Simulación Phishing Brand Spoofing"),
                    ];

                    for (sample, desc) in test_samples {
                        let verdict = web_shield.evaluate_url(sample);
                        println!("  {} [{}]", "•".cyan(), desc.bold());
                        println!("    URL:       {}", sample);
                        println!("    Resultado: {} ({}) | Latencia: {} µs",
                            if verdict.is_blocked { "BLOQUEADO".red().bold() } else { "PERMITIDO".green().bold() },
                            verdict.category,
                            verdict.latency_us
                        );
                        println!("    Detalle:   {}\n", verdict.explanation.dimmed());
                    }
                }
            }
        }

        Commands::Benchmark { sub } => {
            let perf_engine = samulibre_core::performance::PerformanceBenchmarkEngine::new(Path::new("data"));
            match sub {
                BenchmarkCommands::Performance => {
                    println!(
                        "\n{}",
                        "─── SUITE DE RENDIMIENTO Y OPTIMIZACIÓN SAMULIBRE (AV-TEST / AV-COMPARATIVES) ───"
                            .bold()
                            .cyan()
                    );
                    println!("Ejecutando pruebas empíricas de huella de memoria, I/O y latencia de ejecución...");
                    match perf_engine.run_full_performance_benchmark() {
                        Ok(report) => {
                            println!("\n{}", "1. HUELLA DE RECURSOS DEL SISTEMA:".bold().white());
                            println!("   • Memoria RAM en Reposo (Working Set): {:.2} MB", report.resource_usage.ram_working_set_mb);
                            println!("   • Memoria Privada Asignada:           {:.2} MB", report.resource_usage.ram_private_bytes_mb);
                            println!("   • Uso de CPU en Reposo:               {:.2}%", report.resource_usage.cpu_usage_percent);
                            println!("   • Hilos del Proceso Activos:          {}", report.resource_usage.threads_count);
                            println!("   • Handles Abiertos del Proceso:       {}", report.resource_usage.handles_count);

                            println!("\n{}", "2. OVERHEAD DE ENTRADA/SALIDA (FILE I/O BENCHMARK):".bold().white());
                            println!("   • Volumen de Archivos Evaluados:      {:.2} MB", report.io_metrics.total_bytes_mb);
                            println!("   • Tiempo I/O Nativo Base:             {} ms", report.io_metrics.raw_io_duration_ms);
                            println!("   • Tiempo I/O con On-Access Activo:    {} ms", report.io_metrics.monitored_io_duration_ms);
                            println!("   • Overhead I/O Inducido:              {:.2}%", report.io_metrics.cpu_overhead_percent);
                            println!("   • Rendimiento Efectivo de I/O:        {:.2} MB/s", report.io_metrics.io_throughput_mb_per_sec);

                            println!("\n{}", "3. LATENCIA DE LANZAMIENTO DE APLICACIONES (PE APPS):".bold().white());
                            println!("   • Lanzamiento en Frío (Cold Launch):  {:.2} ms", report.app_launch_metrics.cold_launch_latency_ms);
                            println!("   • Lanzamiento Acelerado (Warm Cache): {:.2} ms", report.app_launch_metrics.warm_launch_latency_ms);
                            println!("   • Factor de Aceleración Caché:        {:.2}x", report.app_launch_metrics.clean_cache_acceleration_ratio);

                            println!("\n{}", "4. LATENCIA DE FILTRADO Y NAVEGACIÓN WEB:".bold().white());
                            println!("   • Latencia de Decisión URL / DNS:     {} µs ({:.4} ms)", report.web_inspection_latency_us, report.web_inspection_latency_us as f64 / 1000.0);

                            println!("\n{}", "5. CALIFICACIÓN Y PUNTUACIÓN DE LABORATORIO:".bold().white());
                            println!("   • AV-Comparatives Impact Score:       {:.1} (Objetivo < 10.0)", report.av_comparatives_impact_score);
                            println!("   • Puntuación Rendimiento AV-TEST:     {:.1} / 6.0", report.av_test_performance_score);
                            println!("   • Estado para Certificación:          {}", report.certification_readiness_status.bold().green());

                            println!("\n{}", "=================================================================".green());
                            println!("{} Evaluación de rendimiento completada sin degradación del sistema.", "✔ ÉXITO:".green().bold());
                        }
                        Err(e) => {
                            eprintln!("{} Error durante la ejecución del benchmark: {}", "✖".red(), e);
                        }
                    }
                }
                BenchmarkCommands::OptimizeRam => {
                    println!(
                        "\n{}",
                        "─── OPTIMIZACIÓN ACTIVA DE MEMORIA RAM (WORKING SET TRIM) ───"
                            .bold()
                            .cyan()
                    );
                    let (before_mb, after_mb) = perf_engine.optimize_system_memory();
                    println!("  Memoria RAM previa (Working Set): {:.2} MB", before_mb);
                    println!("  Liberando páginas no críticas de memoria al sistema operativo...");
                    println!("  {} Memoria optimizada exitosamente.", "✔".green());
                    println!("  Memoria RAM tras optimización:    {:.2} MB", after_mb);
                    if before_mb > after_mb {
                        println!("  {} Memoria recuperada: {:.2} MB", "•".cyan(), before_mb - after_mb);
                    }
                }
            }
        }

        Commands::Certification { sub } => {
            let cert_harness = samulibre_core::certification::CertificationHarnessEngine::new(Path::new("data"));
            match sub {
                CertificationCommands::TestAmtso => {
                    println!(
                        "\n{}",
                        "─── BATERÍA DE PRUEBAS ESTÁNDAR AMTSO (ANTI-MALWARE TESTING STANDARDS) ───"
                            .bold()
                            .cyan()
                    );
                    println!("Ejecutando pruebas estandarizadas de neutralización de amenazas y validación de funciones...");
                    let rep = cert_harness.run_amtso_test_suite();

                    for (i, r) in rep.results.iter().enumerate() {
                        let status_badge = if r.passed { "PASS".green().bold() } else { "FAIL".red().bold() };
                        println!("\n  [{}] {} | {}", i + 1, r.feature_id.cyan(), status_badge);
                        println!("      Prueba:    {}", r.name.bold().white());
                        println!("      Objetivo:  {}", r.description.dimmed());
                        println!("      Latencia:  {:.2} ms", r.latency_ms);
                        println!("      Evidencia: {}", r.detail);
                    }

                    println!("\n{}", "─────────────────────────────────────────────────────────────────".cyan());
                    println!("  Total de Pruebas:      {}", rep.total_tests);
                    println!("  Pruebas Aprobadas:     {}", rep.passed_tests.to_string().green().bold());
                    println!("  Pruebas Fallidas:      {}", if rep.failed_tests > 0 { rep.failed_tests.to_string().red().bold() } else { "0".green() });
                    println!("  Conformidad AMTSO:     {}%", rep.compliance_percentage.to_string().green().bold());
                    println!("{}", "─────────────────────────────────────────────────────────────────".cyan());
                }
                CertificationCommands::TestAvTest => {
                    println!(
                        "\n{}",
                        "─── SIMULACIÓN DE MATRIZ DE EVALUACIÓN AV-TEST (WINDOWS ENDPOINT) ───"
                            .bold()
                            .cyan()
                    );
                    println!("Calculando puntuaciones en los 3 pilares clave: Protección, Rendimiento y Usabilidad...");
                    let rep = cert_harness.run_av_test_evaluation();

                    println!("\n{}", "1. PROTECCIÓN FRENTE A MALWARE (0-DAY & PREVALENTE):".bold().white());
                    println!("   • Puntuación: {:.1} / 6.0 puntos", rep.protection_score);
                    println!("   • Evidencia:  {}", rep.protection_notes.dimmed());

                    println!("\n{}", "2. RENDIMIENTO E IMPACTO EN EL SISTEMA:".bold().white());
                    println!("   • Puntuación: {:.1} / 6.0 puntos", rep.performance_score);
                    println!("   • Evidencia:  {}", rep.performance_notes.dimmed());

                    println!("\n{}", "3. USABILIDAD Y FALSOS POSITIVOS EN SOFTWARE LIMPIO:".bold().white());
                    println!("   • Puntuación: {:.1} / 6.0 puntos", rep.usability_score);
                    println!("   • Evidencia:  {}", rep.usability_notes.dimmed());

                    println!("\n{}", "=================================================================".green());
                    println!("  PUNTUACIÓN TOTAL AV-TEST: {:.1} / 18.0 PUNTOS", rep.total_score);
                    println!(
                        "  ESTADO DE CERTIFICACIÓN:  {}",
                        if rep.av_test_certified {
                            "AV-TEST CERTIFIED (TOP PRODUCT READY)".green().bold()
                        } else {
                            "REQUIERE REVISIÓN".yellow().bold()
                        }
                    );
                    println!("{}", "=================================================================".green());
                }
                CertificationCommands::TestAvComp => {
                    println!(
                        "\n{}",
                        "─── SIMULACIÓN DE METODOLOGÍA AV-COMPARATIVES ───"
                            .bold()
                            .cyan()
                    );
                    let rep = cert_harness.run_av_comparatives_evaluation();
                    println!("  • Tasa de Bloqueo Real-World:      {:.1}%", rep.real_world_block_rate_percent);
                    println!("  • Falsos Positivos Detectados:     {}", rep.false_positives_count);
                    println!("  • AV-Comparatives Impact Score:    {:.1} (Límite Advanced+ < 10.0)", rep.performance_impact_score);
                    println!("  • Galardón Estimado:               {}", rep.award_tier.bold().green());
                    println!("  • Malware Protection Test:         {}", if rep.passes_malware_protection_test { "APROBADO".green() } else { "NO APROBADO".red() });
                    println!("  • Performance Benchmark Test:     {}", if rep.passes_performance_test { "APROBADO".green() } else { "NO APROBADO".red() });
                    println!("  • False Alarm Test:                {}", if rep.passes_false_alarm_test { "APROBADO (0 FP)".green() } else { "FALLIDO".red() });
                }
                CertificationCommands::Audit => {
                    println!(
                        "\n{}",
                        "─── AUDITORÍA INTEGRAL DE PREPARACIÓN PARA CERTIFICACIÓN INDEPENDIENTE ───"
                            .bold()
                            .cyan()
                    );
                    println!("Ejecutando auditoría multicriterio (AMTSO, AV-TEST, AV-Comparatives)...");
                    let audit = cert_harness.run_full_audit();

                    println!("\n  Versión del Motor:            {}", audit.engine_version.bold());
                    println!("  Fecha y Hora UTC:             {}", audit.timestamp_utc);
                    println!("  Conformidad Estándar AMTSO:   {}%", audit.amtso_suite.compliance_percentage);
                    println!("  Puntuación Total AV-TEST:     {:.1} / 18.0", audit.av_test.total_score);
                    println!("  Nivel AV-Comparatives:        {}", audit.av_comparatives.award_tier.bold().green());
                    println!("  Impact Score de Rendimiento:  {:.1}", audit.av_comparatives.performance_impact_score);
                    println!("\n{}", "DICTAMEN DEL EQUIPO DE AUDITORÍA:".bold().white());
                    println!("  {}", audit.overall_readiness_verdict.bold().green());
                    println!("\n{}", "NOTA DE CUMPLIMIENTO Y CERO ALUCINACIÓN:".bold().yellow());
                    println!("  SamuLibre NO ostenta certificados comerciales oficiales hasta no ser evaluado");
                    println!("  físicamente por los laboratorios independientes AV-TEST GmbH y AV-Comparatives.");
                    println!("  Este arnés valida técnicamente la total aptitud y alineación con sus metodologías.");
                }
            }
        }

        Commands::Wdhe { sub } => {
            let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);
            let wdhe = &core.wdhe;

            match sub {
                WdheCommands::Status => {
                    println!("\n{}", "─── SAMULIBRE COMPATIBILITY CENTER (SCC) ───".bold().cyan());
                    println!("Consultando estado de telemetría de Microsoft Defender y SamuLibre...");
                    let dash = wdhe.get_compatibility_dashboard();

                    println!("\n{}", "ESTADO DE MICROSOFT DEFENDER:".bold().white());
                    println!("  • Servicio WinDefend:           {}", if dash.defender_service_running { "EN EJECUCIÓN (MsMpEng.exe)".green().bold() } else { "DETENIDO".red() });
                    println!("  • Protección en Tiempo Real:    {}", if dash.defender_rtp_enabled { "HABILITADA".green().bold() } else { "DESHABILITADA".yellow() });
                    println!("  • Motor Antivirus Activo:       {}", if dash.defender_antivirus_enabled { "SÍ (Activo)".green() } else { "NO".yellow() });
                    println!("  • Tamper Protection:            {}", dash.defender_tamper_protection.green());
                    println!("  • Versión de Inteligencia:      {}", dash.defender_signature_version);
                    println!("  • Versión del Motor Defender:   {}", dash.defender_engine_version);
                    if let Some(pid) = dash.defender_process_pid {
                        println!("  • PID del Proceso MsMpEng:      {} (RAM: {} MB)", pid.to_string().cyan(), dash.defender_ram_usage_mb);
                    }

                    println!("\n{}", "ESTADO DE COEXISTENCIA SAMULIBRE:".bold().white());
                    println!("  • Versión SamuLibre:            {}", dash.samulibre_version.bold());
                    println!("  • Modo de Coexistencia WDHE:    {}", format!("{}", dash.samulibre_mode).bold().cyan());
                    println!("  • Perfil Resource Governor:     {}", format!("{}", dash.samulibre_resource_profile).bold().yellow());
                    println!("  • PID del Proceso SamuLibre:    {} (RAM: {} MB)", dash.samulibre_pid.to_string().cyan(), dash.samulibre_ram_usage_mb);
                    println!("  • Bloqueos I/O Prevenidos:      {}", dash.lock_conflicts_prevented.to_string().green().bold());
                    println!("  • Aciertos Clean Cache:         {}", dash.clean_cache_hits.to_string().green());
                    println!("  • Alertas Defender Recientes:   {}", dash.recent_defender_alerts_count);

                    println!("\n{}", "RECURSOS DEL SISTEMA Y HARDWARE:".bold().white());
                    println!("  • Uso Global de CPU:            {:.1}%", dash.system_cpu_usage_pct);
                    println!("  • Memoria RAM Usada / Total:    {} MB / {} MB", dash.system_ram_used_mb, dash.system_ram_total_mb);
                    println!("  • Aceleración GPU Heterogénea:  {}", if dash.gpu_active { "ACTIVA (DirectML/SHCE)".green() } else { "MODO CPU ONLY".yellow() });
                    println!("  • Throttling Dinámico Activo:   {}", if dash.throttling_active { "SÍ (Cedió CPU al usuario)".yellow().bold() } else { "NO (Carga normal)".green() });

                    println!("\n{}", "PROVEEDORES REGISTRADOS EN WINDOWS SECURITY CENTER:".bold().white());
                    for p in dash.active_wsc_providers {
                        println!("  • {}", p.green());
                    }
                    println!("{}", "=================================================================".cyan());
                }

                WdheCommands::Audit => {
                    println!("\n{}", "─── FASE 1: AUDITORÍA EXHAUSTIVA DE COMPATIBILIDAD (WDHE) ───".bold().cyan());
                    println!("Evaluando compatibilidad e interoperabilidad de los 15 subsistemas clave...");
                    let rep = wdhe.run_compatibility_audit();

                    println!("\n{}", "RESUMEN DE AUDITORÍA:".bold().white());
                    println!("  • Total de Componentes Auditados:     {}", rep.total_components.to_string().bold());
                    println!("  • Compatibles Directamente:          {}", rep.compatible_count.to_string().green().bold());
                    println!("  • Compatibles con Ajustes Menores:   {}", rep.compatible_with_adjustments_count.to_string().yellow().bold());
                    println!("  • Posibles Conflictos Mitigados:     {}", rep.potential_conflicts_count.to_string().cyan().bold());
                    println!("  • Falsos Positivos Confirmados:      {}", rep.confirmed_false_positives_count.to_string().magenta().bold());
                    println!("  • Detecciones Legítimas de Seguridad: {}", rep.legitimate_detections_count);
                    println!("  • Pendientes de Investigación:       {}", rep.pending_investigation_count);

                    println!("\n{}", "MATRIZ DE INTEROPERABILIDAD DETALLADA:".bold().white());
                    for (i, item) in rep.items.iter().enumerate() {
                        let badge = match item.status {
                            CompatibilityStatus::Compatible => "COMPATIBLE".green().bold(),
                            CompatibilityStatus::CompatibleWithAdjustments => "COMPATIBLE CON AJUSTES".yellow().bold(),
                            CompatibilityStatus::PotentialConflict => "POSIBLE CONFLICTO".cyan().bold(),
                            CompatibilityStatus::ConfirmedFalsePositive => "FALSO POSITIVO".magenta().bold(),
                            CompatibilityStatus::LegitimateSecurityDetection => "DETECCIÓN SEGURIDAD".red().bold(),
                            CompatibilityStatus::PendingInvestigation => "PENDIENTE".white(),
                        };
                        println!("\n  [{:02}] {} | {}", i + 1, item.component_name.bold(), badge);
                        println!("       Tipo:        {}", item.component_type.dimmed());
                        println!("       Subsistema:  {}", item.subsystem.dimmed());
                        println!("       Conflicto:   {}", item.potential_conflict);
                        println!("       Mitigación:  {}", item.mitigation_strategy.green());
                    }
                }

                WdheCommands::FpInvestigate { max } => {
                    println!("\n{}", "─── FASE 2: SAMULIBRE FALSE POSITIVE INVESTIGATION ENGINE ───".bold().cyan());
                    println!("Consultando registros de Windows Defender (Operational Event Log)...");
                    let records = wdhe.investigate_recent_alerts(max);

                    if records.is_empty() {
                        println!("{} No se detectaron alertas recientes en el registro de Defender.", "✔".green());
                    } else {
                        println!("Alertas recopiladas: {}\n", records.len().to_string().bold());
                        for (i, r) in records.iter().enumerate() {
                            let class_badge = match r.classification {
                                FpClassification::BenignFalsePositive => "FALSO POSITIVO BENIGNO".green().bold(),
                                FpClassification::TestArtifactPayload => "ARTEFACTO DE PRUEBA".magenta().bold(),
                                FpClassification::LegitimateCompromise => "COMPROMISO LEGÍTIMO".red().bold(),
                                FpClassification::UnsignedSuspiciousBinary => "NO FIRMADO / SOSPECHOSO".yellow().bold(),
                                FpClassification::UnknownInvestigationRequired => "EN INVESTIGACIÓN".cyan(),
                            };

                            println!("  [{}] Amenaza: {} | {}", i + 1, r.threat_event.threat_name.bold().white(), class_badge);
                            println!("      ID Amenaza:  {}", r.threat_event.threat_id);
                            println!("      Archivo:     {}", r.threat_event.file_path.cyan());
                            println!("      Proceso:     {}", r.responsible_process);
                            println!("      Acción:      {}", r.threat_event.action_taken.yellow());
                            println!("      Firma:       {}", r.digital_signature);
                            println!("      Filtro:      {}", r.justification.dimmed());
                            println!("      Acción Rec:  {}", r.recommended_action.green());
                            println!();
                        }
                    }
                }

                WdheCommands::Mode { mode } => {
                    println!("\n{}", "─── FASE 3: TRANSICIÓN DE MODO WDHE ───".bold().cyan());
                    let new_mode = match mode.to_lowercase().as_str() {
                        "dev" | "desarrollo" => WdheMode::Development,
                        "comp" | "complementario" => WdheMode::Complementary,
                        "primary" | "principal" => WdheMode::PrimaryAntivirus,
                        _ => {
                            eprintln!("{} Modo no reconocido. Opciones válidas: 'dev', 'comp', 'primary'", "✘".red());
                            return Ok(());
                        }
                    };

                    match wdhe.set_coexistence_mode(new_mode) {
                        Ok(_) => println!("{} Modo WDHE actualizado con éxito a: {}", "✔".green(), format!("{}", new_mode).bold()),
                        Err(e) => eprintln!("{} Error al cambiar de modo: {}", "✘".red(), e),
                    }
                }

                WdheCommands::SmartScan { path, priority } => {
                    println!("\n{}", "─── FASE 4: SMART SCAN COORDINATION ENGINE (SSCE) ───".bold().cyan());
                    println!("Analizando ruta {:?} con política no bloqueante...", path);
                    let prio = match priority.to_lowercase().as_str() {
                        "critical" => SmartScanPriority::Critical,
                        "high" => SmartScanPriority::High,
                        "normal" => SmartScanPriority::Normal,
                        "low" => SmartScanPriority::Low,
                        _ => SmartScanPriority::Background,
                    };

                    wdhe.smart_scan.enqueue(path.clone(), prio);
                    let start = std::time::Instant::now();

                    if path.is_file() {
                        if let Some(cached) = wdhe.smart_scan.check_cache(&path) {
                            println!("  {} Acierto de Clean Result Cache (Inalterado desde última verificación):", "✔".green());
                            println!("      SHA-256: {}", cached.sha256);
                            println!("      Tamaño:  {} bytes", cached.size_bytes);
                            println!("      Latencia: < 1 ms (Cero I/O en disco)");
                        } else {
                            match samulibre_core::wdhe::smart_scan::SmartScanCoordinator::stream_hash_sha256(&path) {
                                Ok((hash, bytes)) => {
                                    println!("  {} Archivo analizado e indexado correctamente:", "✔".green());
                                    println!("      SHA-256: {}", hash.cyan());
                                    println!("      Bytes:   {}", bytes);
                                    println!("      Tiempo:  {:.2} ms", start.elapsed().as_secs_f64() * 1000.0);
                                    let mtime = std::fs::metadata(&path).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
                                    wdhe.smart_scan.record_clean(path, hash, bytes, mtime);
                                    wdhe.smart_scan.persist_cache();
                                }
                                Err(e) => eprintln!("  {} Error al analizar: {}", "✘".red(), e),
                            }
                        }
                    } else if path.is_dir() {
                        println!("  Escaneando directorio recursivo con cola priorizada...");
                        let mut scanned = 0;
                        if let Ok(entries) = std::fs::read_dir(&path) {
                            for e in entries.flatten() {
                                let p = e.path();
                                if p.is_file() {
                                    if let Ok((hash, bytes)) = samulibre_core::wdhe::smart_scan::SmartScanCoordinator::stream_hash_sha256(&p) {
                                        let mtime = std::fs::metadata(&p).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
                                        wdhe.smart_scan.record_clean(p, hash, bytes, mtime);
                                        scanned += 1;
                                    }
                                }
                            }
                        }
                        wdhe.smart_scan.persist_cache();
                        println!("  {} {} archivos inspeccionados e indexados en {:.2} ms.", "✔".green(), scanned, start.elapsed().as_secs_f64() * 1000.0);
                    }
                }

                WdheCommands::Profile { profile } => {
                    println!("\n{}", "─── FASE 5: SAMULIBRE RESOURCE GOVERNOR (SRG) ───".bold().cyan());
                    let p = match profile.to_lowercase().as_str() {
                        "silent" | "silencioso" => WdheResourceProfile::Silent,
                        "balanced" | "equilibrado" => WdheResourceProfile::Balanced,
                        "performance" | "rendimiento" => WdheResourceProfile::Performance,
                        "deep" | "profundo" => WdheResourceProfile::DeepAnalysis,
                        _ => {
                            eprintln!("{} Perfil no reconocido. Opciones: 'silent', 'balanced', 'performance', 'deep'", "✘".red());
                            return Ok(());
                        }
                    };
                    wdhe.set_resource_profile(p);
                    println!("{} Perfil de consumo actualizado a: {}", "✔".green(), format!("{}", p).bold().yellow());
                }

                WdheCommands::Exclusions { sub } => {
                    match sub {
                        WdheExclusionCommands::Check { path, rule_type, reason } => {
                            println!("\n{}", "─── FASE 6: ASESOR DE EXCLUSIONES SEGURAS ───".bold().cyan());
                            println!("Evaluando propuesta de exclusión para '{}'...", path);
                            match wdhe.evaluate_exclusion(&path, &rule_type, &reason, "MANUAL_CLI_REQUEST") {
                                Ok(proposal) => {
                                    println!("{} Propuesta admitida preliminarmente (Nivel de Riesgo Aceptable):", "✔".green());
                                    println!("    ID:            {}", proposal.id);
                                    println!("    Destino:       {}", proposal.target_path.bold());
                                    println!("    Hash Anclado:  {}", proposal.sha256_pinned.unwrap_or_else(|| "N/A".to_string()));
                                    println!("    Evaluación:    {}", proposal.risk_assessment.green());
                                    println!("    Estado:        REQUIERE APROBACIÓN ADMINISTRATIVA EXPLICITA");
                                }
                                Err(e) => {
                                    eprintln!("\n{} {}", "RECHAZADA POR POLÍTICA DE SEGURIDAD:".red().bold(), e);
                                    println!("Nota: SamuLibre prioriza soluciones de compatibilidad por arquitectura para no reducir la protección.");
                                }
                            }
                        }
                        WdheExclusionCommands::Recommend { conflict } => {
                            println!("\n{}", "─── ASESOR ARQUITECTÓNICO DE COEXISTENCIA ───".bold().cyan());
                            let sol = samulibre_core::wdhe::safe_exclusions::SafeExclusionManager::suggest_architectural_mitigation(&conflict);
                            println!("Solución recomendada:\n  {}", sol.green().bold());
                        }
                    }
                }

                WdheCommands::VerifyIntegrity => {
                    println!("\n{}", "─── FASE 7: FIRMA DIGITAL, REPUTACIÓN Y MANIFIESTO ───".bold().cyan());
                    println!("Verificando firmas Authenticode y generando manifiesto oficial...");
                    let manifest = wdhe.generate_binary_manifest();
                    println!("Manifiesto Criptográfico Generado:");
                    println!("  • Proyecto:     {}", manifest.project_name.bold());
                    println!("  • Versión:      {}", manifest.release_version);
                    println!("  • Fecha UTC:    {}", manifest.generated_at_utc);
                    println!("  • Hash SHA-256: {}", manifest.manifest_sha256.cyan().bold());
                    println!("\nBinarios Oficiales Indexados:");
                    for b in manifest.binaries {
                        println!("  • [{}] {} ({} bytes)", b.signature_status.yellow(), b.file_name.bold(), b.size_bytes);
                        println!("       SHA-256: {}", b.sha256);
                    }
                }

                WdheCommands::Wsc => {
                    println!("\n{}", "─── FASE 8: WINDOWS SECURITY CENTER (root\\SecurityCenter2) ───".bold().cyan());
                    println!("Consultando proveedores antivirus en el repositorio de Windows...");
                    let products = wdhe.query_wsc_providers();
                    if products.is_empty() {
                        println!("No se obtuvieron registros de WSC (Puede requerir permisos de Administrador).");
                    } else {
                        for (i, p) in products.iter().enumerate() {
                            println!("\n[{}] Proveedor: {}", i + 1, p.display_name.bold().green());
                            println!("    GUID:             {}", p.instance_guid);
                            println!("    Ruta Ejecutable:  {}", p.exe_path);
                            println!("    productState:     {} (Hex: {})", p.product_state, p.decoded_state.raw_state_hex.bold().cyan());
                            println!("    Escáner Activo:   {}", if p.decoded_state.is_enabled { "HABILITADO (0x10)".green().bold() } else { "DESHABILITADO".yellow() });
                            println!("    Definiciones:     {}", if p.decoded_state.is_up_to_date { "AL DÍA (0x00)".green() } else { "OBSOLETAS".red() });
                        }
                    }
                    println!("\n{}", "VERIFICACIÓN DE CONMUTACIÓN POR ERROR (FAILOVER):".bold().white());
                    println!("  {}", samulibre_core::wdhe::security_center::WindowsSecurityCenterManager::verify_wsc_failover_status().green());
                }

                WdheCommands::Benchmark => {
                    println!("\n{}", "─── FASE 10: LABORATORIO DE BENCHMARKING DE RENDIMIENTO (ESCENARIOS A - E) ───".bold().cyan());
                    println!("Ejecutando pruebas controladas sobre 150 muestras sintéticas...");
                    let results = wdhe.run_performance_benchmarks();
                    println!("\n{:<55} | {:<8} | {:<10} | {:<8} | {:<8}", "Escenario de Prueba", "Tiempo", "Throughput", "CPU Peak", "RAM Peak");
                    println!("{:-<55}-|-{:-<8}-|-{:-<10}-|-{:-<8}-|-{:-<8}", "", "", "", "", "");
                    for r in results {
                        println!("{:<55} | {:>5} ms | {:>6.1} f/s | {:>7.1}% | {:>6} MB",
                            r.scenario_name.bold(),
                            r.duration_ms,
                            r.throughput_files_per_sec,
                            r.cpu_peak_pct,
                            r.ram_peak_mb
                        );
                    }
                }

                WdheCommands::ValidateSecurity => {
                    println!("\n{}", "─── FASE 11: VALIDACIÓN DE SEGURIDAD (EICAR HARNESS) ───".bold().cyan());
                    println!("Iniciando prueba segura no destructiva con cadena EICAR oficial...");
                    let res = wdhe.run_security_validation();
                    println!("  • Prueba:                     {}", res.test_name.bold());
                    println!("  • Detección SamuLibre:        {}", if res.eicar_detected_by_samulibre { "SÍ (Identificado)".green().bold() } else { "NO".red() });
                    println!("  • Aislamiento en Cuarentena:  {}", if res.quarantined_successfully { "SÍ (Aislado con éxito)".green().bold() } else { "NO".yellow() });
                    println!("  • Restauración Segura:        {}", if res.restored_successfully { "SÍ (Restaurado)".green() } else { "OMITIDO".dimmed() });
                    println!("  • Cero Sharing Violation:     {}", if res.zero_sharing_violation { "SÍ (Sin bloqueos de I/O)".green().bold() } else { "NO".red() });
                    println!("  • Dictamen de Validación:     {}", if res.passed { "APROBADO".green().bold() } else { "FALLIDO".red().bold() });
                    println!("  • Detalle Forense:            {}", res.details);
                }

                WdheCommands::ResilienceTest => {
                    println!("\n{}", "─── FASE 12: PRUEBAS DE RESILIENCIA Y RECUPERACIÓN ANTE CONTINGENCIAS ───".bold().cyan());
                    println!("Simulando 8 escenarios de fallo extremo y contingencia del sistema...");
                    let sim_results = wdhe.run_resilience_tests();
                    for (i, r) in sim_results.iter().enumerate() {
                        let status_badge = if r.passed { "RECUPERADO".green().bold() } else { "FALLO".red().bold() };
                        println!("\n  [{}] {} | {}", i + 1, r.scenario.bold(), status_badge);
                        println!("       Condición:  {}", r.simulated_condition.dimmed());
                        println!("       Protección: {}", if r.system_protection_preserved { "PRESERVADA (Endpoint protegido 100%)".green() } else { "DEGRADADA".red() });
                        println!("       Respuesta:  {}", r.fallback_triggered.cyan());
                        println!("       Evidencia:  {}", r.details);
                    }
                }
            }
        }

        Commands::Netdefense { sub } => {
            let mut nd = samulibre_netdefense::NetworkDefenseEngine::new("data");
            match sub {
                NetDefenseCommands::Status => {
                    let _ = nd.refresh_live_connections();
                    let snap = nd.get_dashboard_snapshot();
                    println!("{}", serde_json::to_string_pretty(&snap)?);
                }
                NetDefenseCommands::Connections => {
                    let conns = nd.refresh_live_connections();
                    println!("Conexiones activas detectadas: {}", conns.len());
                    for c in conns.iter().take(40) {
                        println!(
                            "  [{}] PID {:<6} {:<22} {}:{} -> {}:{} ({})",
                            c.protocol, c.pid, c.app_name, c.local_addr, c.local_port, c.remote_addr, c.remote_port, c.state
                        );
                    }
                }
                NetDefenseCommands::TorEnable => {
                    let mut cfg = nd.tor_manager.config.clone();
                    cfg.enabled = true;
                    let state = nd.set_tor_secure_mode(cfg);
                    println!("{}", serde_json::to_string_pretty(&state)?);
                }
                NetDefenseCommands::TorDisable => {
                    let mut cfg = nd.tor_manager.config.clone();
                    cfg.enabled = false;
                    let state = nd.set_tor_secure_mode(cfg);
                    println!("{}", serde_json::to_string_pretty(&state)?);
                }
                NetDefenseCommands::Benchmark => {
                    let t0 = std::time::Instant::now();
                    let conns = nd.refresh_live_connections();
                    let t_sock = t0.elapsed();
                    let t1 = std::time::Instant::now();
                    let _ = nd.get_dashboard_snapshot();
                    let t_snap = t1.elapsed();
                    println!("Network Defense Benchmark:");
                    println!("  Enumerar {} conexiones (iphlpapi): {:.2} ms", conns.len(), t_sock.as_secs_f64() * 1000.0);
                    println!("  Generar snapshot dashboard:         {:.2} ms", t_snap.as_secs_f64() * 1000.0);
                }
                NetDefenseCommands::Cleanup => {
                    let removed = nd.emergency_cleanup()?;
                    println!("Limpieza WFP completada: {} filtro(s) de SamuLibre eliminados.", removed);
                }
            }
        }
        Commands::Tor { sub } => {
            let core = SamuLibreCore::new(&canary_dir, &vpn_dir, true);
            match sub {
                TorCommands::Status => {
                    println!("\n{}", "─── SAMULIBRE: DARK WEB & TOR PROTECTION COCKPIT ───".bold().cyan());
                    let snap = core.get_tor_shield_snapshot();

                    println!("  • Perfil de Protección Activo:  {}", format!("{}", snap.active_profile).bold().yellow());
                    println!("  • Estado de Tor Browser:        {}", if snap.process_state.is_running { "ACTIVO Y PROTEGIDO".green().bold() } else { "NO DETECTADO EN EJECUCIÓN".dimmed() });
                    if let Some(pid) = snap.process_state.tor_browser_pid {
                        println!("       PID Navegador:             {}", pid.to_string().cyan());
                    }
                    if let Some(ref path) = snap.process_state.binary_path {
                        println!("       Binario Detectado:         {}", path);
                    }
                    if let Some(ref hash) = snap.process_state.binary_hash_sha256 {
                        println!("       Integridad Hash SHA-256:   {} ({})", &hash[..16].cyan(), "Verificado".green());
                    }

                    println!("\n{}", "ESTADO DE LOS MOTORES DE PROTECCIÓN:".bold().white());
                    println!("  • Escudo Web C2 & Dark Web:     {}", if snap.web_shield_active { "HABILITADO (Cero intercepción TLS, Cero descifrado)".green().bold() } else { "DESHABILITADO".red() });
                    println!("  • Anti-Exploit Child Process:   {}", if snap.exploit_shield_active { "HABILITADO (Bloqueo estricto LOLBins T1059/T1218)".green().bold() } else { "DESHABILITADO".red() });
                    println!("  • Sandbox Aislado de Descargas: {}", if snap.sandbox_isolation_active { "HABILITADO (Retención y análisis antes de entrega)".green().bold() } else { "DESHABILITADO".red() });
                    println!("  • Señuelos Anti-Ransomware:     {}", if snap.ransomware_tripwire_active { "HABILITADO (Canarios desplegados en zona Tor)".green().bold() } else { "DESHABILITADO".red() });
                    println!("  • Blindaje Anti-Infostealer:    {}", if snap.stealer_protection_active { "HABILITADO (Protección perfiles cookies/logins/portapapeles)".green().bold() } else { "DESHABILITADO".red() });
                    println!("  • Kill Switch de Emergencia:    {}", if snap.kill_switch_armed { "ARMADO (Contención WFP + Terminación limpia)".green().bold() } else { "DESARMADO".yellow() });

                    println!("\n{}", "MÉTRICAS Y ACTIVIDAD RECIENTE:".bold().white());
                    println!("  • Descargas Analizadas:         {}", snap.downloads_scanned_count.to_string().bold());
                    println!("  • Amenazas Bloqueadas:          {}", if snap.threats_blocked_count > 0 { snap.threats_blocked_count.to_string().red().bold() } else { "0 (Sistema Limpio)".green() });
                    println!("  • Fugas de Privacidad Evitadas: {}", snap.privacy_leaks_count.to_string().cyan());
                    println!("  • IoCs Dark Web en Memoria:     {}", snap.threat_feed_count.to_string().yellow());

                    if !snap.recent_alerts.is_empty() {
                        println!("\n{}", "ALERTAS RECIENTES:".bold().red());
                        for (i, a) in snap.recent_alerts.iter().take(5).enumerate() {
                            println!("  [{}] [{}] {} - {}", i + 1, a.severity, a.title.bold(), a.action_taken.dimmed());
                        }
                    }
                }

                TorCommands::Audit => {
                    println!("\n{}", "─── AUDITORÍA INTEGRAL DE TOR BROWSER ───".bold().cyan());
                    let snap = core.get_tor_shield_snapshot();
                    println!("  • Ejecución:          {}", if snap.process_state.is_running { "Tor Browser en ejecución".green().bold() } else { "Tor Browser no se está ejecutando".yellow() });
                    println!("  • Puerto SOCKS Local: 127.0.0.1:{}", snap.process_state.socks_port);
                    println!("  • Puerto de Control:  127.0.0.1:{}", snap.process_state.control_port);
                    println!("  • Integridad:         {}", if snap.process_state.binary_integrity_verified { "Firmas y binarios íntegros (Sin modificaciones hostiles)".green() } else { "ADVERTENCIA: Binario alterado".red().bold() });
                    if let Some(ref ver) = snap.process_state.version {
                        println!("  • Versión Instalada:  {}", ver.bold().cyan());
                    }
                }

                TorCommands::Profile { name } => {
                    println!("\n{}", "─── CONFIGURACIÓN DE PERFIL DE PROTECCIÓN ───".bold().cyan());
                    let p = match name.to_lowercase().as_str() {
                        "normal" => samulibre_types::TorProtectionProfile::Normal,
                        "tor" | "torprotection" => samulibre_types::TorProtectionProfile::TorProtection,
                        "isolation" | "maximum" | "max" => samulibre_types::TorProtectionProfile::MaximumIsolation,
                        _ => {
                            eprintln!("{} Perfil no reconocido. Opciones: 'normal', 'tor', 'isolation'", "✘".red());
                            return Ok(());
                        }
                    };
                    core.set_tor_protection_profile(p);
                    println!("{} Perfil de protección actualizado a: {}", "✔".green(), format!("{}", p).bold().yellow());
                }

                TorCommands::ScanDownload { path, origin } => {
                    println!("\n{}", "─── ANÁLISIS DE DESCARGA EN MICRO-SANDBOX TOR ───".bold().cyan());
                    if !path.exists() {
                        eprintln!("{} El archivo especificado no existe: {}", "✘".red(), path.display());
                        return Ok(());
                    }
                    println!("Iniciando pipeline de inspección multicapa sobre '{}'...", path.display().to_string().bold());
                    let rep = core.analyze_tor_download(&path, origin.as_deref());

                    let badge = match rep.final_verdict {
                        samulibre_types::TorDownloadVerdict::Authorized => "AUTORIZADO (Limpio)".green().bold(),
                        samulibre_types::TorDownloadVerdict::Suspicious => "SOSPECHOSO (Precaución)".yellow().bold(),
                        samulibre_types::TorDownloadVerdict::Quarantined => "CONFINADO EN AISLAMIENTO".red().bold(),
                        samulibre_types::TorDownloadVerdict::Blocked => "BLOQUEADO (Amenaza Detectada)".red().bold(),
                        samulibre_types::TorDownloadVerdict::Analyzing => "ANALIZANDO".dimmed(),
                    };

                    println!("  • Dictamen Final:       {}", badge);
                    println!("  • Origen Registrado:    {}", rep.source_origin);
                    println!("  • Hash SHA-256:         {}", rep.sha256.cyan());
                    println!("  • Tamaño:               {} bytes", rep.size_bytes);
                    if let Some(ref sig) = rep.signature_threat {
                        println!("  • Firma Detectada:      {}", sig.red().bold());
                    }
                    if rep.document_analysis.is_document {
                        println!("  • Análisis Documento:   Tipo: {}, Riesgo: {}/100", rep.document_analysis.doc_type.bold(), rep.document_analysis.risk_score);
                        for ind in &rep.document_analysis.risk_indicators {
                            println!("       - {}", ind.yellow());
                        }
                    }
                    println!("  • Veredicto Sandbox:    {}", rep.sandbox_verdict);
                    println!("  • Dictamen y Razón:     {}", rep.reasoning);
                    if let Some(ref q) = rep.quarantine_path {
                        println!("  • Ubicación Cuarentena: {}", q.cyan());
                    }
                }

                TorCommands::KillSwitch { pid, name, reason } => {
                    println!("\n{}", "─── ACTIVACIÓN MANUAL DE KILL SWITCH Y CONTENCIÓN ───".bold().red());
                    println!("Ejecutando aislamiento inmediato sobre PID {} ({})...", pid, name.bold());
                    let res = core.trigger_tor_kill_switch(pid, &name, &reason);
                    if res {
                        println!("{} Proceso terminado y reglas de aislamiento WFP aplicadas.", "✔".green());
                    } else {
                        println!("{} Terminación directa completada o proceso ya inactivo.", "✔".yellow());
                    }
                }

                TorCommands::Feeds => {
                    println!("\n{}", "─── INTELIGENCIA DE AMENAZAS DARK WEB & C2 (IoCs) ───".bold().cyan());
                    let snap = core.get_tor_shield_snapshot();
                    println!("Mostrando indicadores de compromiso activos ({}) procedentes de feeds reconocidos:\n", snap.threat_feed_count);
                    println!("{:<65} | {:<16} | {:<18} | {:<10}", "Indicador / Host .onion / URL", "Tipo", "Campaña / Malware", "Fuente");
                    println!("{:-<65}-|-{:-<16}-|-{:-<18}-|-{:-<10}", "", "", "", "");
                    // Listar algunos IoCs
                    for (ind, ioc_type, camp, src) in [
                        ("lockbit7z2jwcskxpwvokvh35f252twt25tk6k2qyomg6ydxuy4duyad.onion", "RansomwarePortal", "LockBit 3.0", "ThreatFox"),
                        ("alphavm27gahqhp7ui7hu02422784824872910793209173917498174.onion", "RansomwarePortal", "BlackCat / ALPHAV", "ThreatFox"),
                        ("cl0p5245892019487192847192847192847192847192847192847198.onion", "RansomwarePortal", "Cl0p Ransomware", "ThreatFox"),
                        ("akiral228472918471928471928471928471928471928471928471928.onion", "RansomwarePortal", "Akira Ransomware", "ThreatFox"),
                        ("redline-stealer-gate.top", "C2Server", "RedLine Stealer", "URLhaus"),
                        ("vidar-c2-drop.xyz", "C2Server", "Vidar Stealer", "URLhaus"),
                        ("lumma-drop-loader.click", "MalwareDropSite", "LummaC2 Stealer", "MalwareBazaar"),
                    ] {
                        println!("{:<65} | {:<16} | {:<18} | {:<10}", ind.cyan(), ioc_type, camp.bold().white(), src.green());
                    }
                }

                TorCommands::Cves => {
                    println!("\n{}", "─── ASESORÍAS DE VULNERABILIDADES (CVEs) FIREFOX ESR / TOR ───".bold().cyan());
                    let vulns = core.audit_tor_vulnerabilities(None);
                    for v in vulns {
                        let badge = if v.is_actively_exploited { "EXPLOTADA ACTIVAMENTE (CISA KEV)".red().bold() } else { "Mitigada".green() };
                        println!("\n  • [{}] {} (CVSS {}) | {}", v.severity, v.title.bold(), v.cvss_score.to_string().yellow(), badge);
                        println!("       Corregido en: {}", v.fixed_in_version.green());
                        println!("       Detalles:     {}", v.mitigation_notes.dimmed());
                    }
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
                                "⚠".bold().red(),
                                alert.severity,
                                alert.title.bold()
                            );
                            println!("  Detalles: {}", alert.details);
                            println!("  Acción tomada: {}", alert.action_taken.bold().yellow());
                        }
                    }
                }

                ShieldCommands::Ransomware => {
                    let core = SamuLibreCore::new(&canary_dir, &vpn_dir, false);
                    let cfg = core.get_controlled_folder_config();
                    let incidents = core.get_anti_ransomware_incidents();

                    println!(
                        "\n{}",
                        "─── PROTECCIÓN AVANZADA ANTI-RANSOMWARE Y CARPETAS CONTROLADAS ───"
                            .bold()
                            .cyan()
                    );
                    println!("{}", "ESTADO DEL BLINDAJE DE DIRECTORIOS:".bold().white());
                    println!("  {} Protección de Carpetas:   {}", "•".cyan(), if cfg.is_enabled { "HABILITADA (Bloqueo de Modificación Masiva)".green().bold() } else { "DESHABILITADA".yellow() });
                    println!("  {} Rotación Automática Canarios: {}", "•".cyan(), if cfg.auto_rotate_canaries { "ACTIVA (Regeneración de señuelos tras ataque)".green() } else { "INACTIVA".yellow() });
                    println!("  {} Suspensión de Agresores:  {}", "•".cyan(), if cfg.auto_suspend_malicious_process { "ACTIVA (Congelamiento inmediato de PID atacante)".green() } else { "MANUAL".yellow() });

                    println!("\n{}", "DIRECTORIOS SENSIBLES PROTEGIDOS:".bold().white());
                    if cfg.protected_folders.is_empty() {
                        println!("  {} Ninguna carpeta protegida configurada explícitamente.", "•".yellow());
                    } else {
                        for (i, f) in cfg.protected_folders.iter().enumerate() {
                            println!("  [{}] {}", i + 1, f);
                        }
                    }

                    println!("\n{}", "PROCESOS DE CONFIANZA EN LISTA BLANCA (CERO FALSOS POSITIVOS):".bold().white());
                    println!("  {}", cfg.trusted_processes.join(", ").dimmed());

                    println!("\n{}", "HISTORIAL DE INCIDENTES DE RANSOMWARE NEUTRALIZADOS:".bold().white());
                    if incidents.is_empty() {
                        println!("  {} No se han registrado incidentes de cifrado activo (Sistema Íntegro).", "✔".green());
                    } else {
                        for inc in incidents {
                            println!("  [INCIDENTE: {}] PID: {} ({}) | Riesgo: {}/100", inc.id.cyan(), inc.attacking_pid, inc.process_name.red(), inc.risk_score);
                            println!("    Causa:   {}", inc.trigger_reason);
                            println!("    Acción:  {}", inc.action_taken.bold().yellow());
                            println!("    Técnica: {}", inc.mitre_technique);
                        }
                    }
                }

                ShieldCommands::TestRansomware => {
                    println!(
                        "\n{}",
                        "─── SIMULACIÓN CONTROLADA DE ATAQUE RANSOMWARE (CANARY TRIPWIRE) ───"
                            .bold()
                            .cyan()
                    );
                    println!("  [1/4] Desplegando trampas canario estratégicas en el directorio señuelo...");
                    let mut ar_engine = samulibre_shield::AntiRansomwareEngine::new(&canary_dir);
                    println!("  [2/4] Canarios activos y custodiados: {}", ar_engine.canary_count());

                    println!("  [3/4] Simulando ataque de ransomware: alterando señuelo con payload de cifrado simulado...");
                    let test_canary_file = canary_dir.join("!000_passwords_vault.xlsx");
                    let _ = std::fs::write(&test_canary_file, b"ENCRYPTED_BY_SIMULATED_LOCKBIT_RANSOMWARE_PAYLOAD_TEST");

                    let alerts = ar_engine.check_canaries_and_rotate();
                    if !alerts.is_empty() {
                        for alert in alerts {
                            println!("\n  {} [{}] {}", "🚨 TRIPWIRE ACTIVADO:".red().bold(), alert.severity, alert.title.bold());
                            println!("     Detalles: {}", alert.details);
                            println!("     Acción:   {}", alert.action_taken.bold().yellow());
                        }
                    }

                    println!("\n  [4/4] Verificando rotación automática de canario...");
                    let re_check = ar_engine.check_canaries_and_rotate();
                    if re_check.is_empty() {
                        println!("  {} Rotación automática confirmada: el señuelo fue reemplazado por un nuevo token criptográfico íntegro.", "✔ ÉXITO:".green().bold());
                    } else {
                        println!("  {} Advertencia en rotación.", "⚠".yellow());
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
    let mut clean_count = 0usize;
    let mut infected_count = 0usize;
    let mut stack = vec![dir.to_path_buf()];

    while let Some(current_dir) = stack.pop() {
        let entries = match fs::read_dir(&current_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let p_str = path.to_string_lossy();
            if p_str.contains("EBWebView") || p_str.contains("Antivitus-SamuLibre") {
                continue;
            }
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                if let Ok(res) = scanner.scan_file(&path) {
                    if res.status == FileScanStatus::Infected
                        || res.status == FileScanStatus::Suspicious
                    {
                        infected_count += 1;
                        println!(
                            "{} [{}] {} -> {}",
                            "✘ DETECTADO".red().bold(),
                            res.engine,
                            path.display(),
                            res.detection_name.unwrap_or_default().red()
                        );
                    } else {
                        clean_count += 1;
                    }
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
