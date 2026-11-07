# SAMULIBRE: HOJA DE RUTA Y EVOLUCIÓN TÉCNICA (ROADMAP)
## Plan Estratégico de Desarrollo, Transición al Kernel y Fortalecimiento EDR para Windows

---

### 1. Visión Estratégica

Convertir a SamuLibre en el referente mundial de soluciones de seguridad para endpoints 100% de código abierto, privadas y soberanas para el ecosistema Windows. La meta es evolucionar desde un antivirus de espacio de usuario de alta velocidad hacia una plataforma EDR/XDR completa con soporte de kernel certificado.

---

### 2. Cronograma de Fases de Desarrollo

```
  [Fase 1: Q1 2027]          [Fase 2: Q2 2027]          [Fase 3: Q3-Q4 2027]
  Servicio Windows NT        Telemetría ETW &           Controlador Minifiltro
  & Hardening Local          Comportamiento EDR         Kernel-Mode (fltMgr.sys)
         │                          │                          │
         ▼                          ▼                          ▼
• Crate windows-service    • ETW Microsoft-Windows-   • Driver C / Rust-for-Windows
• SCM callbacks            • Auditoría LSASS OpenProcess • Intercepción IRP_MJ_CREATE
• Ejecución en Winlogon    • Detección DLL Hollow     • Firma EV & WHQL
• IPC local por Named Pipe • Correlación de procesos  • Pre-execution denial
```

---

### 3. Detalle de Fases de Evolución

#### Fase 1: Integración con Service Control Manager (Windows NT Service)
- **Objetivo:** Garantizar que la protección en tiempo real opere de forma continua sin depender del inicio de sesión de un usuario interactivo.
- **Entregables:**
  - Creación de un subproceso o binario de servicio `samulibred.exe` compatible con el SCM de Windows.
  - Implementación de callbacks `SERVICE_START`, `SERVICE_STOP`, `SERVICE_PAUSE` mediante el crate oficial `windows-service`.
  - Canal de comunicación local seguro (Named Pipe con DACL restringida) entre la interfaz gráfica de usuario y el servicio de fondo.
  - Configuración de políticas de recuperación automática del servicio ante fallos (`SERVICE_FAILURE_ACTIONS`).

#### Fase 2: Telemetría Avanzada por ETW (Event Tracing for Windows)
- **Objetivo:** Detectar inyecciones en memoria, robo de credenciales y movimiento lateral sin necesidad de hooks invasivos en espacio de usuario.
- **Entregables:**
  - Suscripción al proveedor de eventos `Microsoft-Windows-Threat-Intelligence` y `Microsoft-Windows-Kernel-Process`.
  - Detección en tiempo real de apertura de descriptores sospechosos hacia `lsass.exe` (`PROCESS_VM_READ` / `PROCESS_QUERY_LIMITED_INFORMATION`).
  - Detección de comandos en memoria mediante eventos AMSI del sistema operativo (`Microsoft-Antimalware-Scan-Interface`).
  - Detección de creación de servicios no autorizados y tareas programadas anómalas.

#### Fase 3: Controlador de Filtro de Sistema de Archivos en Kernel (`Minifilter`)
- **Objetivo:** Proporcionar bloqueo previo a la ejecución (*Pre-Execution Interception*).
- **Entregables:**
  - Desarrollo de un driver minifiltro basado en el Windows Filter Manager (`FltRegisterFilter`).
  - Intercepción de operaciones `IRP_MJ_CREATE` e `IRP_MJ_WRITE`.
  - Denegación de acceso (`STATUS_ACCESS_DENIED`) antes de que el archivo toque el disco o se devuelva el handle al proceso solicitante.
  - Certificación de controladores mediante Microsoft Hardware Dev Center (WHQL) y firma digital con certificado EV.

#### Fase 4: Micro-Sandbox Contenedorizado por Hardware (Hyper-V / Windows Sandbox)
- **Objetivo:** Permitir la ejecución dinámica de muestras desconocidas en un entorno completamente estéril e independiente del host.
- **Entregables:**
  - Integración mediante APIs COM de Windows Sandbox (`WindowsSandbox.exe`).
  - Generación dinámica de archivos de configuración `.wsb` con acceso a disco estrictamente de solo lectura y aislamiento total de red.
  - Recolección automática de artefactos volátiles generados y análisis diferencial de registro tras la finalización del sandbox.

#### Fase 5: Red Comunitaria de Inteligencia y Reputación P2P
- **Objetivo:** Actualización descentralizada de indicadores de compromiso sin intermediarios centralizados.
- **Entregables:**
  - Sincronización P2P distribuida de hashes mediante protocolos libres.
  - Enriquecimiento con fuentes de inteligencia abiertas adicionales (AbuseIPDB, OTX AlienVault, MISP).
  - Consenso criptográfico de firmas para evitar envenenamiento de bases de datos de reputación.
