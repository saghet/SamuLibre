# SAMULIBRE: ARQUITECTURA GENERAL DEL SISTEMA
## Documento Maestro de Diseño, Topología de Crates, Flujos de Datos y Ciclo de Vida de Amenazas

---

### 1. Visión General del Sistema

SamuLibre es una solución modular de código abierto desarrollada en Rust (edición 2021) concebida para brindar capacidades avanzadas de protección de endpoints (EPP/EDR) en entornos Windows, Linux y Android.

El diseño sigue una separación estricta de responsabilidades en 11 crates independientes dentro de un espacio de trabajo Cargo, garantizando alta cohesión, bajo acoplamiento, ausencia de dependencias circulares y ejecución segura en espacio de usuario.

---

### 2. Topología de Crates y Relaciones de Dependencia

```
                           ┌───────────────────────────────┐
                           │      samulibre-gui / cli      │
                           └───────────────┬───────────────┘
                                           │
                           ┌───────────────▼───────────────┐
                           │        samulibre-core         │
                           └───────┬───────────────┬───────┘
                                   │               │
        ┌──────────────────────────┼───────────────┼──────────────────────────┐
        ▼                          ▼               ▼                          ▼
┌───────────────┐          ┌───────────────┐ ┌───────────────┐        ┌───────────────┐
│samulibre-     │          │samulibre-     │ │samulibre-     │        │samulibre-     │
│watcher        │          │scanner        │ │shield         │        │patcher        │
└───────┬───────┘          └───────┬───────┘ └───────┬───────┘        └───────┬───────┘
        │                          │                 │                        │
        └──────────────────────────┼─────────────────┼────────────────────────┘
                                   │                 │
                                   ▼                 ▼
                           ┌───────────────────────────────┐
                           │        samulibre-types        │
                           └───────────────────────────────┘
```

#### Descripción Detallada de Módulos:

| Crate | Responsabilidad Principal | Tecnologías y Librerías Clave |
|---|---|---|
| `samulibre-types` | Esquemas de datos comunes, veredictos (5 niveles), categorías de amenazas, alertas y configuraciones. | `serde`, `chrono`, `uuid` |
| `samulibre-scanner` | Motor de escaneo multicapa: firmas hash exactas, streaming SHA-256 en bloques de 64 KB, reglas heurísticas YARA-X, motor de actualización atómica (`updater.rs`) y gestor de exclusiones ancladas por hash (`ExclusionManager`). | `sha2`, `hex`, `regex`, `ureq`, `flate2` |
| `samulibre-watcher` | Monitorización del sistema de archivos en tiempo real, debouncing de eventos, Clean File Cache acotado, pipeline predictivo de ransomware y bóveda de cuarentena cifrada con tolerancia a bloqueos I/O y permisos Windows. | `notify`, `uuid`, `chrono`, `samulibre-shield` |
| `samulibre-shield` | Autoprotección del antivirus (`AntiTamperShield`), despliegue de archivos canario anti-ransomware, firewall adaptativo contra LOLBins y C2, auditoría de inyecciones y honeytokens de credenciales. | `sysinfo`, `sha2`, `hex`, `tokio` |
| `samulibre-patcher` | Parchado virtual de vulnerabilidades (CVEs conocidas en Windows y Linux), mitigación por registro, cortafuegos dinámico y evaluación de KBs instaladas. | `serde_json`, `tracing` |
| `samulibre-core` | Orquestador central de la suite: inicialización, micro-sandbox seguro con análisis estático de MITRE ATT&CK, reputación comunitaria con $k$-Anonimato y programador de escaneos. | `uuid`, `tokio` |
| `samulibre-vpn` | Gestión de túneles de privacidad, fallback Tor, killswitch de red y pruebas de latencia geográfica. | `tokio`, `tracing` |
| `samulibre-ai` | Copiloto cibernético local con guardarraíles de seguridad y análisis contextual en lenguaje natural de configuraciones y parches. | `regex`, `serde` |
| `samulibre-android` | Puente de compatibilidad y auditoría de paquetes Android (ASB, APK sideload, overlay bancario). | `serde`, `tokio` |
| `samulibre-gui` | Interfaz gráfica de usuario desacoplada mediante WebView nativo (`wry`/`tao`), HTML embebido y TailwindCSS sin dependencias en la nube. | `wry`, `tao`, `tray-icon` |
| `samulibre-cli` | Interfaz de línea de comandos sin dependencias gráficas, automatización de escaneos, gestión de cuarentena y actualización de firmas. | `clap`, `colored` |

---

### 3. Ciclo de Vida de Detección y Neutralización

```
[1. Evento de Archivo] (Creación, modificación o escaneo bajo demanda)
        │
        ▼
[2. Filtro Anti-Symlink / Anti-LPE] (Verificación de symlink/junction NTFS)
        │
        ▼
[3. Verificación de Exclusiones Criptográficas]
    • ¿Ruta excluida?
    • Si tiene hash anclado: ¿Coincide el SHA-256?
    • Si coincide -> Marcado como LIMPIO (Falso Positivo resuelto)
    • Si el hash fue alterado -> Continúa al escaneo
        │
        ▼
[4. Clean File Cache]
    • ¿Mismo tamaño y modified time? -> Omitir re-escaneo (<0.05 ms)
        │
        ▼
[5. Streaming Multi-Engine Analysis]
    • Streaming SHA-256 del 100% del archivo
    • Muestreo de primeros 512 KB en memoria para evaluación de regex
    • Fast-Path substring pre-filtering
    • Reglas YARA-X / Heurísticas (Inyección, Droppers, AMSI bypass)
    • Detección de entropía anómala y scripts activos en PDFs
        │
        ▼
[6. Clasificación de Veredicto (ThreatVerdict)]
    • ConfirmedMalware / LikelyMalware / Inconclusive / LikelyFalsePositive / ConfirmedFalsePositive
        │
        ▼
[7. Aislamiento en Bóveda de Cuarentena (QuarantineVault)]
    • Lectura segura con reintentos backoff
    • Tolerancia a intercepción por kernel (OS Error 225)
    • Ofuscación reversible XOR (0xAA)
    • Escritura atómica a archivo temporal y renombrado
    • Desbloqueo de permisos ReadOnly
    • Eliminación de ruta original con reintentos
    • Fallback de neutralización in-situ (truncado)
        │
        ▼
[8. Notificación y Registro XDR]
    • Metadatos JSON en cuarentena
    • Inserción en threat_history.json con contexto de procedencia
    • Despacho de ThreatAlert hacia IPC / GUI / CLI
```

---

### 4. Seguridad, Autoprotección y Confianza Criptográfica

1. **Integridad de Base de Firmas:** Toda actualización descargada desde repositorios oficiales abiertos (Yara-Rules, Abuse.ch Feodo Tracker) se valida mediante hashes SHA-256 calculados en memoria, sintaxis de reglas YARA y límites estrictos de tamaño (1 KB a 50 MB) antes de instalarse atómicamente con soporte de rollback automático.
2. **Blindaje de Archivos del Antivirus (`AntiTamperShield`):** El motor calcula una línea base criptográfica (SHA-256) de todos los binarios y bases de datos locales. Cualquier eliminación o modificación no autorizada incrementa el contador de intentos de manipulación y alerta al usuario.
3. **Sandbox Seguro sin Riesgo de Infección:** El componente `MicroSandbox` no ejecuta binarios PE hostiles directamente en el host del usuario; utiliza análisis estático profundo, extracción de indicadores MITRE ATT&CK (T1055, T1105, T1059, T1486) y perfilado de entropía, eliminando la vulnerabilidad de infección del host.
