# SAMULIBRE: AUDITORÍA TÉCNICA INTEGRAL DEL SISTEMA ANTIVIRUS
**Fecha:** 7 de Noviembre de 2026  
**Equipo Auditor:** Equipo Multidisciplinario de Ingeniería de Ciberseguridad SamuLibre  
**Versión de Código Auditada:** SamuLibre Core & Suite v2.1.13  
**Entorno de Ejecución:** Windows 10/11 x64 (MSVC / Rust 2021)

---

## 1. RESUMEN EJECUTIVO

Se ha completado una inspección exhaustiva del código fuente, arquitectura, dependencias y comportamiento en tiempo de ejecución del proyecto **Antivirus SamuLibre**.

El proyecto está escrito en **Rust (Edición 2021)** estructurado como un espacio de trabajo (*workspace*) Cargo compuesto por 11 *crates*:
- `samulibre-types`: Tipos compartidos, estructuras de datos y protocolos IPC.
- `samulibre-core`: Núcleo orquestador que instancia los motores de escaneo, vigilancia y heurística.
- `samulibre-scanner`: Motor de firmas SHA-256, reglas de patrones regex, heurística de PDFs, cálculo de entropía y phishing.
- `samulibre-watcher`: Vigilancia de sistema de archivos en modo usuario (`notify` / `ReadDirectoryChangesW`) y bóveda de cuarentena.
- `samulibre-shield`: Escudo de endpoint (canarios anti-ransomware, monitoreo de procesos, auditoría de extensiones de navegador, endurecimiento de registro).
- `samulibre-patcher`: Parchado virtual de vulnerabilidades (CVEs) mediante reglas de firewall de Windows, mitigación de servicios y claves de registro.
- `samulibre-ai`: Copiloto y análisis automatizado de boletines de seguridad.
- `samulibre-gui`: Interfaz gráfica de usuario basada en WebView2 (`wry` / `tao`) y Tailwind CSS.
- `samulibre-cli`: Interfaz de línea de comandos (`clap`).
- `samulibre-vpn`: Gestor de enrutamiento y proxy Tor integrado.
- `samulibre-android`: Bindings y componentes específicos para Android.

---

## 2. MATRIZ DE AUDITORÍA TÉCNICA OBLIGATORIA

A continuación se detalla el estado verificado de cada componente técnico del antivirus:

| Componente | Estado actual | Problema identificado | Riesgo | Solución |
|---|---|---|---|---|
| **Actualización** | **SIMULADO** | `update_signatures()` en `samulibre-scanner/src/lib.rs` no realiza peticiones HTTP. Posee un array fijo de 13 cadenas y si no hay nuevas, genera artificialmente `+8 firmas` y escribe un JSON falso en `update_history.json`. No existe cliente HTTP (`reqwest`/`ureq`) en `Cargo.toml`. | **CRÍTICO** (Falsa sensación de seguridad; incapacidad absoluta de recibir nuevas definiciones de malware). | Implementar un gestor de actualización modular con HTTP/HTTPS real, validación criptográfica SHA-256, respaldo atómico, rollback y conexión con repositorios legítimos de reglas YARA y hashes abiertos. |
| **Firmas** | **PARCIAL** | La base `data/signatures/malware_hashes.db` solo posee 6 hashes. En código se hardcodean ~25 hashes. Además, `scan_file()` trunca el cálculo SHA-256 a los primeros 512 KB en archivos > 16 MB (`lib.rs:438`), produciendo hashes erróneos e impidiendo la detección válida de binarios grandes. | **CRÍTICO** (Catálogo de firmas ínfimo e invalidación matemática de hashes en archivos mayores a 16 MB). | Corregir el cálculo de streaming de SHA-256 al 100% del archivo. Construir base de datos de firmas indexada y compatible con formatos abiertos (YARA y hashes comunitarios). |
| **Escaneo manual** | **FUNCIONAL** (Limitado) | Funciona mediante `scan_paths_parallel` y Rayon en múltiples hilos con triage rápido por entropía y substrings. Sin embargo, no descomprime ni inspecciona dentro de contenedores ZIP/RAR/7z, y se ve afectado por el truncamiento en archivos > 16 MB. | **MEDIO** (No detecta malware empaquetado en archivos comprimidos o instaladores grandes). | Corregir el hasher completo y agregar desempaquetado e inspección de archivos comprimidos. |
| **Tiempo real** | **PARCIAL** | Basado en `notify` (`ReadDirectoryChangesW`) en espacio de usuario. Solo vigila 4 rutas de usuario (Descargas, Escritorio, Documentos, Temp). Si el malware escribe en otra ruta o bloquea el archivo con `Exclusive Lock`, `isolate_file` ignora el error de eliminación (`let _ = fs::remove_file`) dejando el virus en disco. `predictive_ransomware` nunca es invocado desde los eventos. | **CRÍTICO** (Incapacidad de prevenir la ejecución previa al acceso; pérdida de intercepciones ante bloqueos de archivo; rutas de sistema desprotegidas). | Implementar colas de eventos con reintentos escalonados para archivos bloqueados, integrar el monitor de ráfagas de ransomware en el pipeline de eventos y documentar con claridad el límite de modo usuario frente a un driver minifilter. |
| **Heurística** | **PARCIAL** | Heurística de URLs/Phishing y análisis de entropía funcional. Sin embargo, `scan_process_memory_for_fileless` en Windows es un stub vacío que retorna `Vec::new()`, y `MicroSandbox` ejecuta binarios sospechosos con `Command::new()` directamente sobre el host sin aislamiento de seguridad ni Job Objects. | **CRÍTICO** (Vulnerabilidad de auto-infección si se prueba malware en el sandbox; módulo fileless inoperante en Windows). | Desactivar ejecución insegura en MicroSandbox o implementar Job Objects estrictos; implementar inspección real de memoria en Windows o marcarlo como no verificado; robustecer heurística estática de PE. |
| **Cuarentena** | **PARCIAL** | Utiliza cifrado XOR trivial de 1 solo byte (0xAA) con metadatos JSON. Si el archivo está bloqueado por el sistema, la eliminación del original falla silenciosamente pero el metadato se registra. La restauración no verifica integridad SHA-256. | **ALTO** (Archivos infectados pueden permanecer en el origen; falta de verificación criptográfica de integridad de la bóveda). | Verificar éxito de eliminación del archivo original, implementar reintentos ante bloqueo `SharingViolation`, y validar SHA-256 antes de restaurar. |
| **Falsos positivos** | **PARCIAL** | La lista de exclusiones (`exclusions.json`) almacena únicamente rutas de texto plano. No vincula el hash SHA-256 del archivo. Un atacante puede reemplazar un archivo excluido por un binario malicioso en la misma ruta sin ser detectado. | **ALTO** (Bypass del antivirus mediante suplantación de rutas en lista blanca). | Vincular exclusiones obligatoriamente a hashes SHA-256; implementar clasificación de 5 niveles (`CONFIRMED_MALWARE`, `LIKELY_MALWARE`, `INCONCLUSIVE`, `LIKELY_FALSE_POSITIVE`, `CONFIRMED_FALSE_POSITIVE`). |
| **Interfaz** | **PARCIAL** | Interfaz WebView2 fluida y reactiva. Sin embargo, botones como "Actualizar firmas" invocan procesos simulados. No existe indicador de estado que distinga entre modo usuario y driver kernel, mostrando falsamente protección a nivel de kernel. | **MEDIO** (Inconsistencia entre lo reportado por la UI y el estado real de protección del sistema). | Conectar cada control de UI a procesos de backend verificados; mostrar estados transparentes: `FUNCIONAL`, `PARCIAL`, `NO DISPONIBLE`. |
| **Servicios Windows** | **INEXISTENTE** | No existe servicio de Windows registrado ni integración con Service Control Manager (SCM). El archivo `data/samulibre.service` es un archivo de configuración de systemd para Linux. Si el usuario cierra sesión, el antivirus se detiene por completo. | **ALTO** (Falta de persistencia y protección a nivel de sistema previas al inicio de sesión). | Documentar con precisión la ausencia del servicio Windows, clasificarlo como INEXISTENTE y sentar las bases arquitectónicas para el servicio Windows de SamuLibre. |
| **Rendimiento** | **FUNCIONAL** | El paralelismo con Rayon y el pre-filtro rápido de subcadenas (`has_suspicious_indicators`) mantienen baja latencia en escaneo de archivos limpios. Consumo de RAM entre 50 MB y 110 MB. Requiere optimización en el bloqueo del mutex global `core` en el hilo principal de la GUI. | **BAJO** (Desempeño adecuado, pero mejorable en concurrencia y contención de bloqueos). | Reducir el alcance de los locks de `Arc<Mutex<...>>` y desacoplar las consultas de telemetría de las operaciones de I/O pesadas. |

---

## 3. ANÁLISIS DETALLADO DE VULNERABILIDADES Y PROBLEMAS EN EL CÓDIGO

### 3.1 Simulación en el Motor de Actualizaciones (`crates/samulibre-scanner/src/lib.rs`)
En las líneas 666 a 750 de `samulibre-scanner`:
```rust
pub fn update_signatures(&mut self) -> Result<SignatureUpdateReport> {
    let initial_count = self.known_signatures.len();
    let community_signatures = [
        ("c4566c1b3f94539ef2a382c0f655dc3bc3594e50882e3895e34be6acab28d098", "Trojan.Win32.AgentTesla.Stealer"),
        ...
    ];
    // Inserta siempre los mismos 13 elementos
    // No existe ninguna conexión de red
    history.insert(0, UpdateHistoryEntry {
        ...
        signatures_added: if new_added > 0 { new_added } else { 8 }, // ¡Simula 8 nuevas siempre!
        feed_source: "MalwareBazaar & ThreatFox Community Feeds".to_string(),
        ...
    });
}
```
**Impacto:** El botón "Actualizar Firmas" en la interfaz muestra "Sincronizando...", incrementa el contador con firmas falsas y registra en el historial fechas ficticias sin descargar nada.

### 3.2 Error Crítico de Cálculo de Hash SHA-256 en Archivos Grandes (`crates/samulibre-scanner/src/lib.rs`)
En las líneas 437-440 de `samulibre-scanner`:
```rust
// Para archivos gigantescos (> 16 MB) o contenedores/medios comprimidos,
// truncamos el cálculo tras los primeros 512 KB para velocidad extrema (< 1 ms por archivo)
if (file_len > 16 * 1024 * 1024 || is_archive_or_media) && bytes_read_total >= 512 * 1024 {
    break;
}
```
**Impacto:** Cualquier archivo de más de 16 MB (instaladores, imágenes ISO, ejecutables de juegos o software ofimático) recibe un SHA-256 correspondiente únicamente a sus primeros 512 KB. Este hash jamás coincidirá con las firmas reales de malware conocidas, inutilizando la detección de firmas para payloads grandes.

### 3.3 Peligro de Ejecución en `MicroSandbox` (`crates/samulibre-core/src/sandbox.rs`)
En las líneas 57-72 de `sandbox.rs`:
```rust
let mut cmd = Command::new(&jailed_file);
cmd.current_dir(&jail_dir);
cmd.stdin(Stdio::null());
cmd.stdout(Stdio::piped());
cmd.stderr(Stdio::piped());
...
let spawn_res = cmd.spawn();
```
**Impacto:** El "sandbox" simplemente copia el archivo a una subcarpeta y lo ejecuta en el propio sistema operativo anfitrión con los permisos del usuario activo. Si el archivo analizado es un ransomware real, cifrará los archivos del usuario inmediatamente.

### 3.4 Desconexión de la Detección Predictiva de Ransomware
El módulo `crates/samulibre-shield/src/ransomware_predictive.rs` tiene lógica matemática funcional para medir tasa de eventos de I/O y picos de entropía por segundo (`PredictiveRansomwareMonitor`). Sin embargo, el método `record_file_io` nunca es invocado por `RealTimeWatcher` ni por el despachador de eventos. Permanece como código muerto en producción.

### 3.5 Eliminación Silenciosa Fallida en Cuarentena
En `crates/samulibre-watcher/src/lib.rs` (línea 70):
```rust
let _ = fs::remove_file(source_path);
```
Cuando un archivo es detectado en tiempo real en Windows, a menudo el proceso que lo creó aún mantiene un descriptor de archivo abierto. `fs::remove_file` devuelve un error de violación de compartición (`ERROR_SHARING_VIOLATION`), pero el operador `let _` descarta el error. El usuario recibe un mensaje de "Amenaza en Cuarentena" cuando en realidad el archivo original continúa intacto en su ubicación de origen.

---

## 4. PLAN DE TRABAJO INMEDIATO POR PRIORIDADES

1. **Prioridad Crítica (Fase 2):**
   - Construir el subsistema real de actualización de firmas `UpdateManager` con cliente HTTP real, fuentes de inteligencia legítimas y verificación estricta de integridad SHA-256.
   - Corregir inmediatamente el bug de truncamiento de hash en `samulibre-scanner`.
   - Conectar el botón de la interfaz a la descarga y reporte real.

2. **Prioridad Alta (Fase 3):**
   - Corregir el aislamiento de cuarentena con verificación obligatoria de borrado del origen y reintentos ante bloqueos.
   - Conectar el monitor predictivo de ransomware a los eventos de modificación de archivos.
   - Implementar pruebas de verificación con EICAR real.

3. **Prioridad Media / Calidad:**
   - Desactivar o aislar de forma segura la ejecución no contenida en `MicroSandbox`.
   - Establecer el sistema de clasificación de falsos positivos en 5 niveles y endurecer las exclusiones con pinning SHA-256.
   - Transparentar el estado de los servicios en la GUI (marcar como `PARCIAL` el tiempo real y `NO DISPONIBLE` los drivers de kernel).

---
*Fin del documento de auditoría técnica.*
