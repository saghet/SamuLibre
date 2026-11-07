# AUDITORÍA INTEGRAL DEL MOTOR DE PROTECCIÓN EN TIEMPO REAL (SAMULIBRE)

**Fecha:** 7 de Noviembre de 2026  
**Proyecto:** SamuLibre Antivirus & Endpoint Protection (Windows 10/11)  
**Clasificación:** Auditoría de Arquitectura, Detección y Flujo de Eventos  
**Equipo Auditor:** Principal Security Architect, Windows Kernel Developer, Senior Antivirus Engine Developer, Malware Researcher.

---

## 1. RESUMEN EJECUTIVO Y ANÁLISIS DE LA PROBLEMÁTICA

Durante la auditoría inicial de SamuLibre, se identificó un síntoma crítico reportado por los operadores y usuarios: la interfaz gráfica presentaba el texto permanente **"Analizando sistema en tiempo real..."**, sin que existiera evidencia verificable de que los eventos del sistema de archivos de Windows estuvieran siendo capturados, despachados, analizados por las firmas/YARA o correlacionados en tiempo de ejecución.

### Hallazgos Principales de la Auditoría:
1. **Conflación de Interfaces:** La función JavaScript `showScanProgressUI()` en `data/ui/index.html` (línea 1840) fijaba directamente `scanStatusTitle.textContent = 'Analizando sistema en tiempo real...'` al pulsar cualquier botón de escaneo manual (análisis rápido o análisis completo). Esto causaba que una tarea *on-demand* bajo demanda se confundiera visualmente con la supervisión de protección residente permanente.
2. **Ciclo de Vida Acoplado a la GUI:** El monitor de archivos (`notify::RecommendedWatcher`) se instanciaba dentro de un hilo secundario en el proceso principal de la interfaz de usuario (`samulibre-gui`). Si el usuario cerraba la ventana, todo el subsistema de protección en tiempo real finalizaba inmediatamente, dejando el endpoint sin protección.
3. **Ausencia de Cola Asíncrona Desacoplada:** Las alertas de archivos se agregaban directamente a un vector en memoria sin control de contrapresión (*backpressure*), sin priorización (los directorios críticos como `Downloads` o `Temp` recibían el mismo trato que modificaciones inocuas en carpetas del sistema), y sin trazabilidad mediante identificadores de correlación únicos (*Trace/Correlation IDs*).
4. **Manejo de Bloqueos de Archivo (Sharing Violations):** Cuando una aplicación de terceros (e.g. un navegador o instalador) escribía un archivo en disco, el motor intentaba abrirlo inmediatamente con acceso exclusivo. Esto provocaba errores Win32 `ERROR_SHARING_VIOLATION` (código 32), resultando en eventos descartados silenciosamente sin reintentos exponenciales.

---

## 2. AUDITORÍA ESLABÓN POR ESLABÓN DE LA CADENA DE PROTECCIÓN

A continuación se detalla el análisis exhaustivo de cada eslabón de la tubería de protección:

| Eslabón de la Cadena | Estado Previo a la Auditoría | Veredicto | Causa Raíz / Deficiencia Técnica |
| :--- | :--- | :--- | :--- |
| **1. Interacción con Windows** | Eventos capturados mediante `notify` / `ReadDirectoryChangesW` en espacio de usuario. | ⚠️ **PARCIAL** | Solo capturaba eventos en hilos de la interfaz. Si la ventana se cerraba, moría la protección. |
| **2. Sistema de Monitorización** | Un solo hilo consumidor ejecutando `rx.recv()`. | ⚠️ **DEFICIENTE** | Sin desacoplamiento entre el hilo receptor de Windows y el motor de escaneo. Vulnerable a desbordamiento del búfer de kernel. |
| **3. Captura de Eventos** | Sin deduplicación ni gestión de ráfagas (*debouncing*). | ❌ **CRÍTICO** | Múltiples eventos `Modify` consecutivos para un solo archivo descargado saturaban el hilo de análisis. |
| **4. Cola de Procesamiento** | Inexistente (canal mpsc sin límite y sin prioridad). | ❌ **CRÍTICO** | No había búfer delimitado (*bounded queue*). Riesgo de agotamiento de memoria ante ataques por saturación (*queue flooding*). |
| **5. Motor de Análisis On-Access** | Invocaba `core.scan_file()` sincrónicamente. | ⚠️ **LENTO** | Bloqueaba el hilo de eventos si un archivo grande debía ser procesado con SHA-256 sin pasar antes por caché limpia. |
| **6. Base de Firmas** | Hash SHA-256 + prefijo hexadecimal. | ✅ **OPERATIVO** | Funcionaba correctamente, pero faltaba verificación previa de lista de excepciones antes del hash. |
| **7. Motor YARA** | Compilación de reglas en memoria. | ✅ **OPERATIVO** | Capaz de detectar malware complejo, pero requería lectura íntegra en RAM. |
| **8. Motor Heurístico** | Entropía Shannon y detección de ransomware. | ✅ **OPERATIVO** | Bien estructurado, pero sin correlación temporal entre eventos de creación rápida. |
| **9. Clasificación de Amenazas** | Categorización en `Clean`, `Suspicious`, `Infected`. | ✅ **OPERATIVO** | Asignaba severidades `Low`, `Medium`, `High`, `Critical`. |
| **10. Motor de Respuesta** | Aislamiento en Bóveda Cifrada XOR. | ⚠️ **PARCIAL** | La cuarentena existía, pero no desvinculaba atómicamente el archivo en disco ni registraba metadatos de telemetría. |
| **11. Registro de Eventos** | Guardado en `threat_history.json`. | ⚠️ **INCOMPLETO** | No incluía `correlation_id` para auditar la traza completa desde la captura hasta la respuesta. |
| **12. Interfaz SamuLibre** | Mensaje engañoso "Analizando sistema en tiempo real..." | ❌ **CRÍTICO** | Mostraba estado activo incluso cuando el watcher fallaba o no estaba corriendo. |

---

## 3. IDENTIFICACIÓN DEL ERROR VISUAL VS. MOTOR REAL

El análisis del código fuente reveló que la interfaz de usuario presentaba dos anomalías de diseño:
1. En `data/ui/index.html`:
   ```javascript
   // Código defectuoso previo:
   function showScanProgressUI() {
     document.getElementById('scanFilesCount').textContent = '0';
     document.getElementById('scanThreatsCount').textContent = '0';
     document.getElementById('scanStatusTitle').textContent = 'Analizando sistema en tiempo real...'; // <- ERROR
   }
   ```
   Al hacer clic en "Análisis Rápido" o "Análisis Completo", el sistema activaba un análisis bajo demanda (*on-demand*), pero el título indicaba "Analizando sistema en tiempo real...", generando una profunda confusión en el usuario respecto al verdadero estado de la protección residente.

2. En la pestaña de tiempo real (`tab-tiempo-real`):
   El indicador de estado era un HTML estático:
   ```html
   <span class="text-xs font-bold text-emerald-400">ACTIVADO</span>
   <div class="w-3 h-3 rounded-full bg-emerald-500 animate-pulse"></div>
   ```
   No consultaba ninguna API ni proceso en segundo plano. Aunque el monitor fallara o se detuviera, la interfaz continuaba indicando "ACTIVADO" y mostrando una luz verde intermitente.

---

## 4. CONCLUSIÓN DE LA AUDITORÍA

Para que SamuLibre califique como un antivirus profesional y confiable, se requería una refactorización estructural que:
1. Creara un **servicio de fondo desacoplado** capaz de persistir de forma autónoma independientemente de si la interfaz gráfica está abierta o cerrada.
2. Implementara una **cola de eventos con prioridades y contrapresión** (*bounded prioritized queue*) con límite estricto de memoria (10,000 elementos) y descarte seguro con registro de métricas.
3. Incorporara **Trace IDs / Correlation IDs** únicos (`Uuid v4`) en cada evento desde su generación en el monitor hasta su resolución en cuarentena o registro.
4. Implementara un **mecanismo de reintentos exponenciales** para manejar bloqueos de escritura (`Sharing Violations`) en archivos en proceso de descarga.
5. Reemplazara todo el contenido estático de la interfaz por **telemetría en tiempo real atómica** y un módulo de **autodiagnóstico con pruebas reales sobre disco**.
