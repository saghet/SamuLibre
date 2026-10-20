# Changelog de SamuLibre

Todas las mejoras notables, correcciones de errores y nuevas funcionalidades de SamuLibre se documentan en este archivo siguiendo [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y versionado semántico.

---

## [1.99.13] - 2026-10-20

### 🚀 Novedades y Mejoras Principales
- **Inicio Automático en Windows (Windows Autostart al Arranque):**
  - Implementado registro y desregistro nativo en `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` bajo el nombre `SamuLibre`.
  - Soporte de arranque silencioso con parámetro `--minimized` para inicio en segundo plano en la bandeja del sistema.
  - Interruptor interactivo (toggle switch) *"Inicio con Windows"* incorporado en la interfaz y sincronizado bidireccionalmente vía IPC (`get_autostart_status`, `set_autostart`).
- **Revisión y Potenciación Profunda del Motor de Escaneo:**
  - Erradicado el tope arbitrario de 60 archivos (`results.len() >= 60`) que truncaba prematuramente los escaneos de carpetas y rutas personalizadas.
  - Eliminado el límite superficial `max_depth(3)` en `execute_scan_loop`, permitiendo escaneo recursivo completo (`max_depth: 25-30`) con filtrado inteligente de carpetas pesadas no relevantes (`.git`, `node_modules`, `target`, `$Recycle.Bin`).
  - Detección inmediata de binarios ejecutables Windows Portable Executable (cabecera PE `MZ`) y ampliación de reglas YARA-X/Heurísticas contra destructores de copias de seguridad de volumen (`vssadmin delete shadows`), descargadores LOLBin (`certutil`, `bitsadmin`, `mshta`, `regsvr32`), wipers destructivos y volcados de memoria LSASS (`sekurlsa`, `mimikatz`).
  - Emisión en tiempo real de cada amenaza encontrada a la interfaz gráfica y persistencia inmediata en el registro histórico.
- **Detención Inmediata de Análisis Manual (Cancel Scan):**
  - Implementada bandera atómica global `IS_SCAN_CANCELLED: AtomicBool` consultada en cada iteración de archivo dentro de los bucles de escaneo.
  - Manejador IPC `cancel_scan` para abortar escaneos en ejecución de manera instantánea y segura sin bloquear la aplicación ni dejar archivos abiertos.
  - Botón llamativo `⏹️ Detener Análisis` en la tarjeta de progreso en vivo y en los controles de escaneo.
- **Toma de Decisiones Interactivas ante Amenazas Detectadas:**
  - Modal contextual emergente `modalThreatDecision` al detectar archivos infectados o sospechosos.
  - 4 opciones directas para el usuario:
    1. **🛡️ Mover a Cuarentena (Recomendado):** Cifra el contenido con algoritmo XOR (clave 0xAA), custodia el elemento en `data/quarantine/` y destruye el original de forma segura.
    2. **🗑️ Eliminar Permanentemente:** Destrucción y borrado definitivo del archivo del sistema.
    3. **⚪ Excluir (Falso Positivo):** Incorporación de la ruta o hash a `data/exclusions.json` para omitir alertas futuras.
    4. **👁️ Ignorar:** Mantiene el archivo sin modificaciones bajo confirmación del usuario.
  - Capacidad de restauración de archivos desde la cuarentena (`restore_quarantined_item`) revirtiendo el cifrado XOR y devolviendo el archivo a su ruta original.
- **Historial Persistente de Archivos Maliciosos (`data/threat_history.json`):**
  - Registro cronológico permanente de amenazas detectadas, firmas, niveles de severidad (Crítica, Alta, Media), motor de detección y estado de resolución.
  - Tarjeta y tabla interactiva en la pestaña del Escáner con contadores, badges de estado y botones de acción rápida (*Aislar*, *Borrar*, *Restaurar* o *Purgar*).
- **Actualización de Versión y Control Visual:**
  - Etiqueta de versión visible en la esquina superior izquierda de la aplicación: `v1.99.13`.
  - Manifiesto Android actualizado con `versionCode = 6` y `versionName = "1.99.13"`.

---

## [1.99.12] - 2026-10-20

### 🚀 Novedades y Mejoras Principales
- **Gateway Proxy Local Inteligente (`SamuSmartProxyServer`):**
  - Implementado servidor proxy HTTP/HTTPS local de alta concurrencia en `127.0.0.1:8118` con enlace inmediato al `VpnService` de Android en Android 10+ (API 29+).
  - Erradicado de forma definitiva el error `ERR_PROXY_CONNECTION_FAILED` en Google Chrome y navegadores móviles.
  - Handshake SOCKS5 RFC 1928 nativo con resolución remota de dominios (ATYP 0x03) en el nodo de salida para prevención total de fugas de DNS (Zero-Leak).
- **Enmascaramiento Total de IP de ISP Móvil:**
  - Garantizado que navegadores web como Google Chrome muestren la dirección IP pública correspondiente al país seleccionado (ej. Islandia `185.112.82.19`, Suiza `195.176.3.23`) y nunca la IP del operador celular local (Movistar Colombia `152.203.238.220`).
- **Base de Datos GeoIP Integrada:**
  - Empaquetada base `geoip` en los assets de la app y copiada dinámicamente a almacenamiento interno para resolución precisa de nodos de salida por código de país (`{is}`, `{ch}`, `{nl}`, `{se}`).
- **Caché de Consenso y Microdescriptores en Disco:**
  - Eliminada directiva `AvoidDiskWrites 1` para permitir la persistencia del consenso Tor en memoria flash, reduciendo el tiempo de reconexión de 90 segundos a menos de 2 segundos.
  - Pre-calentamiento asíncrono en segundo plano al abrir la aplicación para arranque inmediato.
- **Optimización de Inicio (< 300 ms):**
  - Desacoplada la auditoría masiva de paquetes del ciclo de arranque inicial, trasladándola exclusivamente bajo demanda a la sección correspondiente.
  - Filtrado optimizado en `getInstalledAppsDetailsFast` para omitir paquetes estándar del sistema sin permisos de riesgo.
- **Control de Versión Visual:**
  - Etiqueta de versión visible en la esquina superior izquierda de la aplicación: `v1.99.12`.
  - Manifiesto actualizado con `versionCode = 5` y `versionName = "1.99.12"`.

---

## [1.99.11] - 2026-10-19
- **Arquitectura VPN de Doble Etapa con Watchdog:**
  - Transición segura de túnel en dos etapas (Modo DNS Seguro y Modo Proxy con supervisión continua).
  - Eliminación de ANRs y bloqueos en `TorService` mediante inicio estándar por `startService`.

---

## [1.99.10] - 2026-10-19
- **Sincronización Dinámica de Puertos Tor:**
  - Escucha dinámica de puertos locales y enlace con `ProxyController` de AndroidX WebKit.
  - Verificación de IP en vivo para la interfaz móvil.

---

## [1.99.0] - 2026-10-15
- **Lanzamiento de la Suite de Seguridad SamuLibre:**
  - EDR en Rust con motor YARA-X, tripwires canarios contra Ransomware y mitigación autónoma de vulnerabilidades 0-Day.
  - Soporte multiplataforma para Windows 11, Linux (Ubuntu, RHEL, Garuda) y Android.
