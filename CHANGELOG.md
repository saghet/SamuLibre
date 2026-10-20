# Changelog de SamuLibre

Todas las mejoras notables, correcciones de errores y nuevas funcionalidades de SamuLibre se documentan en este archivo siguiendo [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y versionado semántico.

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
