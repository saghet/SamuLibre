# Registro de Cambios (Changelog)

Todas las modificaciones notables realizadas en este proyecto están documentadas en este archivo.
El formato se basa en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y se adhiere a [Semantic Versioning](https://semver.org/lang/es/).

---

## [2.1.13] - 2026-11-07

### Agregado
- **Subsistema de Servicio Windows 24/7 (SCM):** Integración completa del despachador de servicios de Windows con el crate `windows-service` v0.8.1 para arranque persistente pre-login y ejecución protegida como `NT AUTHORITY\SYSTEM`.
- **Instalación y Elevación UAC en Un Clic:** Botón contextual `[🛡 Instalar Servicio Windows (UAC)]` y badge interactivo en la tarjeta diagnóstica de la interfaz gráfica para desplegar y registrar el servicio sin salir de la GUI.
- **Health Manager de Protección:** Subsistema de auditoría continua en tiempo real que verifica con evidencia criptográfica y de sistema operativo los 9 componentes esenciales de protección de endpoint.
- **Batería de Autodiagnóstico en Tiempo Real:** 8 pruebas automatizadas bajo demanda que evalúan la latencia del monitor, la cola priorizada, la desinfección EICAR, la bóveda XOR y el despachador IPC.
- **Canal IPC Bidireccional Asíncrono:** Comunicación continua a través de `Tao EventLoopProxy` y WebView2 con refresco cada 5 segundos de métricas de telemetría y salud de subsistemas.

### Corregido
- **Resolución de Bloqueo "PENDIENTE" en GUI:** Corregida discrepancia entre el binario de ejecución en `target\release` y el frontend `index.html`. Sincronización de todas las acciones IPC (`get_protection_health`, `run_realtime_autodiagnostic`, `start_realtime_service`).
- **Control de Instancia Única y Fugas de Conexión:** Corrección del enlace en puerto local `49721` y señal `SHOW` para traer ventanas existentes al frente sin bloquear reinicios.
- **Manejo Seguro de Exclusiones:** Validación de rutas normalizadas y hashes fijados para prevenir bypass de análisis en carpetas vigiladas.
- **Tolerancia a Fallos en Inicio:** Detección y saneamiento automático de proxies de red huérfanos al iniciar la aplicación.

### Rendimiento
- **Memoria en Reposo Optimizada:** Consumo promedio del proceso GUI y motor en reposo por debajo de **42 MB de RAM**.
- **Caché Fast-Path en Memoria:** Verificación instantánea de hashes de archivos benignos con latencia inferior a **0.05 ms** por acceso.

---

## [2.1.0] - 2026-10-24

### Agregado
- Motor heurístico avanzado con cálculo de entropía Shannon para detección de empaquetadores polimórficos (*UPX, Themida, VMProtect*).
- Despliegue de archivos trampa canario anti-ransomware con monitoreo diferencial de escrituras.
- Bóveda de cuarentena cifrada con algoritmo XOR reversible y preservación de metadatos de procedencia.

---

## [2.0.0] - 2026-10-15

### Agregado
- Rediseño visual completo con estética glassmorphism moderna e intuitiva.
- Migración integral de la arquitectura a Rust workspace modular (11 crates independientes).
- Módulo de parchado virtual autónomo para mitigación de CVEs de Windows 11 sin necesidad de reinicio.
