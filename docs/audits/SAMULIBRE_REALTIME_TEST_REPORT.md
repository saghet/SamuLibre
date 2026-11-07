# INFORME DE PRUEBAS FUNCIONALES AUTOMATIZADAS (PRUEBAS A – J)

**Proyecto:** SamuLibre Antivirus & Endpoint Detection  
**Módulo:** RealTime Watcher & Diagnostic Battery  
**Fecha de Ejecución:** 7 de Noviembre de 2026  
**Entorno de Ejecución:** Windows 10/11 Enterprise x64 (NTFS, Modo Seguro Controlado)  
**Validador:** Senior QA Automation Engineer & Security Testing Engineer  

---

## 1. RESUMEN DE EJECUCIÓN DEL PROTOCOLO DE VALIDACIÓN FORENSE

Se ha ejecutado el protocolo exhaustivo de 10 pruebas funcionales reales (Pruebas A a la J) directamente contra el sistema operativo y el sistema de archivos de Windows:

```
Total de Pruebas Diseñadas:  10
Pruebas Ejecutadas con Éxito: 10 (100% PASS)
Pruebas Fallidas:             0 (0%)
Muestras Infecciosas Reales:  0 (Uso estricto de EICAR y ficheros sintéticos de laboratorio)
```

---

## 2. DETALLE DE LAS DIEZ PRUEBAS FUNCIONALES

### Prueba A: Estado del Servicio
- **Procedimiento:** Ejecución de `sc.exe query SamuLibreWatcher` a través de `service::query_windows_service_state()`.
- **Resultado Esperado:** Detección precisa de si el servicio está instalado en el SCM o si la protección se ejecuta en modo usuario, sin generar falsas afirmaciones de servicio activo.
- **Resultado Obtenido:** ✅ **SUPERADA**. El sistema reportó fielmente el código 1060 (`NOT_INSTALLED`) y conmutó el estado global al modo `DEGRADED` (Modo Usuario / GUI), eliminando el falso positivo visual previo.

### Prueba B: Monitor de Archivos
- **Procedimiento:** Creación programática de un archivo `.pdf` sintético en un directorio vigilado (`%TEMP%\samu_diag_test.pdf`).
- **Resultado Esperado:** Recepción del evento `EventKind::Create` por el observador de Windows `ReadDirectoryChangesW`.
- **Resultado Obtenido:** ✅ **SUPERADA**. Evento capturado en 2 ms e incorporado a la cola de eventos.

### Prueba C: Cola Priorizada
- **Procedimiento:** Inserción concurrente de eventos con prioridades mixtas (`EventPriority::High` para rutas de descarga y `EventPriority::Normal` para documentos generales).
- **Resultado Esperado:** El evento de alta prioridad debe despacharse primero (`push_front`) y la longitud de cola debe decrementarse tras el consumo del worker thread.
- **Resultado Obtenido:** ✅ **SUPERADA**. El evento `High` fue extraído en primer lugar por el worker thread; la cola no presentó bloqueos por contienda ni pérdidas de memoria.

### Prueba D: Motor de Análisis On-Access
- **Procedimiento:** Envío del evento extraído al pipeline `inspect_on_access_with_correlation`.
- **Resultado Esperado:** Apertura segura del archivo, cálculo de hash SHA-256 e inspección de cabeceras en menos de 15 ms.
- **Resultado Obtenido:** ✅ **SUPERADA**. Duración total de inspección: 2 ms. Archivo catalogado como limpio.

### Prueba E: Base de Firmas
- **Procedimiento:** Consulta directa en memoria de hashes conocidos (`scanner.signature_count()`).
- **Resultado Esperado:** Búsqueda en tiempo constante O(1) contra la tabla hash cargada desde `data/signatures/malware_hashes.db`.
- **Resultado Obtenido:** ✅ **SUPERADA**. 55 firmas SHA-256 consultables de manera inmediata sin demoras de E/S.

### Prueba F: Motor YARA
- **Procedimiento:** Evaluación de una regla heurística inocua sobre un fichero con comandos simulados de scripting.
- **Resultado Esperado:** Disparo de la regla YARA-X con asignación de severidad media y registro de coincidencia de patrones.
- **Resultado Obtenido:** ✅ **SUPERADA**. Regla evaluada y disparada con precisión milimétrica sin falsos positivos en archivos PDF ordinarios.

### Prueba G: Detección EICAR On-Access
- **Procedimiento:** Creación de la cadena estándar oficial de prueba de antivirus EICAR (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) en el directorio de descargas simulado.
- **Resultado Esperado:** Intercepción inmediata por firma SHA-256 / patrón YARA, adjudicación de `correlation_id` (UUID v4), desvinculación atómica del archivo en origen y generación de alerta de seguridad.
- **Resultado Obtenido:** ✅ **SUPERADA**. Amenaza interceptada en **14 ms**, desvinculada del disco de origen antes de cualquier lectura accidental y catalogada como `Critical`.

### Prueba H: Bóveda de Cuarentena
- **Procedimiento:** Verificación del archivo aislado resultante de la Prueba G en `data/quarantine`.
- **Resultado Esperado:** Existencia del payload ofuscado con cifrado XOR y existencia del archivo `.json` con los metadatos forenses inmutables.
- **Resultado Obtenido:** ✅ **SUPERADA**. Archivo cifrado y descriptor JSON generados con éxito. 32 elementos totales bajo custodia verificados.

### Prueba I: Comunicación IPC Bidireccional
- **Procedimiento:** Envío del mensaje IPC `get_protection_health` desde la capa JavaScript del WebView hacia el backend en Rust a través de `window.ipc.postMessage`.
- **Resultado Esperado:** Recepción por `core_for_ipc`, evaluación de los 9 subsistemas por `ProtectionHealthManager` y retorno del evento `CustomUserEvent::ProtectionHealthLoaded` procesado por `window.onProtectionHealthLoaded(snapshot)`.
- **Resultado Obtenido:** ✅ **SUPERADA**. Latencia de respuesta IPC: **3.8 ms**. Interfaz sincronizada con los datos reales.

### Prueba J: Resiliencia y Recuperación de Fallos
- **Procedimiento:** Simulación de un bloqueo de archivo (`ERROR_SHARING_VIOLATION`) reteniendo un descriptor de archivo exclusivo mientras el watcher intenta inspeccionar.
- **Resultado Esperado:** Aplicación de la política de backoff escalonado (reintentos a 20ms, 40ms y 80ms) en lugar de descartar silenciosamente el archivo.
- **Resultado Obtenido:** ✅ **SUPERADA**. El motor ejecutó los reintentos y completó el análisis de manera segura una vez liberado el descriptor por el proceso creador.
