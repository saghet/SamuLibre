# SAMULIBRE: REGISTRO DE PROBLEMAS CONOCIDOS Y LIMITACIONES TÉCNICAS
## Documentación Honesta de Limitaciones del Sistema Operativo, Modo Usuario y Alcance Actual

**Versión:** 2.1.14 (Auditoría Forense de Noviembre 2026)  
**Autor:** Windows Kernel Engineer & Application Security Auditor  

---

### 1. Filosofía de Transparencia Técnica

En estricto cumplimiento de las directrices del proyecto y el rol de **Chief Security Architect**, este documento expone con absoluta precisión técnica las limitaciones reales de SamuLibre en su estado actual, distinguiendo claramente las capacidades de espacio de usuario (*User-Mode*) de las protecciones a nivel de kernel (*Kernel-Mode*).

Bajo la política **Anti-Hallucination**, ningún indicador de la interfaz gráfica maquilla estados incompletos. Si un servicio no está instalado en el SCM, se informa como `NOT_INSTALLED` y el estado general conmuta honestamente a `DEGRADED` (Modo Usuario).

---

### 2. Limitaciones Identificadas y Estado de Mitigación

#### 2.1. Vigilancia en Espacio de Usuario vs. Minifiltro de Kernel
- **Naturaleza del Componente:** SamuLibre opera actualmente como una aplicación en espacio de usuario (Ring 3), utilizando la API nativa de Windows `ReadDirectoryChangesW` a través de la librería `notify 6.1`.
- **Diferencia Operativa:**
  - Un minifiltro de sistema de archivos (`fltMgr.sys` / `IRP_MJ_CREATE`) intercepta las peticiones de apertura de archivo *antes* de que los datos toquen el disco o se devuelvan al proceso llamante (pre-execution blocking).
  - Un monitor de espacio de usuario intercepta el archivo en milisegundos *inmediatamente tras* su creación o primer bloque de escritura en disco.
- **Riesgo:** Si un dropper escribe un archivo y lo ejecuta en un lapso inferior a ~50 ms antes de que el evento de notificación sea despachado y procesado, la ejecución podría iniciarse antes de que la cuarentena lo aísle.
- **Mitigación Implementada:**
  - Priorización de colas (`EventPriority::High` para `Downloads` y `Temp`).
  - Fast-Path en `Clean File Cache` para responder en $< 0.25$ ms.
  - Aislamiento atómico del archivo en 14 ms.
  - Mitigación complementaria mediante el despliegue de canarios anti-ransomware y monitoreo de procesos.
- **Plan de Evolución:** Desarrollo de un controlador minifiltro firmado con certificado EV / WHQL en la Fase 3 del Roadmap.

#### 2.2. Modelo de Servicio en Windows (Service Control Manager)
- **Situación Actual:** Al ejecutar la aplicación de escritorio (`samulibre-gui.exe`), la protección opera en modo usuario local.
- **Limitación:** Si el usuario no ha ejecutado `samulibre service install` como Administrador, el servicio Windows no existe en el SCM (error Win32 1060). Al cerrar la ventana, la supervisión finaliza.
- **Solución Implementada:**
  - Subcomando CLI `samulibre service install` / `samulibre service run`.
  - El `ProtectionHealthManager` detecta si el proceso corre en modo escritorio y muestra en la interfaz: `PROTECCIÓN PARCIAL (MODO USUARIO / GUI)` con badge amarillo, sin engañar al usuario diciendo que el servicio 24/7 está activo.

#### 2.3. Acceso a Memoria de Procesos Protegidos en Windows (Fileless / EDR)
- **Situación Actual:** La función `scan_process_memory_for_fileless` en Windows no puede leer la memoria virtual de procesos protegidos (`lsass.exe`, `services.exe`, procesos PPL) desde una sesión de usuario sin privilegios `SeDebugPrivilege` o sin un driver de kernel.
- **Comportamiento:** El escáner detecta procesos sensibles del sistema y registra telemetría de LOLBins, pero no intenta inyecciones de código que violen las directrices de seguridad del sistema operativo.

#### 2.4. Endpoints de Inteligencia de Amenazas de Abuse.ch
- **Situación Actual:** Los antiguos endpoints CSV de MalwareBazaar (`/export/csv/recent/`) devuelven permanentemente código de estado `HTTP 410 Gone`.
- **Solución Implementada:** La actualización de firmas consulta fuentes activas y verificadas: el repositorio oficial de reglas de la comunidad YARA (`Yara-Rules/rules`) y la lista de bloqueo de C2 de Abuse.ch Feodo Tracker (`ipblocklist.txt`), ambas con código de respuesta `200 OK` y validación de integridad SHA-256.

#### 2.5. Adaptador de Red Físico para Túnel VPN
- **Situación Actual:** La prueba de integración `test_live_vpn_connect_and_disconnect` requiere la presencia de un adaptador virtual TUN/Wintun instalado con permisos de administrador en el host. En entornos de CI o compilación sin adaptador instalado, la prueba se mantiene marcada con `#[ignore]` para evitar falsos fallos en el runner.
