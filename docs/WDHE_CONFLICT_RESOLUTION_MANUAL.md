# MANUAL OPERATIVO DE RESOLUCIÓN DE CONFLICTOS
## SamuLibre Endpoint Protection <-> Microsoft Defender Antivirus
**Documento:** Manual Técnico para Administradores de Seguridad y Desarrolladores  
**Objetivo:** Guía de Diagnóstico, Resolución y Mitigación de Conflictos de Coexistencia  
**Versión:** WDHE 2.1.13  

---

## 1. INTRODUCCIÓN

Este manual ofrece procedimientos paso a paso para diagnosticar y solucionar cualquier escenario de fricción, contienda de recursos o discrepancia de detección entre SamuLibre y Microsoft Defender Antivirus en sistemas Windows 10 y Windows 11.

---

## 2. ESCENARIOS COMUNES Y PROTOCOLO DE RESOLUCIÓN

### ESCENARIO 1: ERROR DE ACCESO COMPARTIDO (`ERROR_SHARING_VIOLATION` / CÓDIGO 0x20)
**Síntoma:**  
Al descargar o compilar un archivo ejecutable, SamuLibre o una aplicación de usuario reporta:  
`El proceso no tiene acceso al archivo porque está siendo utilizado por otro proceso.`

**Causa Raíz:**  
Microsoft Defender (`MsMpEng.exe` vía `WdFilter.sys`) bloqueó temporalmente el archivo para análisis de firmas en la nube o emulación heurística.

**Solución Paso a Paso:**
1. **No crear exclusiones:** No excluya la carpeta de descargas ni el directorio temporal.
2. **Verificar el estado del SSCE:**
   ```bash
   samulibre wdhe status
   ```
   Compruebe que el contador `Bloqueos I/O Prevenidos` esté incrementándose, lo que indica que el reintento automático con backoff exponencial está funcionando.
3. **Ejecutar escaneo coordinado:**
   ```bash
   samulibre wdhe smart-scan <ruta_archivo> --priority high
   ```
   El Smart Scan Coordinator abrirá el archivo con flags `FILE_SHARE_READ | FILE_SHARE_WRITE`, reintentando hasta 3 veces (10ms, 20ms, 40ms) hasta que Defender libere el handle.

---

### ESCENARIO 2: DEFENDER DETECTA UN BINARIO DE PRUEBA DE SAMULIBRE (EICAR / AMTSO)
**Síntoma:**  
Notificación de Windows Security: `Virus:DOS/EICAR_Test_File detectado en temp\test_eicar.com`.

**Causa Raíz:**  
Durante la ejecución del arnés de pruebas o laboratorio de certificación, SamuLibre escribió una muestra de validación estándar EICAR. Defender interceptó correctamente el archivo.

**Solución Paso a Paso:**
1. **Ejecutar el Investigador de Falsos Positivos:**
   ```bash
   samulibre wdhe fp-investigate --max 5
   ```
2. **Revisar el veredicto:**  
   El motor confirmará: `Clasificación: ARTEFACTO DE PRUEBA (TestArtifactPayload)`.
3. **Confirmación:**  
   El sistema funciona según el diseño. No intente excluir `test_eicar.com` ni restaurar archivos fuera del entorno de sandbox.

---

### ESCENARIO 3: ALTO CONSUMO DE CPU DURANTE COMPILACIONES O JUEGOS
**Síntoma:**  
Uso combinado de CPU de SamuLibre y Defender superior al 60% durante tareas intensivas de usuario (compilador `cargo`/`rustc`, render en `blender` o videojuegos).

**Causa Raíz:**  
Ambos motores están procesando ráfagas continuas de nuevos archivos `.o`, `.obj`, `.dat` en el disco.

**Solución Paso a Paso:**
1. **Comprobar perfil del Resource Governor:**
   ```bash
   samulibre wdhe status
   ```
   Verifique si `Throttling Dinámico Activo` está en `SÍ`.
2. **Cambiar al perfil Silencioso:**
   ```bash
   samulibre wdhe profile silent
   ```
   Esto fuerza a SamuLibre a reducir la concurrencia a 1 hilo y aplicar 20ms de retardo entre archivos, cediendo el procesador al usuario.
3. **Una vez finalizada la tarea pesada:**
   ```bash
   samulibre wdhe profile balanced
   ```

---

### ESCENARIO 4: VERIFICACIÓN DEL ESTADO DE WINDOWS SECURITY CENTER
**Síntoma:**  
Duda sobre si SamuLibre está interfiriendo o si Windows reconoce a Defender como proveedor activo.

**Solución Paso a Paso:**
1. **Consultar el repositorio WMI oficial:**
   ```bash
   samulibre wdhe wsc
   ```
2. **Interpretar los resultados:**
   - Si Windows Defender muestra `productState: 397568 (0x061100)`:
     - Escáner Activo: **HABILITADO (0x10)**
     - Definiciones: **AL DÍA (0x00)**
   - Si SamuLibre está en Modo Complementario, ambos conviven de forma transparente.
   - En la sección `VERIFICACIÓN DE CONMUTACIÓN POR ERROR (FAILOVER)` debe leerse:
     `Microsoft Defender detectado en WSC (...). La transición por conmutación por error está plenamente operativa.`

---

### ESCENARIO 5: SOLICITUD DE EXCLUSIÓN AUDITADA
**Síntoma:**  
Un software propietario de la organización genera falsos positivos repetidos con ambos motores.

**Solución Paso a Paso:**
1. **Evaluar la exclusión con el evaluador seguro:**
   ```bash
   samulibre wdhe exclusions check "C:\SoftwareInterno\app.exe" --rule-type file --reason "Software propio firmado"
   ```
2. **Si es rechazada por política:**  
   Revise el motivo (p. ej. intento de excluir `C:\` o extensiones completas `*.exe`). Modifique la ruta para apuntar exclusivamente al ejecutable específico.
3. **Consultar la recomendación arquitectónica:**
   ```bash
   samulibre wdhe exclusions recommend "sharing violation on app.exe"
   ```
   Priorice siempre la apertura compartida sin exclusión antes de solicitar privilegios administrativos.
