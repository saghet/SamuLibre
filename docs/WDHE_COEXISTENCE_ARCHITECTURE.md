# ARQUITECTURA DE COEXISTENCIA: WINDOWS DEFENDER HARMONY ENGINE (WDHE)
## Diseño Técnico de Interoperabilidad, Smart Scan y Gobernanza de Recursos
**Proyecto:** SamuLibre Endpoint Protection Suite  
**Clasificación:** Especificación de Arquitectura de Seguridad (Fases 3, 4, 5, 6 y 8)  
**Versión del Motor:** WDHE v2.1.13  

---

## 1. PRINCIPIOS DE ARQUITECTURA

El **Windows Defender Harmony Engine (WDHE)** fue concebido bajo cuatro pilares irrenunciables:

1. **No-Agresión y Cero Manipulación:** SamuLibre nunca intenta detener, deshabilitar, desconfigurar ni ocultar componentes de Microsoft Defender ni de Windows Security.
2. **Coexistencia Sinérgica:** Ambos motores suman capacidades defensivas (firmas comunitarias + heurística local + cloud protection de Microsoft) sin crear puntos ciegos ni tormentas de I/O.
3. **Respeto a las Políticas del Sistema:** Toda integración con Windows Security Center (WSC) se rige por los canales oficiales y especificaciones de Microsoft ISV.
4. **Gobernanza Dinámica de Recursos:** La seguridad del equipo jamás debe degradar la experiencia de usuario ni generar picos descontrolados de CPU, RAM o disco.

---

## 2. MODALIDADES DE OPERACIÓN DEL WDHE

El motor implementa una máquina de estados determinista con 3 modalidades:

```
               ┌────────────────────────────────────────────────────────┐
               │              MODO DESARROLLO (Development)             │
               │   Defender: Primario Activo | SamuLibre: Bajo Demanda   │
               │   • Telemetría de conflictos | • Medición Benchmark     │
               └───────────────────────────┬────────────────────────────┘
                                           │
                               Transición de Madurez
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │            MODO COMPLEMENTARIO (Complementary)         │
               │   Ambos Motores Activos | Protección en Tiempo Real     │
               │   • Smart Scan Coordinator (SSCE) | • Clean Hash Cache  │
               │   • Prevención de I/O Contention (Shared Read Locks)   │
               └───────────────────────────┬────────────────────────────┘
                                           │
                              Certificación WSC Validada
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │           MODO ANTIVIRUS PRINCIPAL (PrimaryAntivirus)   │
               │   SamuLibre: Proveedor Principal en SecurityCenter2    │
               │   • Handshake WSC oficial | • Defender en Modo Pasivo  │
               │   • Failover Watchdog: Reactivación automática si cae   │
               └────────────────────────────────────────────────────────┘
```

### A. Modo Desarrollo (`WdheMode::Development`)
- Microsoft Defender permanece 100% activo como la defensa primaria del endpoint.
- SamuLibre opera inicialmente bajo demanda o monitoreando directorios controlados.
- Registra métricas de contienda de I/O y latencias sin interferir en el flujo de trabajo del desarrollador.

### B. Modo Complementario (`WdheMode::Complementary` - Por Defecto)
- Ambos productos proporcionan protección activa en tiempo real de forma coordinada.
- El **Smart Scan Coordination Engine (SSCE)** administra una cola priorizada de análisis.
- Se previene la contienda de lectura compartiendo locks (`FILE_SHARE_READ | FILE_SHARE_WRITE`) con reintentos exponenciales.

### C. Modo Antivirus Principal (`WdheMode::PrimaryAntivirus`)
- Activado cuando SamuLibre cumple los requisitos de certificación (firma Authenticode, estabilidad de servicio y catálogo de firmas actualizado).
- Se comunica oficialmente con Windows Security Center a través de WMI `root\SecurityCenter2` reportando el bitmask `productState`.
- Windows gestiona legítimamente la transición de Microsoft Defender a **Modo Pasivo** (análisis periódico en segundo plano sin escáner on-access concurrente).
- **Failover Watchdog:** Si el servicio de SamuLibre se interrumpe, Windows detecta el cese y restaura Defender inmediatamente a Modo Activo.

---

## 3. SMART SCAN COORDINATION ENGINE (SSCE)

Para evitar duplicación innecesaria de análisis y bloqueos de I/O, el SSCE implementa:

### A. Cola Priorizada de Análisis
- **Critical (4):** Archivos descargados o ejecutables recién creados en tiempo real.
- **High (3):** Modificaciones en directorios de inicio (`Startup`, `AppData`).
- **Normal (2):** Escaneo bajo demanda solicitado por el usuario.
- **Low (1):** Tareas programadas periódicas.
- **Background (0):** Verificación de integridad en reposo.

### B. Clean Result Cache Criptográfica
- La caché almacena el cuarteto de verificación: `(canonical_path, size_bytes, mtime_unix, sha256_hash)`.
- Si el tamaño y la fecha de modificación (`mtime`) coinciden exactamente, el archivo se considera limpio con **latencia < 1 ms** y **0 bytes leídos de disco**.
- Cualquier alteración en el contenido o metadatos invalida la entrada de inmediato.

### C. Patrón de Acceso a Archivos Sin Contienda
Cuando Microsoft Defender intercepta un archivo recién creado, el Filter Manager de Windows retiene temporalmente el handle.
Si un antivirus secundario intenta abrir el archivo con exclusividad (`FileAccess::ReadWrite`), Windows retorna `ERROR_SHARING_VIOLATION` (0x20).
SamuLibre mitiga esto con:
1. Solicitud de acceso con flags `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
2. Backoff exponencial de 3 niveles: si ocurre contienda, espera 10ms, luego 20ms, luego 40ms.
3. Apertura por streaming en búferes de 64KB para archivos de gran tamaño (> 10MB).

---

## 4. SAMULIBRE RESOURCE GOVERNOR (SRG)

El Gobernador de Recursos administra dinámicamente el impacto en hardware mediante cuatro perfiles:

| Perfil | Límite CPU | Concurrencia | Retardo Adaptativo | Uso de GPU | Propósito |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Silencioso** | < 15% | 1 hilo | 20 ms | Desactivada | Uso mientras el usuario navega o redacta documentos. |
| **Equilibrado** | < 40% | 3 hilos | 5 ms | Condicional | Operación estándar por defecto. |
| **Rendimiento** | < 75% | 6 hilos | 0 ms | Acelerada (DirectML) | Escaneos programados intensivos o análisis manual. |
| **Análisis Profundo** | < 85% | 2 hilos | 2 ms | Heurística PE | Desempaquetado y cálculo de entropía sin desbordar RAM. |

### Detección Dinámica de Cargas de Usuario
El SRG monitorea los procesos del sistema. Si detecta aplicaciones pesadas en primer plano (juegos como `cs2`, `cyberpunk2077`; entornos de desarrollo como `devenv`, `rustc`, `cargo`; herramientas de render como `blender`, `premiere`), activa el **Throttling Dinámico**:
- Reduce la concurrencia a 1 hilo.
- Introduce un retardo de 50ms entre archivos.
- **No detiene la protección esencial en tiempo real**, pero libera el 95% de la capacidad de cómputo para la aplicación del usuario.

---

## 5. POLÍTICA DE EXCLUSIONES SEGURAS Y BLINDAJE ANTI-BYPASS

El **Safe Exclusion Manager** prohíbe taxativamente:
1. Exclusiones de unidades de disco completas (`C:\`, `D:\`).
2. Exclusiones de directorios del sistema operativo (`C:\Windows`, `System32`, `SysWOW64`).
3. Exclusiones genéricas de perfiles de usuario (`C:\Users\*`).
4. Exclusiones comodín de extensiones ejecutables (`*.exe`, `*.dll`, `*.sys`, `*.ps1`, `*.bat`).
5. Exclusiones automáticas no auditadas.

Toda exclusión legítima requiere:
- Ruta absoluta validada sin enlaces simbólicos ni uniones NTFS.
- Anclaje obligatorio de hash SHA-256 (`sha256_pinned`).
- Justificación técnica documentada y aprobación explícita del administrador.
- Evaluación arquitectónica previa: si el conflicto puede resolverse mediante lectura compartida o sincronización de colas, se descarta la exclusión.

---

## 6. INTEGRACIÓN CON WINDOWS SECURITY CENTER

SamuLibre se comunica con WSC a través de WMI `root\SecurityCenter2` decodificando el campo entero de 24 bits `productState`:

- **Byte Alto (0x06):** Proveedor Antivirus Registrado de Terceros en Windows 10/11.
- **Byte Medio (0x10 / 0x00):** Escáner en Tiempo Real (`0x10` = Habilitado / Activo, `0x00` = Deshabilitado, `0x20` = Pausado).
- **Byte Bajo (0x00 / 0x10):** Definiciones de Inteligencia de Seguridad (`0x00` = Al Día, `0x10` = Obsoletas).

**Valor nominal de SamuLibre en estado óptimo:** `0x061000` (Habilitado y con firmas al día).
Cuando SamuLibre está en modo complementario, Defender permanece en `0x061100` (Activo y al día), conviviendo sinérgicamente.
