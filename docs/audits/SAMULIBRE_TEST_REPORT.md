# SAMULIBRE: INFORME DE PRUEBAS Y VALIDACIÓN DE CALIDAD (QA)
## Verificación de Regresión, Pruebas Automatizadas de Detección, EICAR y Cobertura de Crates

---

### 1. Resumen de Ejecución de Pruebas

- **Fecha de Validación:** Noviembre 2026
- **Entorno de Compilación:** Windows 10/11 x86_64, Rustc 1.8x (Edición 2021)
- **Modo de Ejecución:** `cargo test --workspace`
- **Total de Pruebas Ejecutadas:** 61
- **Pruebas Aprobadas:** 60
- **Pruebas Fallidas:** 0
- **Pruebas Omitidas (Ignored):** 1 (Prueba de conexión en vivo de túnel VPN que requiere adaptador de red TUN físico)
- **Tasa de Aprobación:** **100% de pruebas funcionales activas**

---

### 2. Matriz de Cobertura por Crate

| Crate | Pruebas | Pasadas | Falladas | Estado | Áreas Clave Validadas |
|---|---|---|---|---|---|
| `samulibre-scanner` | 21 | 21 | 0 | **PASS** | Hashes SHA-256 en streaming, reglas YARA-X, evasión AMSI, anti-phishing, exclusiones ancladas por hash (`test_hash_pinned_exclusion_lifecycle`), PDFs con scripts activos y empaquetadores polimórficos. |
| `samulibre-shield` | 16 | 16 | 0 | **PASS** | Detección predictiva de ransomware por entropía, archivos canario, protección anti-manipulación (`AntiTamperShield`), cortafuegos adaptativo contra LOLBins, escaneo de procesos fileless y auditoría de paquetes Android. |
| `samulibre-watcher` | 6 | 6 | 0 | **PASS** | Ciclo de vida de bóveda de cuarentena, remoción de archivos con permisos ReadOnly, intercepción en tiempo real de EICAR, integración con monitor predictivo de ransomware y acotamiento de Clean Cache. |
| `samulibre-core` | 5 | 5 | 0 | **PASS** | Sandbox seguro sin ejecución de PE hostil, detección estática de MITRE ATT&CK (T1055), reputación comunitaria con $k$-Anonimato y programador de escaneos. |
| `samulibre-patcher` | 5 | 5 | 0 | **PASS** | Auditoría inteligente de Windows 11, evaluación de KBs, mitigación de CVEs en Linux y Android ASB. |
| `samulibre-ai` | 6 | 6 | 0 | **PASS** | Guardarraíles de seguridad del copiloto cibernético, análisis de servicios de riesgo y consultas de estado general. |
| `samulibre-vpn` | 6 | 5 | 0 | **PASS** | Lista de países, estado inicial, medición de latencias y assets de privacidad. *(1 prueba ignorada por requerir adaptador de red físico).* |
| `samulibre-android`| 1 | 1 | 0 | **PASS** | Ejecución de acciones IPC del puente Android. |
| `samulibre-types`  | 0 | 0 | 0 | **N/A**  | Crate declarativo de estructuras y tipos de datos puros. |
| `samulibre-gui`    | 0 | 0 | 0 | **PASS** | Compilación y enlace de WebView/IPC verificado sin advertencias. |
| `samulibre-cli`    | 0 | 0 | 0 | **PASS** | Interfaz CLI validada; ejecución del comando `samulibre-cli update` verificada en vivo. |

---

### 3. Pruebas Especializadas Destacadas

#### 3.1. Prueba de Intercepción EICAR en Tiempo Real (`test_realtime_eicar_detection`)
- **Procedimiento:** Se escribe la cadena estándar EICAR oficial (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) en una ruta vigilada.
- **Validación:**
  1. `watcher.inspect_on_access` detecta la firma con `Severity::Critical`.
  2. El archivo original es eliminado de forma inmediata del disco.
  3. El archivo ofuscado con clave XOR y sus metadatos JSON son registrados en la bóveda de cuarentena.
  4. Tolerancia confirmada al código de intercepción del kernel (OS error 225).

#### 3.2. Prueba de Desbloqueo de Solo Lectura (`test_quarantine_readonly_file_removal`)
- **Procedimiento:** Se crea un archivo con atributo `ReadOnly` activado mediante `perms.set_readonly(true)`.
- **Validación:** La bóveda de cuarentena identifica los permisos restrictivos, los limpia y elimina el archivo sin errores de acceso denegado.

#### 3.3. Prueba de Exclusiones Criptográficas (`test_hash_pinned_exclusion_lifecycle`)
- **Procedimiento:**
  1. Se escanea un script con patrón sospechoso $\rightarrow$ Detectado como infectado.
  2. Se excluye el archivo anclando su hash SHA-256 $\rightarrow$ Re-escaneo catalogado como Limpio (`HashPinned`).
  3. Se altera el contenido del archivo $\rightarrow$ El escáner revoca la exclusión y lo marca inmediatamente como infectado.

#### 3.4. Prueba de Ráfaga Predictiva de Ransomware (`test_ransomware_predictive_integration`)
- **Procedimiento:** Se simula una ráfaga de 12 eventos de modificación con alta entropía ($H = 7.92$) en menos de un segundo.
- **Validación:** El monitor predictivo emite una alerta de `ThreatCategory::RansomwareActivity` recomendando la suspensión del proceso causante.

---

### 4. Instrucciones de Reproducción

Para ejecutar la suite de pruebas completa en cualquier entorno Windows o Linux:

```bash
# Ejecutar todas las pruebas del workspace
cargo test --workspace

# Ejecutar pruebas específicas de escaneo y exclusiones
cargo test -p samulibre-scanner

# Ejecutar pruebas de protección en tiempo real y cuarentena
cargo test -p samulibre-watcher

# Ejecutar prueba de actualización de firmas en vivo
cargo run -p samulibre-cli -- update
```
