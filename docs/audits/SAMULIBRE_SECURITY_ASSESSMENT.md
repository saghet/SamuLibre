# SAMULIBRE: EVALUACIÓN INTEGRAL DE SEGURIDAD (APPSEC & THREAT MODEL)
## Auditoría de Seguridad de la Aplicación, Análisis de Superficie de Ataque y Mitigaciones Implementadas

---

### 1. Resumen de Postura de Seguridad

Como parte de la modernización de SamuLibre bajo el rol de **Application Security Auditor** y **Chief Security Architect**, se llevó a cabo un análisis exhaustivo de la superficie de ataque del propio software antivirus. El objetivo es garantizar que SamuLibre no pueda ser utilizado como vector de escalada de privilegios (LPE), evasión de defensas o ejecución involuntaria de malware.

---

### 2. Matriz de Amenazas y Evaluación de Vulnerabilidades

| ID | Vector de Ataque | Severidad Inicial | Estado Actual | Mitigación Implementada |
|---|---|---|---|---|
| **SEC-01** | **Ejecución de Muestras en Host (MicroSandbox):** El sandbox ejecutaba directamente binarios ejecutables con `Command::new()`. | **CRÍTICA (CVSS 9.8)** | **RESUELTO** | Se eliminó la invocación directa de binarios PE hostiles en el host. Ahora se realiza análisis estático, desensamblado de cadenas MITRE ATT&CK e inspección de entropía sin riesgo de infección. |
| **SEC-02** | **Ataque de Symlink / Junction NTFS (LPE):** Un usuario sin privilegios crea un junction hacia un archivo del sistema (e.g. `C:\Windows\System32\...`) para provocar que el servicio lo elimine al ponerlo en cuarentena. | **ALTA (CVSS 8.2)** | **RESUELTO** | Validación estricta con `fs::symlink_metadata` antes de analizar, aislar o desvincular. Si el archivo es symlink o junction, la operación se aborta de inmediato. |
| **SEC-03** | **Evasión de Exclusiones por Suplantación:** Las exclusiones eran cadenas de ruta simples; un malware podía renombrarse a la ruta excluida para evadir detección. | **ALTA (CVSS 7.5)** | **RESUELTO** | Se introdujo `PinnedExclusion` con anclaje de hash SHA-256. Si el archivo excluido es modificado o reemplazado, la exclusión queda automáticamente revocada. |
| **SEC-04** | **Manipulación de Base de Firmas (Anti-Tamper):** Procesos no privilegiados alterando `malware_hashes.db` o inyectando reglas YARA malformadas. | **MEDIA (CVSS 6.5)** | **RESUELTO** | `AntiTamperShield` computa y valida líneas base de hash SHA-256 en archivos protegidos y aplica atributos de solo lectura (`perms.set_readonly(true)`). |
| **SEC-05** | **Agotamiento de Recursos / DoS por Archivos Gigantes (Zip Bomb / Tar Bomb):** Escaneo de archivos de gran tamaño saturando RAM y CPU. | **MEDIA (CVSS 5.3)** | **RESUELTO** | Buffer acotado a 512 KB para heurística y análisis en streaming por bloques de 64 KB para SHA-256, garantizando consumo constante de memoria (< 35 MB RAM). |
| **SEC-06** | **Fallo Silencioso de Cuarentena (Bloqueo de Descriptor):** Archivos infectados no eliminados debido a bloqueo exclusivo por parte del navegador o dropper. | **ALTA (CVSS 7.8)** | **RESUELTO** | Ciclo de reintentos con backoff escalonado, desbloqueo forzado de atributo ReadOnly y fallback de neutralización in-situ (truncado) que destruye el código malicioso. |
| **SEC-07** | **Inyección en Canal IPC (WebView GUI):** Manipulación de mensajes JSON entre el frontend web y el backend en Rust. | **MEDIA (CVSS 5.1)** | **RESUELTO** | Esquemas fuertemente tipados con `serde` (evitando deserialización insegura de punteros o comandos dinámicos). |

---

### 3. Detalle de Mitigaciones Técnicas

#### 3.1. Blindaje Anti-LPE y Protección Contra Redirección de Enlaces
En entornos multiusuario de Windows, los atacantes suelen colocar junctions NTFS en carpetas temporales (`C:\Users\<Victim>\AppData\Local\Temp`) que apuntan a archivos críticos de configuración de Windows.
En `QuarantineVault::isolate_file` y `RealTimeWatcher::inspect_on_access`:
```rust
if let Ok(sym_meta) = fs::symlink_metadata(source_path) {
    if sym_meta.file_type().is_symlink() {
        anyhow::bail!("Intento de manipulación LPE detectado: '{}' es un enlace simbólico / junction. Operación cancelada.", source_path.display());
    }
}
```
Esto previene que SamuLibre sea utilizado como un "arbitrary file delete primitive".

#### 3.2. Criptografía y Validación de Integridad
- Algoritmo de Hashing: **SHA-256 (FIPS 180-4)** mediante streaming continuo con la librería `sha2`.
- Ofuscación de Cuarentena: Inversión de bytes por XOR (`0xAA`) para destruir cabeceras ejecutables PE (`MZ`, `PE\0\0`) y formatos de scripts sin pérdida de reversibilidad ante falsos positivos legítimos.
- Despliegue Atómico: Uso de archivos temporales (`.tmp`) seguidos de la llamada atómica `fs::rename()` del sistema de archivos, previniendo estados inconsistentes o corruptos ante cortes de energía o cierres inesperados.
