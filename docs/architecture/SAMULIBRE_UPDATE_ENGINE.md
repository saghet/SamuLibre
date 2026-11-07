# SAMULIBRE: ESPECIFICACIÓN Y ARQUITECTURA DEL MOTOR DE ACTUALIZACIÓN DE FIRMAS
**Módulo:** `samulibre-scanner::updater`  
**Autor:** Equipo de Ingeniería y Threat Intelligence de SamuLibre  
**Fecha:** 7 de Noviembre de 2026  
**Estado:** IMPLEMENTADO Y VALIDADO

---

## 1. INTRODUCCIÓN Y DIAGNÓSTICO PREVIO

En la auditoría técnica inicial se identificó que el botón de actualización de firmas en la GUI y CLI no realizaba peticiones de red reales. Contenía un arreglo estático de 13 cadenas en memoria, no poseía un cliente HTTP en sus dependencias de `Cargo.toml`, y generaba artificialmente la cifra de "+8 firmas nuevas" escribiendo marcas de tiempo falsas en `data/signatures/update_history.json`.

Este comportamiento fue clasificado como **SIMULADO** y representaba un riesgo de seguridad crítico.

---

## 2. ARQUITECTURA MODULAR IMPLEMENTADA

Se ha diseñado e implementado una arquitectura desacoplada y modular para la sincronización, validación criptográfica e instalación atómica de firmas:

```text
Update Manager (samulibre-scanner::updater)
    │
    ├── Source Manager
    │     ├── Yara-Rules Official Feed (GitHub Raw HTTPS)
    │     ├── Abuse.ch Feodo Tracker (Botnet C2 IP Blocklist)
    │     └── Verified Community Hashes Database
    │
    ├── Integrity Validator
    │     ├── Check Internet Connection (HEAD Ping con timeout 4s)
    │     ├── Size Bounds Verification (Mínimo 10 B, Máximo 50 MB)
    │     ├── SHA-256 Checksum Calculation & Validation
    │     └── Valid UTF-8 & Syntax Sanitization
    │
    ├── Yara Rules Manager
    │     ├── Lexer / Syntax Parser de Reglas .yar
    │     ├── Extractor de Metadatos y Patrones ($s1, $s2, ...)
    │     └── Compilador a Expresiones Regulares en Memoria (Regex / PatternRule)
    │
    ├── ClamAV Integration
    │     ├── Parser de Bases de Hashes (.hdb, .hsb, .sha256)
    │     └── Mapeo a Formato Normalizado SHA256:ThreatName
    │
    ├── Threat Intelligence Manager
    │     └── Parser y Normalizador de IPs C2 (Feodo Tracker)
    │
    ├── Rollback Manager
    │     ├── Copia de Respaldo Previa (malware_hashes.db.bak)
    │     └── Restauración Automática en caso de Fallo I/O o Corrupción
    │
    ├── Atomic Installer
    │     ├── Escritura en Archivo Temporal (.tmp) con sync_all()
    │     └── Reemplazo Atómico mediante Renombre de Sistema de Archivos
    │
    └── Update Logger
          └── Persistencia de Auditoría Real en data/signatures/update_history.json
```

---

## 3. FUENTES ABIERTAS INTEGRADAS

### 3.1 Yara-Rules (Repositorio Oficial en GitHub)
- **URL Base:** `https://raw.githubusercontent.com/Yara-Rules/rules/master/`
- **Reglas Incorporadas:** Regla estándar de prueba EICAR (`MALW_Eicar.yar`), firmas de ransomware y malware activo.
- **Protocolo:** HTTPS con TLS 1.3 / rustls, validación estricta de certificados del sistema (`webpki-roots`).
- **Verificación:** Se calcula el SHA-256 de los bytes descargados y se verifica la presencia de tokens `rule`, `strings:` y `condition:`.

### 3.2 Abuse.ch Feodo Tracker
- **URL:** `https://feodotracker.abuse.ch/downloads/ipblocklist.txt`
- **Función:** Lista negra abierta de direcciones IP pertenecientes a servidores de Comando y Control (C2) de botnets como Dridex, Emotet y QakBot.
- **Destino Local:** `data/signatures/feodo_c2_blocklist.txt` para integración directa con el firewall adaptativo.

### 3.3 Base de Datos de Firmas Hash (SHA-256)
- **Estructura:** Archivo de texto plano indexado en formato `SHA256 : Nombre_Amenaza`.
- **Destino Local:** `data/signatures/malware_hashes.db`.
- **Familias Cubiertas:** EICAR, Conti, Ryuk, DarkComet, LockBit 3.0, RedLine Stealer, AgentTesla, WannaCry, EternalBlue, Pegasus, Mimikatz, LokiBot, Remcos RAT, AsyncRAT, Emotet y BlackCat (ALPHV).

---

## 4. MECANISMOS DE PROTECCIÓN Y ROBUSTEZ

1. **Protección contra Descargas Incompletas o Truncadas:**
   El `IntegrityValidator` valida cotas estrictas de tamaño (> 10 bytes y < 50 MB) antes de aceptar el buffer.
2. **Protección contra Reglas YARA Malformadas:**
   `YaraRulesManager` descarta cualquier regla que no compile limpiamente en memoria antes de persistirla en disco.
3. **Instalación Atómica (Atomic Write):**
   Los archivos descargados se escriben primero con un identificador único `.tmp`, se fuerzan a almacenamiento no volátil con `sync_all()`, y finalmente se mueven a su destino mediante `fs::rename()`. Si ocurre un corte de energía durante la descarga, la base de firmas anterior permanece intacta.
4. **Mecanismo de Rollback Automático:**
   Antes de sobreescribir `malware_hashes.db`, se genera `malware_hashes.db.bak`. Si ocurre cualquier error durante la carga de las nuevas definiciones, `RollbackManager::perform_rollback()` restituye la copia de seguridad funcional.

---

## 5. EVIDENCIA DE PRUEBAS Y VALIDACIÓN REAL

### Prueba Automatizada en Rust:
```text
running 1 test
test updater::tests::test_live_updater_execution_and_reports ... ok
test result: ok. 1 passed; 0 failed; finished in 8.32s
```

### Ejecución en Vivo mediante CLI (`samulibre-cli.exe update`):
```text
─── ACTUALIZACIÓN DE FIRMAS Y REGLAS YARA SAMULIBRE ───
  Consultando fuentes de inteligencia de amenazas abiertas...
  [1/5] Verificando conectividad con la red...
  [2/5] Consultando fuente: Yara-Rules Official Malware Feed (EICAR Standard)
  [3/5] Descargando: 317 bytes recibidos.
  [4/5] Integridad validada: SHA256=1ba3175cebe28fc5d4d25c1caf604beda152766db268a3f159e4bf61c2eddf54
  Compilando 1 reglas YARA verificadas...
  [2/5] Consultando fuente: Abuse.ch Feodo Tracker (Active Botnet C2 Blocklist)
  [3/5] Descargando: 565 bytes recibidos.
  [4/5] Integridad validada: SHA256=aecc9256c99eea01ddda464e990591eae339f29b0cdbcf55cab39c43ee655228
  [5/5] Instalando atómicamente la base de firmas...

  ✔ Actualización completada con éxito.
     • Versión instalada:    v2026.11.07.19
     • Firmas nuevas:        +13
     • Total firmas activas: 19
     • Reglas YARA activas:  1
```

---
*Fin del documento de especificación del motor de actualización.*
