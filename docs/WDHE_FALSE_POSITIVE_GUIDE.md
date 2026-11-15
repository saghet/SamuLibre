# GUÍA DE INVESTIGACIÓN DE FALSOS POSITIVOS Y DISPUTAS CON MICROSOFT
## False Positive Investigation Engine (FPIE) & Microsoft Security Intelligence (WDSI)
**Proyecto:** SamuLibre Endpoint Protection Suite  
**Clasificación:** Procedimiento Forense y Guía de Resolución de Alertas (Fases 2 y 7)  
**Versión:** 2.1.13  

---

## 1. MISIÓN Y PRINCIPIOS DE NO-DESTRUCCIÓN

El **SamuLibre False Positive Investigation Engine** tiene como objetivo investigar técnica y objetivamente por qué Microsoft Defender emite detecciones sobre determinados componentes de SamuLibre o sobre cargas de prueba del entorno.

### Reglas de Integridad del FPIE:
- **No modifica los registros de Windows Defender.**
- **No borra ni intenta alterar el histórico de amenazas del sistema.**
- **No crea exclusiones automáticas para silenciar detecciones.**
- **Utiliza exclusivamente canales de lectura oficiales:** `Microsoft-Windows-Windows Defender/Operational` (Event IDs 1116, 1117, 1006) y WMI `MSFT_MpThreatDetection`.

---

## 2. TAXONOMÍA FORENSE DE CLASIFICACIÓN DE ALERTAS

Cuando el FPIE recopila un evento de detección, lo clasifica bajo una de las 5 categorías:

```
                                 ALERTA DETECTADA EN DEFENDER
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
         ¿Coincide con EICAR / AMTSO?                    ¿Proceso es SamuLibre?
         ├─ SÍ: [TestArtifactPayload]                    ├─ SÍ: ¿Detección Heurística?
         └─ NO: Continuar evaluación                     │      ├─ SÍ: [BenignFalsePositive]
                                                         │      └─ NO: [LegitimateCompromise]
                                                         └─ NO: [LegitimateCompromise]
```

1. **`TestArtifactPayload` (Artefacto de Prueba Controlada):**
   - Corresponde a la cadena estándar EICAR (`Virus:DOS/EICAR_Test_File`, Threat ID 2147519003) o muestras de prueba de AMTSO.
   - **Diagnóstico:** Comportamiento esperado y correcto del subsistema de seguridad.
   - **Acción:** Ninguna exclusión requerida; documentar en telemetría de validación.

2. **`BenignFalsePositive` (Falso Positivo Benigno Confirmado):**
   - Binario oficial de SamuLibre detectado por heurística genérica (`Trojan:Win32/Wacatac`, `Bearfoos`, `Heur.BML`).
   - Habitual en binarios Rust compilados en modo debug o con secciones de alta entropía.
   - **Acción:** Firmar con certificado Authenticode comercial y remitir paquete de disputa a Microsoft Security Intelligence (WDSI).

3. **`LegitimateCompromise` (Compromiso Legítimo de Seguridad):**
   - Detección sobre un archivo externo o binario alterado cuyo hash SHA-256 no coincide con el manifiesto oficial de compilación.
   - **Acción:** Mantener la cuarentena de Defender y emitir alerta de alta severidad al operador.

4. **`UnsignedSuspiciousBinary` (Binario No Firmado o Sospechoso):**
   - Archivo ejecutable generado en el entorno que carece de firma digital y muestra patrones anómalos.

5. **`UnknownInvestigationRequired` (Pendiente de Investigación Profunda):**
   - Requiere análisis dinámico en el MicroSandbox de SamuLibre antes de emitir veredicto.

---

## 3. PROCESO DE DISPUTA ANTE MICROSOFT SECURITY INTELLIGENCE (WDSI)

Cuando se confirma un falso positivo sobre un binario legítimo de SamuLibre, se sigue el protocolo oficial de la industria:

### Paso 1: Generación del Paquete de Disputa con SamuLibre CLI
```bash
samulibre wdhe verify-integrity
```
Este comando genera el manifiesto criptográfico sellado `samulibre-manifest.json` conteniendo el hash SHA-256 exacto, tamaño, versión y estado de firma de cada binario.

### Paso 2: Preparación de la Ficha Técnica de Disputa
El motor genera un objeto JSON estructurado con la información requerida por Microsoft:
- **Organización:** SamuLibre Security Community (Open Source Endpoint Protection).
- **Nombre de la Amenaza Asignada:** p. ej., `Trojan:Win32/Wacatac.B!ml` o `Virus:DOS/EICAR_Test_File`.
- **Threat ID:** Identificador numérico de Defender (ej. 2147519003).
- **SHA-256 del Archivo:** Hash exacto de 64 caracteres hexadecimales.
- **Entorno de Compilación:** Rust 1.80+ (MSVC 64-bit), mitigaciones de exploit habilitadas (`/GUARD:CF`, `/DYNAMICBASE`, `/NXCOMPAT`).
- **Justificación Técnica:** Descripción del propósito del binario y código fuente auditable en GitHub.

### Paso 3: Remisión en el Portal Oficial de Microsoft
1. Acceder al portal de envío de archivos de Microsoft:  
   `https://www.microsoft.com/en-us/wdsi/filesubmission`
2. Seleccionar la opción: **Software Developer (Submit files for false positive analysis)**.
3. Adjuntar el binario en formato comprimido cifrado (`.zip` con contraseña `infected` o según estándares de remisión).
4. Indicar el nombre exacto de la amenaza y la versión de inteligencia de Defender (`MpComputerStatus.AntivirusSignatureVersion`).
5. Tras la revisión automatizada y humana de los analistas de Microsoft, la firma es incorporada a la lista blanca global en la siguiente actualización de inteligencia de Defender (habitualmente en menos de 24 horas).
