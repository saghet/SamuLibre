# Política de Seguridad (Security Policy)

SamuLibre se compromete a garantizar la máxima transparencia técnica, integridad criptográfica y seguridad defensiva en todos sus componentes.

---

## 1. Versiones Compatibles (Supported Versions)

Actualmente, solo la versión más reciente del árbol de desarrollo recibe parches de seguridad activos:

| Versión | Estado de Soporte |
| :--- | :--- |
| **2.1.x** | :white_check_mark: Soportada activamente |
| < 2.0.0 | :x: No soportada |

---

## 2. Divulgación Responsable de Vulnerabilidades (Reporting a Vulnerability)

Si has descubierto una vulnerabilidad de seguridad en SamuLibre (por ejemplo, bypass del motor de análisis, condición de carrera en el vigilante, problemas de elevación de privilegios en el servicio SCM o debilidades en el cifrado de la bóveda de cuarentena), **por favor NO abras un Issue público en GitHub**.

Para reportar vulnerabilidades de forma responsable y confidencial:

1. **GitHub Security Advisories (Recomendado):**  
   Envía un reporte privado a través de la pestaña [Security > Advisories](https://github.com/saghet/SamuLibre/security/advisories) del repositorio oficial.
2. **Correo Electrónico de Seguridad:**  
   Envía los detalles técnicos a: `security@samulibre.org` (o al mantenedor principal del repositorio).

### Información que debes incluir:
- Descripción detallada de la vulnerabilidad y vector de ataque.
- Componente afectado (`samulibre-watcher`, `samulibre-shield`, `samulibre-gui`, `samulibre-cli`, etc.).
- Pasos exactos para reproducir la vulnerabilidad (PoC).
- Impacto potencial en el sistema operativo anfitrión.
- Versión de SamuLibre y sistema operativo de prueba (Windows 10, Windows 11 o Linux).

### Compromiso de Respuesta:
- **Confirmación inicial:** En un plazo máximo de 48 horas laborables.
- **Evaluación y triaje:** En menos de 5 días hábiles.
- **Parche correctivo:** Se publicará un parche y un aviso de seguridad (*Security Advisory*) antes de cualquier divulgación pública.

---

## 3. Política de Muestras y Archivos de Prueba (Malware Testing Policy)

- **Prohibición de Malware Real:** Por diseño y política de seguridad de la comunidad, **está terminantemente prohibido subir muestras de malware activo o código malicioso ejecutable al repositorio**.
- **Pruebas Estándar EICAR:** Todas las pruebas automatizadas y funcionales del motor de firmas y tiempo real se realizan utilizando la cadena estándar oficial **EICAR Standard Anti-Virus Test File** (`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`) o muestras simuladas benignas generadas en memoria durante la ejecución de los tests.
- **Aislamiento de Cuarentena:** Todos los artefactos detectados en entornos de prueba locales se neutralizan mediante cifrado XOR reversible y aislamiento en `data/quarantine/`, impidiendo cualquier ejecución involuntaria en el sistema anfitrión.

---

## 4. Auditoría de Integridad y Verificación de Cadena de Suministro

- **Criptografía SHA-256:** Todos los ejecutables oficiales, binarios de servicio y paquetes de firmas incluyen hashes criptográficos SHA-256 publicados en las notas de lanzamiento (*Releases*).
- **Protección Anti-Tampering:** SamuLibre incluye protecciones residentes en memoria y canarios de integridad para detectar intentos de inyección DLL, parches no autorizados en caliente y suspensión forzada del proceso.
