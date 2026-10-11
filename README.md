# Antivirus SamuLibre 🛡️

**Suite Integral de Ciberseguridad, EDR, Parchado Virtual y Navegación Privada**  
*100% Código Abierto | 0% Anuncios | Sin Muros de Pago | Licencia GPL-3.0*

---

## 🌟 Visión del Proyecto
SamuLibre nace para democratizar la ciberseguridad avanzada en estaciones de trabajo y servidores, integrando lo mejor de las iniciativas de código abierto (**ClamAV**, **YARA-X**, **OpenEDR**, **Wazuh**, **PRX-SD**) en un solo ecosistema ligero, modular y desarrollado en **Rust**.

---

## 📦 Estructura del Workspace

```
Antivitus-SamuLibre/
├── crates/
│   ├── samulibre-types/     # Modelos de datos comunes (Alertas, Reglas, Estados)
│   ├── samulibre-patcher/   # Motor de Parchado Virtual Autónomo (Detección de KBs y WFP)
│   ├── samulibre-shield/    # Escudo Anti-Hackers (LSASS Guard, Cookies Web, Canarios)
│   ├── samulibre-scanner/   # Motor Multi-Engine (Firmas ClamAV, YARA-X, Entropía)
│   ├── samulibre-vpn/       # Cliente WireGuard, Kill-Switch y DNS Cifrado (Quad9/AdGuard)
│   ├── samulibre-core/      # Orquestador central, demonio de fondo y bus de eventos
│   └── samulibre-cli/       # Herramienta de línea de comandos interactiva
├── data/
│   ├── canaries/            # Trampas canario anti-ransomware desplegadas
│   ├── vpn/                 # Perfiles de conexión segura WireGuard
│   └── test_samples/        # Muestras de prueba de laboratorio
└── Cargo.toml               # Workspace de Rust
```

---

## 🚀 Capacidades Principales Implementadas

### 1. 🩹 Motor de Parchado Virtual Autónomo (`samulibre-patcher`)
- **Detección Local**: Analiza las actualizaciones instaladas en el SO (`Get-HotFix` / Registro) y las cruza contra la base de datos de vulnerabilidades críticas conocidas (CVE-2024-38063 IPv6 RCE, CVE-2024-38077 RDP Licensing, PrintNightmare, Follina, EternalBlue).
- **Mitigación Dinámica**: Aplica reglas de firewall WFP, endurecimiento de registro o mitigación de servicios para bloquear el vector de ataque antes de que el usuario reciba o instale la actualización del fabricante.
- **Desactivación Automática Inteligente**: Comprueba de forma continua la instalación de parches oficiales del SO. En el instante en que detecta que Windows instaló la actualización nativa correspondiente (KB oficial), **retira automáticamente la regla de parche virtual**, eliminando la sobrecarga en el sistema.

### 2. 🛡️ Escudo Endpoint contra Tácticas de Hackers (`samulibre-shield`)
- **Protección de Memoria LSASS**: Monitorea procesos e intercepta intentos de volcado de credenciales (ataques estilo Mimikatz, NanoDump, ProcDump, o invocaciones maliciosas de `comsvcs.dll`).
- **Escudo de Cookies y Tokens Web**: Protege los almacenes de sesión y credenciales de navegadores basados en Chromium (Chrome, Edge, Brave) y Firefox contra troyanos *InfoStealers* (RedLine, Lumma, Vidar).
- **Trampas Anti-Ransomware con Archivos Canario**: Despliega archivos señuelo con nombres atractivos en ubicaciones estratégicas. Si cualquier proceso anómalo intenta modificar, cifrar o borrar un canario, el sistema activa la alerta crítica y congela el proceso atacante antes del cifrado de datos reales.

### 3. 🔍 Motor de Escaneo Multi-Engine (`samulibre-scanner`)
- **Firmas Hash**: Compatibilidad con hashes de malware abiertos de ClamAV y feeds comunitarios de Abuse.ch / MalwareBazaar.
- **Reglas YARA-X**: Inspección en memoria y disco con expresiones regulares de alto rendimiento para detectar droppers de PowerShell ofuscados, intentos de bypass de AMSI y extractores de DPAPI.
- **Detección de Entropía de Shannon**: Identifica ejecutables empaquetados o con payloads cifrados.

### 4. 🌐 Privacidad y Navegación Libre (`samulibre-vpn`)
- **Núcleo WireGuard**: Generación y gestión de perfiles de conexión abierta y rápida.
- **DNS Cifrado Libre**: Integración con **Quad9** (`9.9.9.9`, fundación sin fines de lucro en Suiza para bloqueo de malware) y **AdGuard Libre**.
- **Kill-Switch de Firewall**: Prevención de fugas de tráfico fuera del túnel seguro.

---

## 💻 Guía de Uso del CLI y GUI

### Iniciar la Interfaz Gráfica Nativa (Estilo Apple)
```bash
cargo run -p samulibre-gui
```
*(O ejecuta directamente el binario compilado: `target/debug/samulibre-gui.exe`)*

### Estado Global (Línea de Comandos)
```bash
cargo run -p samulibre-cli -- status
```

### Ejecutar Demostración Integral
```bash
cargo run -p samulibre-cli -- demo
```

### Gestión de Parchado Virtual
```bash
# Escanear vulnerabilidades abiertas del SO
cargo run -p samulibre-cli -- patcher scan

# Aplicar mitigaciones de parchado virtual
cargo run -p samulibre-cli -- patcher apply

# Probar la desactivación automática al detectar un parche nativo (Ej. KB5041585)
cargo run -p samulibre-cli -- patcher simulate-install KB5041585
```

### Escudo de Endpoint y Canarios
```bash
# Desplegar trampas anti-ransomware
cargo run -p samulibre-cli -- shield deploy-canaries

# Auditar procesos activos
cargo run -p samulibre-cli -- shield check
```

### VPN y Navegación
```bash
# Exportar configuración WireGuard libre
cargo run -p samulibre-cli -- vpn export-config

# Configurar DNS Seguro con bloqueo de malware
cargo run -p samulibre-cli -- vpn secure-dns quad9
```
