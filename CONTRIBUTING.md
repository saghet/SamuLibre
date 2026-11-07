# Guía de Contribución a SamuLibre (Contributing Guide)

¡Gracias por tu interés en contribuir a **SamuLibre**! Como suite de ciberseguridad y antivirus de código abierto escrita en Rust, la calidad, la integridad y el rigor técnico son nuestra prioridad absoluta.

---

## 1. Código de Conducta

Al participar en este proyecto, te comprometes a seguir nuestro [Código de Conducta](CODE_OF_CONDUCT.md). Tratamos a todos los miembros de la comunidad con respeto, profesionalismo y colaboración técnica constructiva.

---

## 2. Requisitos Previos para Desarrolladores

Para compilar y probar SamuLibre localmente en tu estación de trabajo:

- **Rust:** Versión 1.80 o superior (Edición 2021). Instalar mediante [rustup.rs](https://rustup.rs/).
- **Cargo:** Incluido con Rust.
- **Sistema Operativo:** Windows 10/11 (x64) o Linux (Ubuntu, Debian, Fedora, Arch/Garuda).
- **Herramientas de compilación en Windows:** Visual Studio Build Tools con componentes C++ (MSVC).
- **Herramientas de compilación en Linux:** `build-essential`, `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`.

---

## 3. Flujo de Trabajo para Contribuir

1. **Haz un Fork** del repositorio en GitHub: `https://github.com/saghet/SamuLibre`.
2. **Clona tu repositorio localmente**:
   ```bash
   git clone https://github.com/TU-USUARIO/SamuLibre.git
   cd SamuLibre
   ```
3. **Crea una rama descriptiva** para tu mejora o corrección:
   ```bash
   git checkout -b feat/nuevo-analizador-heurisitco
   # o
   git checkout -b fix/fuga-memoria-watcher
   ```
4. **Implementa tus cambios**, asegurándote de:
   - Mantener cobertura de pruebas unitarias.
   - Preservar la política estricta de **no subir malware real**.
   - No añadir dependencias innecesarias o pesadas que comprometan el rendimiento.
5. **Ejecuta las pruebas y comprobaciones de calidad**:
   ```bash
   # Comprobar formato
   cargo fmt --check

   # Análisis estático y linter
   cargo clippy --workspace --all-targets -- -D warnings

   # Batería completa de pruebas unitarias e integración
   cargo test --workspace
   ```
6. **Haz commit de tus cambios** siguiendo la convención de [Conventional Commits](https://www.conventionalcommits.org/):
   ```bash
   git commit -m "feat(scanner): incorporar regla de entropía adaptativa para ejecutables compactados"
   ```
7. **Envía tus cambios a tu Fork**:
   ```bash
   git push origin feat/nuevo-analizador-heurisitco
   ```
8. **Abre un Pull Request (PR)** hacia la rama `main` del repositorio oficial.

---

## 4. Estándares Técnicos Obligatorios

- **Anti-Hallucination Policy:** Toda telemetría, métrica o estado que se muestre en la interfaz gráfica o CLI debe reflejar fielmente la realidad técnica del sistema operativo. Está prohibido hardcodear estados como "Protegido" si el subsistema subyacente está inactivo.
- **Zero-Telemetry Default:** SamuLibre no recopila ni transmite telemetría privada a servidores de terceros sin consentimiento explícito y anónimo del usuario.
- **Seguridad en Ring 0 / SCM:** Cualquier interacción con el *Service Control Manager* de Windows o drivers debe gestionar excepciones y códigos de retorno de forma robusta, sin provocar bloqueos del sistema anfitrión (*BSoD* o fugas de descriptores).
- **Pruebas de Regresión:** Cualquier bug reportado debe acompañarse de una prueba unitaria o de integración que falle antes del parche y pase después de él.
