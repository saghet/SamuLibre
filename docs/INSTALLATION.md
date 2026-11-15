# Installation & Updates (`SamuLibre Network Defense`)

## Instalación en Windows
- Ejecutar `scripts/install_windows.ps1` (soporta `-Silent` para instalación desatendida con privilegios de Administrador).
- El instalador respalda la configuración previa en `%ProgramData%\SamuLibre\rollback_backup`, detiene el servicio de forma controlada, copia los binarios actualizados, verifica firmas Authenticode, e instala/arranca el servicio Windows SCM `SamuLibreWatcher`.
- Al operar 100% con WFP en modo usuario, **no requiere instalar drivers `.sys` ni habilitar `TESTSIGNING`**.

## Desinstalación Limpia
- `scripts/uninstall_windows.ps1` ejecuta `samulibre.exe netdefense cleanup` para eliminar todos los filtros WFP propios de SamuLibre antes de detener y eliminar el servicio `SamuLibreWatcher`, evitando filtros huérfanos o pérdida de conectividad.
