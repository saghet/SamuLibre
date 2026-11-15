# Uninstaller Script for SamuLibre Endpoint Protection Suite
# Requires Administrator privileges

$ErrorActionPreference = "Stop"

function Test-Administrator {
    $user = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $user.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "Elevando privilegios con UAC..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$InstallDir = "$env:ProgramFiles\SamuLibre"
Write-Host "─── Desinstalador de SamuLibre Endpoint Protection ───" -ForegroundColor Yellow

# 1. Limpiar filtros WFP propios de SamuLibre y detener el servicio Windows SCM
Write-Host "Limpiando filtros WFP propios de SamuLibre y deteniendo SamuLibreWatcher..."
$CliExe = "$InstallDir\samulibre.exe"
if (Test-Path $CliExe) {
    & $CliExe netdefense cleanup 2>$null
    & $CliExe service stop
    & $CliExe service uninstall
} else {
    sc.exe stop SamuLibreWatcher
    sc.exe delete SamuLibreWatcher
}

# 2. Terminar procesos gráficos si están abiertos
Stop-Process -Name "samulibre-gui", "SamuLibre-GUI" -Force -ErrorAction SilentlyContinue

# 3. Eliminar accesos directos
$DesktopPath = [Environment]::GetFolderPath("CommonDesktopDirectory")
$ShortcutPath = "$DesktopPath\SamuLibre.lnk"
if (Test-Path $ShortcutPath) {
    Remove-Item -Force $ShortcutPath
}

# 4. Eliminar directorio de instalación
if (Test-Path $InstallDir) {
    Write-Host "Eliminando archivos del programa..."
    Remove-Item -Recurse -Force $InstallDir
}

Write-Host "✔ SamuLibre ha sido desinstalado completamente del sistema." -ForegroundColor Green
