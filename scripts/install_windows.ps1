# Installer Script for SamuLibre Endpoint Protection Suite
# Requires Administrator privileges (will auto-elevate if needed)

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
Write-Host "─── Instalador de SamuLibre Endpoint Protection ───" -ForegroundColor Cyan
Write-Host "Destino de Instalación: $InstallDir"

# 1. Crear carpeta de destino
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 2. Copiar archivos desde el origen
$SourceDir = $PSScriptRoot
Write-Host "Copiando componentes de protección..."
Copy-Item "$SourceDir\*" -Destination $InstallDir -Recurse -Force -Exclude "install.ps1"

# 3. Registrar Servicio de Windows SCM 24/7
Write-Host "Registrando Servicio Windows SamuLibreWatcher 24/7..."
$CliExe = "$InstallDir\samulibre.exe"
if (Test-Path $CliExe) {
    & $CliExe service install
    & $CliExe service start
}

# 4. Crear accesos directos en Escritorio y Menú Inicio
$WshShell = New-Object -ComObject WScript.Shell
$DesktopPath = [Environment]::GetFolderPath("CommonDesktopDirectory")
$Shortcut = $WshShell.CreateShortcut("$DesktopPath\SamuLibre.lnk")
$Shortcut.TargetPath = "$InstallDir\SamuLibre-GUI.exe"
$Shortcut.WorkingDirectory = $InstallDir
$Shortcut.IconLocation = "$InstallDir\assets\icon.ico,0"
$Shortcut.Description = "SamuLibre Endpoint Protection Suite"
$Shortcut.Save()

Write-Host "✔ Instalación completada exitosamente." -ForegroundColor Green
Write-Host "El servicio Windows 24/7 está activo y el acceso directo se ha creado en el Escritorio."
