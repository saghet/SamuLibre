# Installer Script for SamuLibre Endpoint Protection Suite
# Requires Administrator privileges (will auto-elevate if needed)
param(
    [switch]$Silent
)

$ErrorActionPreference = "Stop"

function Test-Administrator {
    $user = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $user.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    if ($Silent) {
        Write-Error "La instalación desatendida requiere privilegios de Administrador."
        exit 1
    }
    Write-Host "Elevando privilegios con UAC..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$InstallDir = "$env:ProgramFiles\SamuLibre"
$BackupDir = "$env:ProgramData\SamuLibre\rollback_backup"
Write-Host "─── Instalador de SamuLibre Endpoint Protection & Network Defense ───" -ForegroundColor Cyan
Write-Host "Destino de Instalación: $InstallDir"

# 0. Respaldo para rollback si existe instalación previa (sin perder conectividad)
if (Test-Path "$InstallDir\data\netdefense") {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    Copy-Item "$InstallDir\data\netdefense\*" -Destination $BackupDir -Recurse -Force -ErrorAction SilentlyContinue
}

# 1. Crear carpeta de destino
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 2. Detener servicio previo de forma controlada antes de actualizar binarios
$CliExe = "$InstallDir\samulibre.exe"
if (Test-Path $CliExe) {
    & $CliExe service stop 2>$null
}

# 3. Copiar archivos desde el origen
$SourceDir = $PSScriptRoot
Write-Host "Copiando componentes de protección..."
Copy-Item "$SourceDir\*" -Destination $InstallDir -Recurse -Force -Exclude "install.ps1"

# 4. Verificar firma Authenticode si existe
Get-ChildItem "$InstallDir\*.exe" | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName
    Write-Host "  Firma $($_.Name): $($sig.Status)"
}

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
