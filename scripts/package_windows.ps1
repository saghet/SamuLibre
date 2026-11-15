# Packaging Script for SamuLibre Windows Distribution
param (
    [string]$Version = "2.1.13"
)

$ErrorActionPreference = "Stop"

Write-Host "─── Empaquetando SamuLibre v$Version para Windows x64 ───" -ForegroundColor Cyan

# 1. Compilar en modo Release
Write-Host "[1/4] Compilando binarios optimizados (Release)..." -ForegroundColor Yellow
cargo build --release -p samulibre-gui -p samulibre-cli
if ($LASTEXITCODE -ne 0) {
    Write-Error "Fallo en la compilación de Release."
    exit 1
}

# 2. Preparar directorio de distribución
$distDir = "dist\SamuLibre-v$Version-Windows-x64"
if (Test-Path $distDir) {
    Remove-Item -Recurse -Force $distDir
}
New-Item -ItemType Directory -Path "$distDir\data" -Force | Out-Null
New-Item -ItemType Directory -Path "$distDir\assets" -Force | Out-Null

Write-Host "[2/4] Copiando ejecutables y recursos requeridos..." -ForegroundColor Yellow
Copy-Item "target\release\samulibre-gui.exe" "$distDir\SamuLibre-GUI.exe"
Copy-Item "target\release\samulibre-cli.exe" "$distDir\samulibre.exe"
Copy-Item "LICENSE" "$distDir\LICENSE"
Copy-Item "README.md" "$distDir\README.md"
Copy-Item "VERSION" "$distDir\VERSION"

# Copiar activos y estructura mínima de datos
Copy-Item -Recurse "data\ui" "$distDir\data\ui"
Copy-Item -Recurse "data\signatures" "$distDir\data\signatures"
Copy-Item -Recurse "data\cve_rules" "$distDir\data\cve_rules"
Copy-Item -Recurse "assets\*" "$distDir\assets\"
Copy-Item -Recurse "docs" "$distDir\docs" -ErrorAction SilentlyContinue

# Incluir script de instalación con UAC y desinstalador
Copy-Item "scripts\install_windows.ps1" "$distDir\install.ps1" -ErrorAction SilentlyContinue
Copy-Item "scripts\uninstall_windows.ps1" "$distDir\uninstall.ps1" -ErrorAction SilentlyContinue

# 3. Comprimir paquete ZIP
Write-Host "[3/4] Generando archivo comprimido..." -ForegroundColor Yellow
$zipPath = "dist\SamuLibre-v$Version-Windows-x64.zip"
if (Test-Path $zipPath) {
    Remove-Item -Force $zipPath
}
Compress-Archive -Path "$distDir\*" -DestinationPath $zipPath -CompressionLevel Optimal

# 4. Calcular Hash SHA-256
Write-Host "[4/4] Calculando integridad criptográfica SHA-256..." -ForegroundColor Yellow
$hash = (Get-FileHash -Algorithm SHA256 $zipPath).Hash
$checksumLine = "$hash  SamuLibre-v$Version-Windows-x64.zip"
Set-Content -Path "dist\SHA256SUMS.txt" -Value $checksumLine

Write-Host ""
Write-Host "[OK] Paquete de distribución generado con éxito:" -ForegroundColor Green
Write-Host "  Archivo: $zipPath"
Write-Host "  SHA-256: $hash"

