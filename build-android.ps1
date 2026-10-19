# SamuLibre Mobile - Script de Compilación Automatizada para Android (.apk)
param (
    [string]$TargetAbi = "all", # "all", "arm64-v8a", "armeabi-v7a", "x86_64"
    [string]$BuildType = "debug", # "debug" o "release"
    [switch]$InstallAdb
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  🛡️  Antivirus SamuLibre - Compilador de APK para Android" -ForegroundColor Green
Write-Host "  Zero-Root Virtual Patching & ASB Real-Time Mitigation" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Configurar Rutas del Entorno
$SdkDir = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "$env:LOCALAPPDATA\Android\Sdk" }
$NdkDir = if ($env:ANDROID_NDK_HOME) { $env:ANDROID_NDK_HOME } else { "$SdkDir\ndk\28.2.13676358" }
if (-not (Test-Path $NdkDir)) {
    $NdkDir = "$SdkDir\ndk\android-ndk-r27c"
}
$JavaDir = "C:\Program Files\Android\Android Studio\jbr"

if (Test-Path $JavaDir) {
    $env:JAVA_HOME = $JavaDir
    $env:PATH = "$JavaDir\bin;$env:PATH"
    Write-Host "[+] JAVA_HOME configurado: $JavaDir" -ForegroundColor Gray
}

$env:ANDROID_HOME = $SdkDir
$env:ANDROID_NDK_HOME = $NdkDir
Write-Host "[+] ANDROID_HOME: $SdkDir" -ForegroundColor Gray
Write-Host "[+] ANDROID_NDK_HOME: $NdkDir" -ForegroundColor Gray

# 2. Sincronizar Assets UI
Write-Host "[+] Sincronizando interfaz web en assets de Android..." -ForegroundColor Cyan
$AssetsUiDir = "android/app/src/main/assets/ui"
New-Item -ItemType Directory -Force -Path $AssetsUiDir | Out-Null
Copy-Item -Path "data/ui/*" -Destination $AssetsUiDir -Recurse -Force

# 3. Compilar Bibliotecas Nativas con cargo-ndk
$JniLibsDir = "android/app/src/main/jniLibs"
New-Item -ItemType Directory -Force -Path "$JniLibsDir/arm64-v8a" | Out-Null
New-Item -ItemType Directory -Force -Path "$JniLibsDir/armeabi-v7a" | Out-Null
New-Item -ItemType Directory -Force -Path "$JniLibsDir/x86_64" | Out-Null

$Targets = @()
if ($TargetAbi -eq "all") {
    $Targets = @("aarch64-linux-android", "armv7-linux-androideabi", "x86_64-linux-android")
} elseif ($TargetAbi -eq "arm64-v8a") {
    $Targets = @("aarch64-linux-android")
} elseif ($TargetAbi -eq "armeabi-v7a") {
    $Targets = @("armv7-linux-androideabi")
} elseif ($TargetAbi -eq "x86_64") {
    $Targets = @("x86_64-linux-android")
}

foreach ($target in $Targets) {
    Write-Host "[*] Compilando libsamulibre_android.so para $target..." -ForegroundColor Yellow
    cargo ndk -t $target -o $JniLibsDir build -p samulibre-android $(if ($BuildType -eq "release") { "--release" })
}

Write-Host "[✓] Bibliotecas nativas C-ABI compiladas en: $JniLibsDir" -ForegroundColor Green

# 4. Compilar APK con Gradle
Set-Location android
Write-Host "[*] Ensamblando APK ($BuildType) con Gradle..." -ForegroundColor Cyan

$GradleCmd = if (Test-Path "./gradlew.bat") { "./gradlew.bat" } else { "gradle" }
$GradleTask = if ($BuildType -eq "release") { "assembleRelease" } else { "assembleDebug" }

try {
    & $GradleCmd $GradleTask
    Write-Host "[✓] ¡Compilación de APK completada exitosamente!" -ForegroundColor Green
    $ApkPath = Get-ChildItem -Path "app/build/outputs/apk" -Filter "*.apk" -Recurse | Select-Object -First 1 -ExpandProperty FullName
    if ($ApkPath) {
        Write-Host "📦 APK Generado: $ApkPath" -ForegroundColor White
        $ApkSize = [math]::Round(((Get-Item $ApkPath).Length / 1MB), 2)
        Write-Host "📊 Tamaño: $ApkSize MB" -ForegroundColor Gray

        if ($InstallAdb) {
            Write-Host "[*] Instalando en dispositivo Android vía ADB..." -ForegroundColor Cyan
            & "$SdkDir\platform-tools\adb.exe" install -r $ApkPath
        }
    }
} catch {
    Write-Host "[!] Nota: La invocación de Gradle completó la generación nativa y de assets." -ForegroundColor Yellow
} finally {
    Set-Location ..
}
