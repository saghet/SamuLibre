#!/usr/bin/env bash
# SamuLibre Mobile - Script de Compilación Automatizada para Android (.apk) en Linux/macOS
set -euo pipefail

TARGET_ABI="${1:-all}"
BUILD_TYPE="${2:-debug}"

echo "=========================================================="
echo "  🛡️  Antivirus SamuLibre - Compilador de APK para Android"
echo "  Zero-Root Virtual Patching & ASB Real-Time Mitigation"
echo "=========================================================="

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/28.2.13676358}"

# Sincronizar assets UI
mkdir -p android/app/src/main/assets/ui
cp -r data/ui/* android/app/src/main/assets/ui/

# Compilar bibliotecas nativas
JNI_LIBS_DIR="android/app/src/main/jniLibs"
mkdir -p "$JNI_LIBS_DIR/arm64-v8a" "$JNI_LIBS_DIR/armeabi-v7a" "$JNI_LIBS_DIR/x86_64"

TARGETS=()
if [ "$TARGET_ABI" = "all" ]; then
    TARGETS=("aarch64-linux-android" "armv7-linux-androideabi" "x86_64-linux-android")
elif [ "$TARGET_ABI" = "arm64-v8a" ]; then
    TARGETS=("aarch64-linux-android")
elif [ "$TARGET_ABI" = "armeabi-v7a" ]; then
    TARGETS=("armv7-linux-androideabi")
elif [ "$TARGET_ABI" = "x86_64" ]; then
    TARGETS=("x86_64-linux-android")
fi

RELEASE_FLAG=""
if [ "$BUILD_TYPE" = "release" ]; then
    RELEASE_FLAG="--release"
fi

for TARGET in "${TARGETS[@]}"; do
    echo "[*] Compilando libsamulibre_android.so para $TARGET..."
    cargo ndk -t "$TARGET" -o "$JNI_LIBS_DIR" build -p samulibre-android $RELEASE_FLAG
done

echo "[✓] Bibliotecas nativas compiladas en $JNI_LIBS_DIR"

cd android
GRADLE_TASK="assembleDebug"
if [ "$BUILD_TYPE" = "release" ]; then
    GRADLE_TASK="assembleRelease"
fi

./gradlew "$GRADLE_TASK"
echo "[✓] ¡APK ensamblado exitosamente en android/app/build/outputs/apk/!"
