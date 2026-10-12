#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SamuLibre - Generador de Paquete Pacman para Garuda Linux / Arch Linux
# ==============================================================================

VERSION="0.2.0"
WORK_DIR="target/archpkg"

echo "==> [Garuda/Arch] Compilando binarios de SamuLibre en release..."
cargo build --release -p samulibre-gui -p samulibre-cli

echo "==> [Garuda/Arch] Preparando directorio de empaquetado..."
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}/src"

cp target/release/samulibre-gui "${WORK_DIR}/src/"
cp target/release/samulibre-cli "${WORK_DIR}/src/"
cp data/samulibre.desktop "${WORK_DIR}/src/"
cp assets/icon.png "${WORK_DIR}/src/"
cp data/samulibre.service "${WORK_DIR}/src/"
cp -r data/ui "${WORK_DIR}/src/"
if [ -d "data/signatures" ]; then
    cp -r data/signatures "${WORK_DIR}/src/"
fi

cp scripts/packaging/PKGBUILD "${WORK_DIR}/PKGBUILD"

echo "==> [Garuda/Arch] Empaquetando con makepkg..."
cd "${WORK_DIR}"
makepkg -f --nodeps

cp *.pkg.tar.zst ../ || true
echo "✔ Paquete Pacman generado con éxito en target/."
