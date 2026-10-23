#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SamuLibre - Generador de Paquete Pacman para Garuda Linux / Arch Linux
# Nota: makepkg no puede ejecutarse como root (en CI se usa un usuario 'builder').
# ==============================================================================

VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
WORK_DIR="target/archpkg"

echo "==> [Garuda/Arch] Compilando binarios de SamuLibre ${VERSION} en release..."
cargo build --release -p samulibre-gui -p samulibre-cli

echo "==> [Garuda/Arch] Preparando directorio de empaquetado..."
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}/src"

cp target/release/samulibre-gui "${WORK_DIR}/src/"
cp target/release/samulibre-cli "${WORK_DIR}/src/"
cp data/samulibre.desktop "${WORK_DIR}/src/"
cp assets/icon.png "${WORK_DIR}/src/"
cp data/samulibre.service "${WORK_DIR}/src/"

# Recursos completos (UI, firmas, catálogo KB, reglas CVE, sandbox, canarios)
bash scripts/packaging/stage_data.sh "${WORK_DIR}/src/data"

sed "s/^pkgver=.*/pkgver=${VERSION}/" scripts/packaging/PKGBUILD > "${WORK_DIR}/PKGBUILD"

echo "==> [Garuda/Arch] Empaquetando con makepkg..."
cd "${WORK_DIR}"
makepkg -f --nodeps --noextract

cp ./*.pkg.tar.zst ../
echo "✔ Paquete Pacman generado con éxito en target/."
