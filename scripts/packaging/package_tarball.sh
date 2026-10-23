#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SamuLibre - Empaquetador de Tarball Universal Autónomo para Linux
# Genera: target/samulibre-<version>-linux-x86_64.tar.gz
# ==============================================================================

VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
BUNDLE_DIR="target/bundle/samulibre-${VERSION}-linux-x86_64"

echo "==> Compilando binarios de SamuLibre ${VERSION} en modo release..."
cargo build --release -p samulibre-gui -p samulibre-cli

echo "==> Ensamblando bundle portable..."
rm -rf "${BUNDLE_DIR}"
mkdir -p "${BUNDLE_DIR}"

cp target/release/samulibre-gui "${BUNDLE_DIR}/"
cp target/release/samulibre-cli "${BUNDLE_DIR}/"
chmod 755 "${BUNDLE_DIR}/samulibre-gui" "${BUNDLE_DIR}/samulibre-cli"

cp data/samulibre.desktop "${BUNDLE_DIR}/"
cp assets/icon.png "${BUNDLE_DIR}/"
cp data/samulibre.service "${BUNDLE_DIR}/"
cp scripts/packaging/install.sh "${BUNDLE_DIR}/"
chmod 755 "${BUNDLE_DIR}/install.sh"

# Recursos completos (UI, firmas, catálogo KB, reglas CVE, sandbox, canarios)
bash scripts/packaging/stage_data.sh "${BUNDLE_DIR}/data"

echo "==> Creando archivo comprimido .tar.gz..."
cd target/bundle
tar -czf "../samulibre-${VERSION}-linux-x86_64.tar.gz" "samulibre-${VERSION}-linux-x86_64"
cd ../..

echo "✔ Tarball generado con éxito en: target/samulibre-${VERSION}-linux-x86_64.tar.gz"
