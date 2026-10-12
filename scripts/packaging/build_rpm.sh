#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SamuLibre - Generador de Paquete .rpm para Red Hat Enterprise Linux / Fedora
# Compatible con RHEL 9, Rocky Linux, AlmaLinux y Fedora 39/40+
# ==============================================================================

VERSION="0.2.0"
BUILD_DIR="target/rpmbuild"

echo "==> [Red Hat/Fedora] Compilando binarios de SamuLibre en release..."
cargo build --release -p samulibre-gui -p samulibre-cli

echo "==> [Red Hat/Fedora] Preparando estructura rpmbuild..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/BUILD"
mkdir -p "${BUILD_DIR}/RPMS"
mkdir -p "${BUILD_DIR}/SOURCES"
mkdir -p "${BUILD_DIR}/SPECS"
mkdir -p "${BUILD_DIR}/SRPMS"

# Copiar artefactos al directorio BUILD para empaquetado binario
cp target/release/samulibre-gui "${BUILD_DIR}/BUILD/"
cp target/release/samulibre-cli "${BUILD_DIR}/BUILD/"
cp data/samulibre.desktop "${BUILD_DIR}/BUILD/"
cp assets/icon.png "${BUILD_DIR}/BUILD/"
cp data/samulibre.service "${BUILD_DIR}/BUILD/"
cp -r data/ui "${BUILD_DIR}/BUILD/"
if [ -d "data/signatures" ]; then
    cp -r data/signatures "${BUILD_DIR}/BUILD/"
fi

cp scripts/packaging/samulibre.spec "${BUILD_DIR}/SPECS/"

echo "==> [Red Hat/Fedora] Ejecutando rpmbuild..."
rpmbuild --define "_topdir $(pwd)/${BUILD_DIR}" -bb "${BUILD_DIR}/SPECS/samulibre.spec"

cp ${BUILD_DIR}/RPMS/*/*.rpm target/ || true
echo "✔ Paquete .rpm generado con éxito en target/."
