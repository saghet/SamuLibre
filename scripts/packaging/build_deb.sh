#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SamuLibre - Generador de Paquete .deb para Ubuntu / Debian
# Soporta Ubuntu 22.04 LTS, 24.04 LTS y Debian 12
# ==============================================================================

VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
ARCH="amd64"
PKG_DIR="target/debian/samulibre_${VERSION}_${ARCH}"

echo "==> [Ubuntu/Debian] Compilando binarios de SamuLibre ${VERSION} en release..."
cargo build --release -p samulibre-gui -p samulibre-cli

echo "==> [Ubuntu/Debian] Preparando árbol de directorios de empaquetado..."
rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${PKG_DIR}/usr/share/icons/hicolor/512x512/apps"
mkdir -p "${PKG_DIR}/usr/lib/systemd/user"

echo "==> [Ubuntu/Debian] Copiando binarios y activos..."
cp target/release/samulibre-gui "${PKG_DIR}/usr/bin/samulibre-gui"
cp target/release/samulibre-cli "${PKG_DIR}/usr/bin/samulibre-cli"
chmod 755 "${PKG_DIR}/usr/bin/samulibre-gui" "${PKG_DIR}/usr/bin/samulibre-cli"

cp data/samulibre.desktop "${PKG_DIR}/usr/share/applications/samulibre.desktop"
cp assets/icon.png "${PKG_DIR}/usr/share/icons/hicolor/512x512/apps/samulibre.png"
cp data/samulibre.service "${PKG_DIR}/usr/lib/systemd/user/samulibre.service"

# Recursos completos (UI, firmas, catálogo KB, reglas CVE, sandbox, canarios)
bash scripts/packaging/stage_data.sh "${PKG_DIR}/usr/share/samulibre/data"

echo "==> [Ubuntu/Debian] Generando DEBIAN/control..."
cat << EOF > "${PKG_DIR}/DEBIAN/control"
Package: samulibre
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: SamuLibre Security Team <security@samulibre.org>
Depends: libc6 (>= 2.31), libwebkit2gtk-4.1-0, libgtk-3-0, tor, iptables, zenity
Recommends: apparmor, libayatana-appindicator3-1
Description: Suite de Seguridad y Antivirus Open Source
 SamuLibre es una solución integral de ciberdefensa ligera y modular:
  - Antivirus multipatrón heurístico y detección por IA.
  - EDR con canarios anti-ransomware, autoprotección y protección de credenciales.
  - Parches Virtuales en memoria y mitigaciones sysctl del kernel.
  - Protección de navegadores y auditoría de extensiones.
  - VPN Tor integrada con doble cifrado y Kill-Switch.
EOF

cat << 'EOF' > "${PKG_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    update-desktop-database -q /usr/share/applications || true
    gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

cat << 'EOF' > "${PKG_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e
pkill -f samulibre-gui || true
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

echo "==> [Ubuntu/Debian] Construyendo paquete .deb..."
dpkg-deb --build --root-owner-group "${PKG_DIR}" "target/samulibre_${VERSION}_${ARCH}.deb"

echo "✔ Paquete .deb generado con éxito en: target/samulibre_${VERSION}_${ARCH}.deb"
