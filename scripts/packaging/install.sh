#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SamuLibre - Instalador Universal para Distribuciones Linux
# Compatible con: Ubuntu, Debian, Red Hat (RHEL/Fedora/Rocky), Garuda (Arch)
# ==============================================================================

echo "=========================================================="
echo "          SamuLibre - Instalador Universal Linux          "
echo "=========================================================="

DISTRO_ID="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
fi

echo "✔ Distribución detectada: ${PRETTY_NAME:-$DISTRO_ID}"

# Detección de privilegios
IS_ROOT=false
if [ "$(id -u)" -eq 0 ]; then
    IS_ROOT=true
    INSTALL_PREFIX="/usr/local"
    APP_DATA_DIR="/usr/share/samulibre"
    DESKTOP_DIR="/usr/share/applications"
    ICON_DIR="/usr/share/icons/hicolor/512x512/apps"
else
    INSTALL_PREFIX="${HOME}/.local"
    APP_DATA_DIR="${HOME}/.local/share/samulibre"
    DESKTOP_DIR="${HOME}/.local/share/applications"
    ICON_DIR="${HOME}/.local/share/icons/hicolor/512x512/apps"
    echo "ℹ Ejecutando como usuario no-root. Instalando en ${HOME}/.local"
fi

# Asistencia de dependencias según distribución
echo "==> Verificando dependencias del sistema..."
case "${DISTRO_ID}" in
    ubuntu|debian|pop|linuxmint)
        echo "ℹ Para Ubuntu/Debian, asegurando dependencias recomendadas:"
        echo "  sudo apt install -y libwebkit2gtk-4.1-0 libgtk-3-0 tor iptables zenity"
        ;;
    rhel|fedora|rocky|almalinux|centos)
        echo "ℹ Para Red Hat/Fedora, asegurando dependencias recomendadas:"
        echo "  sudo dnf install -y webkit2gtk4.1 gtk3 tor iptables zenity"
        ;;
    garuda|arch|manjaro|endeavouros)
        echo "ℹ Para Garuda Linux/Arch, asegurando dependencias recomendadas:"
        echo "  sudo pacman -S --needed webkit2gtk-4.1 gtk3 tor iptables kdialog zenity"
        ;;
    *)
        echo "ℹ Distribución genérica Linux. Requiere WebKit2GTK 4.1, Tor e IPTables."
        ;;
esac

# Creación de directorios
mkdir -p "${INSTALL_PREFIX}/bin"
mkdir -p "${APP_DATA_DIR}/data/ui"
mkdir -p "${APP_DATA_DIR}/data/signatures"
mkdir -p "${DESKTOP_DIR}"
mkdir -p "${ICON_DIR}"

# Ubicación del paquete
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Instalando binarios ejecutables..."
if [ -f "${SCRIPT_DIR}/samulibre-gui" ]; then
    cp "${SCRIPT_DIR}/samulibre-gui" "${INSTALL_PREFIX}/bin/samulibre-gui"
    chmod 755 "${INSTALL_PREFIX}/bin/samulibre-gui"
elif [ -f "${SCRIPT_DIR}/../../target/release/samulibre-gui" ]; then
    cp "${SCRIPT_DIR}/../../target/release/samulibre-gui" "${INSTALL_PREFIX}/bin/samulibre-gui"
    chmod 755 "${INSTALL_PREFIX}/bin/samulibre-gui"
else
    echo "❌ Error: No se encontró el binario 'samulibre-gui'."
    exit 1
fi

if [ -f "${SCRIPT_DIR}/samulibre-cli" ]; then
    cp "${SCRIPT_DIR}/samulibre-cli" "${INSTALL_PREFIX}/bin/samulibre-cli"
    chmod 755 "${INSTALL_PREFIX}/bin/samulibre-cli"
elif [ -f "${SCRIPT_DIR}/../../target/release/samulibre-cli" ]; then
    cp "${SCRIPT_DIR}/../../target/release/samulibre-cli" "${INSTALL_PREFIX}/bin/samulibre-cli"
    chmod 755 "${INSTALL_PREFIX}/bin/samulibre-cli"
fi

echo "==> Instalando recursos web, firmas y configuración..."
if [ -d "${SCRIPT_DIR}/ui" ]; then
    cp -r "${SCRIPT_DIR}/ui/"* "${APP_DATA_DIR}/data/ui/"
elif [ -d "${SCRIPT_DIR}/../../data/ui" ]; then
    cp -r "${SCRIPT_DIR}/../../data/ui/"* "${APP_DATA_DIR}/data/ui/"
fi

if [ -d "${SCRIPT_DIR}/signatures" ]; then
    cp -r "${SCRIPT_DIR}/signatures/"* "${APP_DATA_DIR}/data/signatures/"
elif [ -d "${SCRIPT_DIR}/../../data/signatures" ]; then
    cp -r "${SCRIPT_DIR}/../../data/signatures/"* "${APP_DATA_DIR}/data/signatures/"
fi

echo "==> Instalando acceso directo de escritorio e iconos..."
if [ -f "${SCRIPT_DIR}/samulibre.desktop" ]; then
    cp "${SCRIPT_DIR}/samulibre.desktop" "${DESKTOP_DIR}/samulibre.desktop"
elif [ -f "${SCRIPT_DIR}/../../data/samulibre.desktop" ]; then
    cp "${SCRIPT_DIR}/../../data/samulibre.desktop" "${DESKTOP_DIR}/samulibre.desktop"
fi

# Ajustar ruta de ejecución en desktop file si es instalación local de usuario
if [ "${IS_ROOT}" = false ]; then
    sed -i "s|/usr/bin/samulibre-gui|${INSTALL_PREFIX}/bin/samulibre-gui|g" "${DESKTOP_DIR}/samulibre.desktop" || true
fi

if [ -f "${SCRIPT_DIR}/icon.png" ]; then
    cp "${SCRIPT_DIR}/icon.png" "${ICON_DIR}/samulibre.png"
elif [ -f "${SCRIPT_DIR}/../../assets/icon.png" ]; then
    cp "${SCRIPT_DIR}/../../assets/icon.png" "${ICON_DIR}/samulibre.png"
fi

# Actualizar base de datos de escritorio si existe la utilidad
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "${DESKTOP_DIR}" || true
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$(dirname "${ICON_DIR}")/.." || true
fi

echo "=========================================================="
echo " ✔ Instalación de SamuLibre completada exitosamente!     "
echo " Ejecutable: ${INSTALL_PREFIX}/bin/samulibre-gui          "
echo " Inicie la aplicación desde el menú o ejecutando:         "
echo "   ${INSTALL_PREFIX}/bin/samulibre-gui                    "
echo "=========================================================="
