#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SamuLibre - Preparación común del directorio data/ para paquetes Linux
# Uso: scripts/packaging/stage_data.sh <directorio_destino>
# ==============================================================================

DEST="${1:?Uso: stage_data.sh <directorio_destino>}"
mkdir -p "${DEST}"

# Copiar directorios esenciales con datos completos
for d in ui signatures kbs cve_rules sandbox canaries; do
    mkdir -p "${DEST}/${d}"
    if [ -d "data/${d}" ]; then
        cp -r "data/${d}/." "${DEST}/${d}/" 2>/dev/null || true
    fi
done

# VPN: copiar configs y listas, omitiendo binarios Windows (.exe, .dll) y logs
mkdir -p "${DEST}/vpn"
if [ -d "data/vpn" ]; then
    find data/vpn -maxdepth 1 -type f ! -name "*.exe" ! -name "*.dll" -exec cp {} "${DEST}/vpn/" \; 2>/dev/null || true
fi

# Directorio de cuarentena vacío
mkdir -p "${DEST}/quarantine"

# Archivos base de configuración y accesos en data/
for f in samulibre.desktop samulibre.service closed_ports.json; do
    if [ -f "data/${f}" ]; then
        cp "data/${f}" "${DEST}/"
    fi
done

echo "✔ data/ preparado exitosamente en ${DEST}"
