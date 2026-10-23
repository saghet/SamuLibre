#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SamuLibre - Preparación común del directorio data/ para paquetes Linux
# Uso: scripts/packaging/stage_data.sh <directorio_destino>
# Copia todos los recursos con paridad funcional Windows (UI, firmas, catálogo KB,
# reglas CVE, sandbox, canarios, VPN) excluyendo binarios Windows y artefactos de
# ejecución local.
# ==============================================================================

DEST="${1:?Uso: stage_data.sh <directorio_destino>}"
mkdir -p "${DEST}"

tar -C data \
    --exclude='./bin' \
    --exclude='./test_samples' \
    --exclude='./vpn/tor_data' \
    --exclude='*.exe' \
    --exclude='*.dll' \
    --exclude='*.log' \
    --exclude='./threat_history.json*' \
    --exclude='./kbs/daily_check_log.json' \
    --exclude='./quarantine/*.quarantine' \
    --exclude='./quarantine/*.meta.json' \
    -cf - . | tar -C "${DEST}" -xf -

# Directorios de ejecución que deben existir aunque estén vacíos
for d in ui signatures kbs cve_rules sandbox canaries quarantine vpn; do
    mkdir -p "${DEST}/${d}"
done

echo "✔ data/ preparado en ${DEST}"
