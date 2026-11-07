#!/usr/bin/env python3
"""
scripts/bump_build_version.py
Automatiza el incremento del dígito de la derecha (versión de compilación) en SamuLibre.
Armoniza SemVer 2.0.0 de Cargo (2.0.X) con la presentación en UI (v2.00.X).
"""

import sys
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CARGO_TOML = ROOT / "Cargo.toml"
INDEX_HTML = ROOT / "data" / "ui" / "index.html"

def get_current_cargo_version():
    content = CARGO_TOML.read_text(encoding="utf-8")
    m = re.search(r'\[workspace\.package\][^\[]*version\s*=\s*"([^"]+)"', content)
    if m:
        return m.group(1)
    raise RuntimeError("No se encontró version en [workspace.package] en Cargo.toml")

def set_version(new_cargo_ver, new_ui_ver):
    # 1. Update Cargo.toml
    cargo_text = CARGO_TOML.read_text(encoding="utf-8")
    updated_cargo = re.sub(
        r'(\[workspace\.package\][^\[]*version\s*=\s*)"([^"]+)"',
        rf'\g<1>"{new_cargo_ver}"',
        cargo_text,
        count=1
    )
    CARGO_TOML.write_text(updated_cargo, encoding="utf-8")

    # 2. Update data/ui/index.html
    if INDEX_HTML.exists():
        html_text = INDEX_HTML.read_text(encoding="utf-8")
        # Replace v1.99.17 or any v2.00.X
        updated_html = re.sub(r'v(1\.99\.\d+|2\.00\.\d+)', f'{new_ui_ver}', html_text)
        INDEX_HTML.write_text(updated_html, encoding="utf-8")

    print(f"[*] Version actualizada exitosamente:")
    print(f"   Cargo.toml (SemVer): {new_cargo_ver}")
    print(f"   UI / Visual:         {new_ui_ver}")

def bump_patch():
    curr = get_current_cargo_version()
    parts = curr.split(".")
    if len(parts) >= 3:
        major, minor, patch = parts[0], parts[1], int(parts[2]) + 1
        new_cargo = f"{major}.{minor}.{patch}"
        new_ui = f"v{major}.{int(minor):02d}.{patch}"
    else:
        new_cargo = "2.0.1"
        new_ui = "v2.00.1"
    set_version(new_cargo, new_ui)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--set":
        target = sys.argv[2] if len(sys.argv) > 2 else "2.0.1"
        parts = target.split(".")
        new_cargo = target
        new_ui = f"v{parts[0]}.{int(parts[1]):02d}.{parts[2]}"
        set_version(new_cargo, new_ui)
    else:
        bump_patch()

if __name__ == "__main__":
    main()
