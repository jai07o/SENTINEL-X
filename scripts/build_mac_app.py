#!/usr/bin/env python3
"""
SENTINEL-X macOS Application (.app) Packaging System
Builds the macOS Application Bundle and compressed release archive:
  - Output Bundle: dist/mac/SENTINEL-X.app
  - Output Archive: dist/mac/SENTINEL-X-macOS.zip
  - Architecture: Universal (Apple Silicon M1/M2/M3 + Intel x86_64)
"""
import os
import sys
import shutil
import zipfile
import hashlib
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DIST_MAC_DIR = ROOT_DIR / "dist" / "mac"
APP_BUNDLE = DIST_MAC_DIR / "SENTINEL-X.app"
CONTENTS_DIR = APP_BUNDLE / "Contents"
MACOS_DIR = CONTENTS_DIR / "MacOS"
RESOURCES_DIR = CONTENTS_DIR / "Resources"


def build_mac_app():
    print("\n" + "=" * 65)
    print("  BUILDING SENTINEL-X NATIVE MACOS APPLICATION (.APP)")
    print("=" * 65)

    if APP_BUNDLE.exists():
        shutil.rmtree(APP_BUNDLE)

    MACOS_DIR.mkdir(parents=True, exist_ok=True)
    RESOURCES_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Info.plist
    src_plist = ROOT_DIR / "desktop" / "mac" / "Info.plist"
    if src_plist.exists():
        shutil.copy2(src_plist, CONTENTS_DIR / "Info.plist")
    else:
        # Fallback default plist
        plist_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>SENTINEL-X</string>
    <key>CFBundleDisplayName</key><string>SENTINEL-X Cyber Defense</string>
    <key>CFBundleIdentifier</key><string>org.sentinelx.security</string>
    <key>CFBundleVersion</key><string>2.4.0</string>
    <key>CFBundleExecutable</key><string>SENTINEL-X</string>
    <key>CFBundlePackageType</key><string>APPL</string>
</dict>
</plist>"""
        (CONTENTS_DIR / "Info.plist").write_text(plist_content, encoding="utf-8")

    # 2. Executable launcher script
    launcher_sh = MACOS_DIR / "SENTINEL-X"
    launcher_content = """#!/bin/bash
# SENTINEL-X macOS App Entry Point
DIR="$(cd "$(dirname "$0")/../Resources" && pwd)"
PYTHON_EXEC="python3"
if [ -f "$DIR/../../../../.venv/bin/python" ]; then
    PYTHON_EXEC="$DIR/../../../../.venv/bin/python"
fi

exec "$PYTHON_EXEC" "$DIR/mac_app.py" "$@"
"""
    launcher_sh.write_text(launcher_content, encoding="utf-8")
    try:
        os.chmod(launcher_sh, 0o755)
    except Exception:
        pass

    # 3. Resources
    src_mac_py = ROOT_DIR / "desktop" / "mac" / "mac_app.py"
    if src_mac_py.exists():
        shutil.copy2(src_mac_py, RESOURCES_DIR / "mac_app.py")

    src_icon = ROOT_DIR / "desktop" / "app_icon.png"
    if src_icon.exists():
        shutil.copy2(src_icon, RESOURCES_DIR / "app_icon.png")

    # 4. Copy web bundle
    dist_web = ROOT_DIR / "frontend" / "dist"
    web_target = RESOURCES_DIR / "web"
    if dist_web.exists():
        if web_target.exists():
            shutil.rmtree(web_target)
        shutil.copytree(dist_web, web_target)
    print(f"[+] macOS App bundle assembled at: {APP_BUNDLE}")

    # 5. Package as ZIP for distribution
    out_zip = DIST_MAC_DIR / "SENTINEL-X-macOS.zip"
    print(f"[*] Compressing macOS bundle into distribution archive: {out_zip}...")
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in APP_BUNDLE.rglob("*"):
            arc_name = f.relative_to(DIST_MAC_DIR).as_posix()
            zf.write(f, arc_name)

    sha256 = hashlib.sha256(out_zip.read_bytes()).hexdigest()
    size_mb = round(out_zip.stat().st_size / (1024 * 1024), 2)

    print("\n" + "=" * 65)
    print("  [+] MACOS APPLICATION BUILD SUCCESSFUL!")
    print("=" * 65)
    print(f"  App Bundle:      {APP_BUNDLE}")
    print(f"  Release Archive: {out_zip}")
    print(f"  Bundle ID:       org.sentinelx.security")
    print(f"  Version:         2.4.0")
    print(f"  Archive Size:    {size_mb} MB ({out_zip.stat().st_size} bytes)")
    print(f"  SHA-256 Digest:  {sha256}")
    print("\n  Deployment Instructions:")
    print("    1. Move SENTINEL-X.app to /Applications")
    print("    2. On first run: Right-click -> Open (or 'xattr -cr /Applications/SENTINEL-X.app')")
    print("=" * 65 + "\n")
    return out_zip


if __name__ == "__main__":
    build_mac_app()
