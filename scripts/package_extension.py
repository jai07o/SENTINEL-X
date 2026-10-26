#!/usr/bin/env python3
"""
SENTINEL-X Browser Extension Packaging System
Packages the Manifest V3 Browser Security Extension:
  - Output Archive: dist/extension/sentinel-x-companion.zip
  - Compatible Browsers: Google Chrome, Microsoft Edge, Brave, Chromium
"""
import os
import sys
import zipfile
import hashlib
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
EXT_DIR = ROOT_DIR / "extension"
DIST_EXT_DIR = ROOT_DIR / "dist" / "extension"


def package_extension():
    print("\n" + "=" * 65)
    print("  PACKAGING SENTINEL-X BROWSER EXTENSION (MANIFEST V3)")
    print("=" * 65)

    if not (EXT_DIR / "manifest.json").exists():
        print(f"[!] Error: manifest.json not found in {EXT_DIR}")
        return None

    DIST_EXT_DIR.mkdir(parents=True, exist_ok=True)
    out_zip = DIST_EXT_DIR / "sentinel-x-companion.zip"

    files_packed = []
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in EXT_DIR.rglob("*"):
            if f.is_file():
                arc_name = f.relative_to(EXT_DIR).as_posix()
                zf.write(f, arc_name)
                files_packed.append(arc_name)

    sha256 = hashlib.sha256(out_zip.read_bytes()).hexdigest()
    size_kb = round(out_zip.stat().st_size / 1024, 2)

    print("\n" + "=" * 65)
    print("  [+] BROWSER EXTENSION PACKAGE CREATED!")
    print("=" * 65)
    print(f"  Package File:    {out_zip}")
    print(f"  Files Included:  {len(files_packed)} assets")
    print(f"  Archive Size:    {size_kb} KB ({out_zip.stat().st_size} bytes)")
    print(f"  SHA-256 Digest:  {sha256}")
    print("\n  Installation Instructions (Chrome / Edge / Brave):")
    print("    1. Open chrome://extensions (or edge://extensions)")
    print("    2. Turn ON 'Developer Mode' (toggle in top-right corner)")
    print(f"    3. Click 'Load unpacked' and select the directory:\n       {EXT_DIR.resolve()}")
    print("    4. Or unzip 'sentinel-x-companion.zip' and load that directory.")
    print("=" * 65 + "\n")
    return out_zip


if __name__ == "__main__":
    package_extension()
