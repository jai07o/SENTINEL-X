@echo off
REM ==============================================================================
REM SENTINEL-X Android APK Build & Packaging Script
REM Generates: dist\android\sentinel-x-security.apk
REM ==============================================================================

cd /d "%~dp0\.."

if exist ".venv\Scripts\python.exe" (
    .venv\Scripts\python.exe scripts\build_android_apk.py
) else (
    python scripts\build_android_apk.py
)

pause
