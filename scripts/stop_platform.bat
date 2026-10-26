@echo off
REM ==============================================================================
REM SENTINEL-X Unified Local Shutdown Script (Windows)
REM Stops FastAPI backend (port 8000), Vite dev server (port 5173), and watchdogs
REM ==============================================================================

echo ==========================================================
echo   SENTINEL-X SOC Platform -- Windows Graceful Shutdown
echo ==========================================================

cd /d "%~dp0\.."

if exist ".venv\Scripts\python.exe" (
    .venv\Scripts\python.exe launcher.py stop
) else (
    python launcher.py stop
)

echo [+] Shutdown sequence complete.
pause
