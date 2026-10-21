@echo off
REM ==============================================================================
REM SENTINEL-X Unified Local Startup Script (Windows)
REM Starts FastAPI backend (port 8000) and Vite frontend dev server (port 5173)
REM ==============================================================================

echo ==========================================================
echo   SENTINEL-X SOC Platform -- Windows Launcher
echo ==========================================================

cd /d "%~dp0\.."

if not exist ".venv\Scripts\python.exe" (
  echo [*] Setting up Python virtual environment...
  python -m venv .venv
  call .venv\Scripts\activate.bat
  pip install -r backend\requirements.txt
)

if not exist "data\uploads" mkdir data\uploads
if not exist "data\evidence" mkdir data\evidence
if not exist "data\reports" mkdir data\reports

echo [+] Starting FastAPI Backend on http://127.0.0.1:8000 in background window...
start "SENTINEL-X Backend" cmd /k "cd /d "%~dp0\.." && .venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload"

echo [+] Starting Vite Dashboard on http://127.0.0.1:5173 in background window...
start "SENTINEL-X Dashboard" cmd /k "cd /d "%~dp0\..\frontend" && npm run dev"

echo.
echo ==========================================================
echo   SENTINEL-X SOC Services Launched:
echo     - Dashboard UI: http://127.0.0.1:5173
echo     - API Docs:     http://127.0.0.1:8000/docs
echo     - Credentials:  admin / SentinelX@2026!
echo ==========================================================
echo.
echo [*] Opening Web Dashboard in default browser in 3 seconds...
timeout /t 3 /nobreak >nul
start http://127.0.0.1:5173
echo [+] Done. Keep the terminal windows open while using the platform.
pause
