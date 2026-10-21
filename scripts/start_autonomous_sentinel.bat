@echo off
setlocal
echo =================================================================
echo   STARTING SENTINEL-X AUTONOMOUS BACKGROUND SENTINEL (WINDOWS)   
echo =================================================================

cd /d "%~dp0\.."

if exist .venv\Scripts\python.exe (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

echo Activating Autonomous Background Sentinel on Laptop & Mobile...
start /b "" "%PYTHON_EXE%" scripts\run_background_sentinel.py

echo.
echo [OK] Autonomous Background Sentinel is now running persistently in background!
echo [OK] To stop and exit background monitoring, run: scripts\stop_autonomous_sentinel.bat
echo      or click the 'STOP & EXIT SENTINEL' button directly on the web dashboard.
echo =================================================================
pause
