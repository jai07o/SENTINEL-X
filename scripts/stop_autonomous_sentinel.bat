@echo off
setlocal
echo =================================================================
echo   STOPPING SENTINEL-X AUTONOMOUS BACKGROUND SENTINEL            
echo =================================================================

cd /d "%~dp0\.."

if exist .venv\Scripts\python.exe (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

"%PYTHON_EXE%" -c "import httpx; res = httpx.post('http://127.0.0.1:8000/api/v1/omniscan/autonomous-sentinel/stop', headers={'Authorization': 'Bearer sx_dev_agent_key_default'}, timeout=4.0); print(res.json().get('message', 'Stopped'))" 2>nul

echo [OK] Autonomous Background Sentinel stopped and exited.
echo =================================================================
pause
