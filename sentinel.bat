@echo off
REM ==============================================================================
REM SENTINEL-X Direct Terminal Command Runner (Windows)
REM Double-click or run from terminal to launch the interactive terminal workbench.
REM Pass any sub-command (e.g. `sentinel safeguard`, `sentinel system-scan`, `sentinel scan-folder`)
REM ==============================================================================
setlocal
cd /d "%~dp0"
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0cli.py" %*
) else (
    python "%~dp0cli.py" %*
)
endlocal
