@echo off
REM ==============================================================================
REM SENTINEL-X Terminal Security Workbench & Tools Launcher (Windows)
REM Run without arguments to launch the interactive terminal menu.
REM Pass any sub-command (e.g. `tools scan-folder`, `tools safeguard`, `tools total-safeguard`)
REM ==============================================================================
setlocal
cd /d "%~dp0"
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0cli.py" %*
) else (
    python "%~dp0cli.py" %*
)
endlocal
