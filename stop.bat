@echo off
REM ==============================================================================
REM SENTINEL-X Root Quick Stopper (Windows)
REM Double-click to terminate Backend, Dashboard, and Watchdog services all at once
REM ==============================================================================
call "%~dp0scripts\stop_platform.bat"
