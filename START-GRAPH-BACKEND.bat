@echo off
title AITHENA Graph Backend
cd /d "%~dp0"
if not exist "backend\graph_api.py" (
  echo Put this .bat in your AITHENA-live folder (the one that now has a "backend" folder).
  echo Current folder: %cd%
  pause & exit /b
)
where python >nul 2>&1
if errorlevel 1 (
  echo.
  echo Python is not installed. Install it from https://www.python.org/downloads/
  echo and TICK "Add python.exe to PATH" during setup. Then run this file again.
  echo.
  pause & exit /b
)
echo Installing the 3 Python packages (first run only)...
python -m pip install --quiet --disable-pip-version-check flask flask-cors networkx
echo.
echo ================================================
echo   AITHENA GRAPH BACKEND  -  keep this window OPEN
echo   running on http://127.0.0.1:5001
echo ================================================
echo.
set PYTHONPATH=%~dp0
python -m backend.graph_api
echo.
pause
