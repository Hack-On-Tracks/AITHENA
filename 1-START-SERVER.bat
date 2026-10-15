@echo off
title AITHENA Server
cd /d "%~dp0\.."
set AITHENA_ADMIN_TOKEN=test123
set PORT=8443
echo ================================================
echo   AITHENA SERVER  -  keep this window OPEN
echo   Admin token: test123
echo ================================================
echo.
node server\aithena-server.js
echo.
echo Server stopped. Press any key to close.
pause >nul
