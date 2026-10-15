@echo off
title AITHENA Firewall
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo This must run as Administrator.
  echo Right-click this file  -^>  "Run as administrator".
  echo.
  pause
  exit /b
)
netsh advfirewall firewall add rule name="AITHENA 8443" dir=in action=allow protocol=TCP localport=8443
echo.
echo Done - port 8443 allowed inbound. Friends can now reach your server.
pause
