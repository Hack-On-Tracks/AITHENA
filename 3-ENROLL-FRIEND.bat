@echo off
title AITHENA Enroll Friend
cd /d "%~dp0\.."
echo Your computer's network (LAN) IP address(es):
echo ------------------------------------------------
powershell -NoProfile -Command "Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -like '192.168.*' -or $_.IPAddress -like '10.*' -or $_.IPAddress -like '172.*'} | Select-Object InterfaceAlias,IPAddress | Format-Table -AutoSize"
echo ------------------------------------------------
echo Pick the one for your Wi-Fi/Ethernet (NOT a VirtualBox/Hyper-V one).
echo.
set /p IP=Type that LAN IP: 
set /p NAME=Type a label for the friend's laptop (e.g. Rahul-Laptop): 
node agent\enroll.js --server http://%IP%:8443 --token test123 --label "%NAME%" --out .\agent-config.%NAME%.json
echo.
echo If it said "Enrolled", send these files to the friend's laptop (same folder):
echo    1) agent-config.%NAME%.json   (in THIS folder)
echo    2) agent\aithena-agent.js
echo    3) _clickstart\RUN-ON-FRIEND-PC.bat
echo.
pause
