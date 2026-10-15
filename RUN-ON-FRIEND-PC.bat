@echo off
title AITHENA Agent
cd /d "%~dp0"
if not exist aithena-agent.js (
  echo Put this file in the SAME folder as aithena-agent.js and your agent-config file.
  pause
  exit /b
)
set CFG=
for %%f in (agent-config*.json) do set CFG=%%f
if "%CFG%"=="" (
  echo No agent-config file found in this folder.
  pause
  exit /b
)
node -e "const fs=require('fs');const p=process.argv[1];const c=JSON.parse(fs.readFileSync(p));c.consent=true;fs.writeFileSync(p,JSON.stringify(c,null,2));console.log('Consent set. Using '+p)" "%CFG%"
echo.
echo ================================================
echo   AITHENA AGENT - keep this window OPEN
echo ================================================
echo.
node aithena-agent.js --config "%CFG%"
echo.
pause >nul
