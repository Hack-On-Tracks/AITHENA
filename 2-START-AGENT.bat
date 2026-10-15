@echo off
title AITHENA Agent (this PC)
cd /d "%~dp0\.."
if not exist agent-config.self.json (
  echo Enrolling this PC as "My-PC"...
  node agent\enroll.js --server http://localhost:8443 --token test123 --label "My-PC" --out .\agent-config.self.json
)
node -e "const fs=require('fs');const p='agent-config.self.json';const c=JSON.parse(fs.readFileSync(p));c.consent=true;fs.writeFileSync(p,JSON.stringify(c,null,2));console.log('consent set, using '+p)"
echo.
echo ================================================
echo   AITHENA AGENT (this PC) - keep this window OPEN
echo ================================================
echo.
node agent\aithena-agent.js --config agent-config.self.json
echo.
pause >nul
