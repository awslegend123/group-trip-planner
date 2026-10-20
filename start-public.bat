@echo off
cd /d "%~dp0"
title Trip planner - public link
if not exist node_modules (
  echo Installing for the first time...
  call npm install
)
if not exist cloudflared.exe (
  echo Downloading Cloudflare's tunnel tool, one time only...
  curl -L -o cloudflared.exe https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe
)
start "Trip planner server" cmd /k npm start
timeout /t 3 /nobreak >nul
echo.
echo ================================================================
echo  Your public link appears below in a box, ending in
echo  .trycloudflare.com  -  send that link to your group.
echo.
echo  Keep BOTH windows open. Closing them takes the site offline.
echo  You get a new link each time you start this.
echo ================================================================
echo.
cloudflared.exe tunnel --no-autoupdate --url http://localhost:3000
pause
