@echo off
setlocal
cd /d "%~dp0.."
call "%CD%\simulate_unauthorized_attack.bat" %*
