@echo off
setlocal
cd /d "%~dp0.."
call "%CD%\start_real_data_collection.bat" %*
