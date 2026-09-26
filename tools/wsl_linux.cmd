@echo off
set TURING_WSL_MODE=link
if "%~1"=="run" set TURING_WSL_MODE=run
python "%~dp0wsl_linux.py" %*
