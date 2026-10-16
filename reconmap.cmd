@echo off
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Run python tools\bootstrap.py first.
  exit /b 3
)
"%~dp0.venv\Scripts\python.exe" -m reconmap %*
exit /b %errorlevel%
