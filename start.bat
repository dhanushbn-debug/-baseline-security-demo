@echo off
title Baseline Security Demo
echo ================================================================
echo   Launching Baseline Security Demo (Controlled Comparator)
echo ================================================================
echo.
echo Checking Node.js installation...
node -v >nul 2>&1
if %errorlevel% neq 0 (
  echo Error: Node.js is not installed or not in PATH.
  pause
  exit /b 1
)

echo Starting local server on http://localhost:5000...
echo Health Endpoint: http://localhost:5000/api/health
echo.
node server.js
pause
