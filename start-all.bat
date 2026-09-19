@echo off
echo ============================================================
echo   PHISHLENS — SIH 2026 ONE-CLICK LAUNCHER
echo ============================================================
echo Starting PhishLens Backend Core Engine on http://localhost:3001 ...
start "PhishLens Backend" cmd /k "cd /d ""%~dp0my-product-backend"" && node server.js"

timeout /t 3 /nobreak >nul

echo Starting PhishLens SOC Dashboard on http://localhost:3005 ...
start "PhishLens Dashboard" cmd /k "cd /d ""%~dp0my-product-dashboard"" && npx vite --port 3005"

echo ============================================================
echo All services launched!
echo PhishLens SOC Dashboard: http://localhost:3005
echo Backend Engine:      http://localhost:3001
echo Sublime Dashboard:   http://localhost:3000
echo ============================================================
pause
