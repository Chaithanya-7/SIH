@echo off
echo ============================================================
<<<<<<< HEAD
echo   PHISHLENS — SIH 2026 ONE-CLICK LAUNCHER
echo ============================================================
echo Starting PhishLens Backend Core Engine on http://localhost:3001 ...
start "PhishLens Backend" cmd /k "cd /d ""%~dp0phishlens-backend"" && node server.js"

timeout /t 3 /nobreak >nul

echo Starting PhishLens SOC Dashboard on http://localhost:3005 ...
start "PhishLens Dashboard" cmd /k "cd /d ""%~dp0phishlens-dashboard"" && npx vite --port 3005"

echo ============================================================
echo All services launched!
echo PhishLens SOC Dashboard: http://localhost:3005
echo Backend Engine:      http://localhost:3001
=======
echo   SECUREMAIL AI — SIH 2026 ONE-CLICK LAUNCHER
echo ============================================================
echo Starting SecureMail Backend Core Engine on http://localhost:3001 ...
start "SecureMail Backend" cmd /k "cd /d D:\sih\my-product-backend && node server.js"

timeout /t 3 /nobreak >nul

echo Starting SecureMail Custom SOC Dashboard on http://localhost:3005 ...
start "SecureMail Dashboard" cmd /k "cd /d D:\sih\my-product-dashboard && npx vite --port 3005"

echo ============================================================
echo All services launched!
echo Custom SOC Dashboard: http://localhost:3005
echo Backend Engine:      http://localhost:3001
echo Sublime Dashboard:   http://localhost:3000
>>>>>>> f7f1f4d8e33400ea5fae1975653db1ac88ff5dcc
echo ============================================================
pause
