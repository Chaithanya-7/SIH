@echo off
echo ============================================================
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
echo ============================================================
pause
