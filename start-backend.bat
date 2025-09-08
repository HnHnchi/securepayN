@echo off
echo Starting SecurePat Backend...
echo.

cd backend

echo Installing dependencies...
call npm install
if errorlevel 1 (
    echo Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo Starting Backend Server...
echo Backend will be available at: http://localhost:5000
echo.
npm start
