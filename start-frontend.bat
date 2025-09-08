@echo off
echo Starting SecurePat Frontend...
echo.

cd frontend

echo Installing dependencies...
call npm install
if errorlevel 1 (
    echo Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo Starting Frontend Server...
echo Frontend will be available at: http://localhost:3000
echo.
npm start
