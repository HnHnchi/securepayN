@echo off
echo Starting SecurePat Application...
echo.

echo Installing backend dependencies...
cd backend
call npm install
if errorlevel 1 (
    echo Failed to install backend dependencies
    pause
    exit /b 1
)

echo Installing frontend dependencies...
cd ..\frontend
call npm install
if errorlevel 1 (
    echo Failed to install frontend dependencies
    pause
    exit /b 1
)

echo.
echo Starting Backend Server...
start "Backend Server" cmd /k "cd backend && npm start"

echo Waiting for backend to start...
timeout /t 3

echo Starting Frontend Server...
start "Frontend Server" cmd /k "cd frontend && npm start"

echo.
echo Both servers are starting...
echo Backend: http://localhost:5000
echo Frontend: http://localhost:3000
echo.
echo Press any key to exit this window...
pause > nul
