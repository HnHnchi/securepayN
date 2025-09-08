@echo off
echo Starting SecurePat Application in Development Mode...
echo.

echo Building and starting Docker containers in development mode...
docker-compose -f docker-compose.dev.yml up --build

echo.
echo Development application is running!
echo Backend: http://localhost:5000
echo Frontend: http://localhost:3000
echo.
echo Press Ctrl+C to stop the containers
echo Press any key to exit this window...
pause > nul
