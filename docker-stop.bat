@echo off
echo Stopping SecurePat Docker containers...
echo.

docker-compose down

echo.
echo All containers stopped!
echo.
echo Press any key to exit...
pause > nul
