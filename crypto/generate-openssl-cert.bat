@echo off
echo Generating Self-Signed Certificate and PKCS#12 Keystore with OpenSSL...
echo.

REM Check if OpenSSL is available
openssl version >nul 2>&1
if errorlevel 1 (
    echo OpenSSL is not installed or not in PATH.
    echo Please install OpenSSL from: https://slproweb.com/products/Win32OpenSSL.html
    echo Or use Git Bash which includes OpenSSL.
    echo.
    echo Alternative: Use the Node.js generated keys and create certificate manually.
    pause
    exit /b 1
)

echo OpenSSL found. Generating certificate...

REM Generate self-signed certificate
echo Creating self-signed certificate...
openssl req -x509 -key keys\rsa_private.pem -out certs\server.crt -days 365 -subj "/C=US/ST=State/L=City/O=SecurePat/OU=IT Department/CN=localhost"

if errorlevel 1 (
    echo Failed to generate certificate
    pause
    exit /b 1
)

echo Certificate created: certs\server.crt

REM Create PKCS#12 keystore
echo Creating PKCS#12 keystore...
openssl pkcs12 -export -in certs\server.crt -inkey keys\rsa_private.pem -out certs\server.p12 -name "securepat" -password pass:securepat123

if errorlevel 1 (
    echo Failed to create PKCS#12 keystore
    pause
    exit /b 1
)

echo PKCS#12 keystore created: certs\server.p12
echo.
echo All cryptographic materials are ready!
echo.
echo Files created:
echo   - keys\client_rsa_private.pem
echo   - keys\client_rsa_public.pem
echo   - keys\rsa_private.pem
echo   - keys\rsa_public.pem
echo   - keys\aes_key_1.txt
echo   - keys\aes_key_2.txt
echo   - certs\server.crt
echo   - certs\server.p12
echo   - crypto-config.json
echo.
echo Keystore password: securepat123
echo.
pause
