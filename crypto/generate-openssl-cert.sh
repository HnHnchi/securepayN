#!/bin/bash

echo "Generating Self-Signed Certificate and PKCS#12 Keystore with OpenSSL..."
echo

# Check if OpenSSL is available
if ! command -v openssl &> /dev/null; then
    echo "OpenSSL is not installed or not in PATH."
    echo "Please install OpenSSL:"
    echo "  Ubuntu/Debian: sudo apt-get install openssl"
    echo "  CentOS/RHEL: sudo yum install openssl"
    echo "  macOS: brew install openssl"
    echo
    exit 1
fi

echo "OpenSSL found. Generating certificate..."

# Generate self-signed certificate
echo "Creating self-signed certificate..."
openssl req -x509 -key keys/rsa_private.pem -out certs/server.crt -days 365 -subj "/C=US/ST=State/L=City/O=SecurePat/OU=IT Department/CN=localhost"

if [ $? -ne 0 ]; then
    echo "Failed to generate certificate"
    exit 1
fi

echo "Certificate created: certs/server.crt"

# Create PKCS#12 keystore
echo "Creating PKCS#12 keystore..."
openssl pkcs12 -export -in certs/server.crt -inkey keys/rsa_private.pem -out certs/server.p12 -name "securepat" -password pass:securepat123

if [ $? -ne 0 ]; then
    echo "Failed to create PKCS#12 keystore"
    exit 1
fi

echo "PKCS#12 keystore created: certs/server.p12"
echo
echo "All cryptographic materials are ready!"
echo
echo "Files created:"
echo "  - keys/client_rsa_private.pem"
echo "  - keys/client_rsa_public.pem"
echo "  - keys/rsa_private.pem"
echo "  - keys/rsa_public.pem"
echo "  - keys/aes_key_1.txt"
echo "  - keys/aes_key_2.txt"
echo "  - certs/server.crt"
echo "  - certs/server.p12"
echo "  - crypto-config.json"
echo
echo "Keystore password: securepat123"
echo
