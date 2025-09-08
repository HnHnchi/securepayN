# Cryptographic Materials and Utilities

This directory contains all the cryptographic materials and utilities for the SecurePat application.

## 🔐 Generated Materials

### RSA Key Pairs
- **Client RSA Key Pair**:
  - `keys/client_rsa_private.pem` - Client private key (PKCS#8 format)
  - `keys/client_rsa_public.pem` - Client public key (SPKI format)

- **Server RSA Key Pair**:
  - `keys/rsa_private.pem` - Server private key (PKCS#8 format)
  - `keys/rsa_public.pem` - Server public key (SPKI format)

### AES-256 Keys
- `keys/aes_key_1.txt` - First AES-256 key (Base64-encoded, 32 bytes)
- `keys/aes_key_2.txt` - Second AES-256 key (Base64-encoded, 32 bytes)

### Certificates
- `certs/server.crt` - Self-signed server certificate (instructions for generation)
- `certs/keystore-info.json` - PKCS#12 keystore conversion information

### Configuration
- `crypto-config.json` - Central configuration file with all key paths and values

## 🛠️ Generation Scripts

### Node.js Generation (No OpenSSL Required)
```bash
# Generate all keys and materials
node generate-keys.js
```

### OpenSSL Generation (For Production Certificates)
```bash
# Windows
generate-openssl-cert.bat

# Linux/macOS
./generate-openssl-cert.sh
```

## 🧪 Testing

### Test All Cryptographic Utilities
```bash
node test-crypto.js
```

### Test Backend Crypto Integration
```bash
# Start the backend and test the crypto endpoint
curl http://localhost:5000/api/crypto/test
```

## 📚 Utility Functions

The `crypto-utils.js` module provides comprehensive cryptographic utilities:

### String/Byte Conversions
- `stringToBytes(str)` - Convert string to UTF-8 byte array
- `bytesToString(bytes)` - Convert byte array to string

### Base64 Encoding/Decoding
- `base64Encode(data)` - Base64 encode data
- `base64Decode(encoded)` - Base64 decode string

### PEM File Operations
- `loadPemFile(filePath)` - Load PEM file content
- `loadPublicKey(filePath)` - Load public key from PEM file
- `loadPrivateKey(filePath)` - Load private key from PEM file

### RSA Operations
- `signRSA(data, privateKey)` - Sign data with RSA private key
- `verifyRSA(data, signature, publicKey)` - Verify RSA signature

### AES Operations
- `encryptAES(data, key)` - Encrypt data with AES-256-GCM
- `decryptAES(encryptedData, key)` - Decrypt AES-256-GCM data
- `generateAESKey()` - Generate random AES-256 key
- `generateAESKeyBase64()` - Generate Base64-encoded AES-256 key

### Hash Functions
- `sha256(data)` - SHA-256 hash (hex)
- `sha256Base64(data)` - SHA-256 hash (Base64)
- `hmacSha256(data, key)` - HMAC-SHA256 (hex)
- `hmacSha256Base64(data, key)` - HMAC-SHA256 (Base64)

### Utility Functions
- `getKeyFingerprint(key)` - Get SHA-256 fingerprint of public key
- `loadConfig(configPath)` - Load crypto configuration
- `generateRandomBytes(length)` - Generate random bytes

## 🔧 Usage Examples

### Basic Usage
```javascript
const CryptoUtils = require('./crypto-utils');

// Load configuration
const config = CryptoUtils.loadConfig();

// Load keys
const clientPrivateKey = CryptoUtils.loadPrivateKey(config.keys.client.private);
const serverPublicKey = CryptoUtils.loadPublicKey(config.keys.server.public);

// Sign data
const message = 'Hello, SecurePat!';
const signature = CryptoUtils.signRSA(message, clientPrivateKey);

// Verify signature
const isValid = CryptoUtils.verifyRSA(message, signature, serverPublicKey);

// Encrypt data
const encrypted = CryptoUtils.encryptAES(message, config.aes.key1);
const decrypted = CryptoUtils.decryptAES(encrypted, config.aes.key1);
```

### Advanced Usage
```javascript
// Generate new AES key
const newAESKey = CryptoUtils.generateAESKeyBase64();

// Create HMAC
const hmac = CryptoUtils.hmacSha256('data', 'secret-key');

// Get key fingerprint
const fingerprint = CryptoUtils.getKeyFingerprint(publicKey);

// String/byte conversions
const bytes = CryptoUtils.stringToBytes('Hello');
const backToString = CryptoUtils.bytesToString(bytes);
```

## 🔒 Security Notes

1. **Key Storage**: Private keys should be stored securely and never committed to version control
2. **Key Rotation**: Regularly rotate AES keys and certificates
3. **Certificate Validation**: In production, use proper certificate authorities
4. **Random Generation**: All random data is generated using cryptographically secure methods
5. **Algorithm Selection**: Uses industry-standard algorithms (RSA-2048, AES-256-GCM, SHA-256)

## 📋 OpenSSL Commands Reference

### Generate Self-Signed Certificate
```bash
openssl req -x509 -key keys/rsa_private.pem -out certs/server.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=SecurePat/OU=IT Department/CN=localhost"
```

### Create PKCS#12 Keystore
```bash
openssl pkcs12 -export -in certs/server.crt -inkey keys/rsa_private.pem \
  -out certs/server.p12 -name "securepat" -password pass:securepat123
```

### View Certificate Details
```bash
openssl x509 -in certs/server.crt -text -noout
```

### Verify Certificate
```bash
openssl verify certs/server.crt
```

## 🚀 Integration with Backend

The backend automatically loads the crypto configuration and provides a test endpoint:

- **Health Check**: `GET /api/health`
- **System Status**: `GET /api/status`
- **Crypto Test**: `GET /api/crypto/test`

The crypto test endpoint demonstrates:
- RSA signing and verification
- AES encryption and decryption
- Key fingerprint generation
- Configuration loading

## 📁 File Structure

```
crypto/
├── keys/
│   ├── client_rsa_private.pem    # Client private key
│   ├── client_rsa_public.pem     # Client public key
│   ├── rsa_private.pem           # Server private key
│   ├── rsa_public.pem            # Server public key
│   ├── aes_key_1.txt             # First AES key
│   └── aes_key_2.txt             # Second AES key
├── certs/
│   ├── server.crt                # Server certificate
│   ├── keystore-info.json        # PKCS#12 info
│   └── server.p12                # PKCS#12 keystore (if generated)
├── generate-keys.js              # Key generation script
├── generate-openssl-cert.bat     # Windows OpenSSL script
├── generate-openssl-cert.sh      # Linux/macOS OpenSSL script
├── test-crypto.js                # Crypto utilities test
├── crypto-utils.js               # Main utilities module
├── crypto-config.json            # Configuration file
└── README.md                     # This file
```

All cryptographic materials are ready for use in your SecurePat application! 🎉
