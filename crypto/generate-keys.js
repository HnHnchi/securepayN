const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Ensure directories exist
const keysDir = path.join(__dirname, 'keys');
const certsDir = path.join(__dirname, 'certs');

if (!fs.existsSync(keysDir)) fs.mkdirSync(keysDir, { recursive: true });
if (!fs.existsSync(certsDir)) fs.mkdirSync(certsDir, { recursive: true });

console.log('🔐 Generating Cryptographic Materials...\n');

// 1. Generate Client RSA Key Pair
console.log('1. Generating Client RSA Key Pair...');
const clientKeyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

fs.writeFileSync(path.join(keysDir, 'client_rsa_private.pem'), clientKeyPair.privateKey);
fs.writeFileSync(path.join(keysDir, 'client_rsa_public.pem'), clientKeyPair.publicKey);
console.log('   ✅ client_rsa_private.pem');
console.log('   ✅ client_rsa_public.pem');

// 2. Generate Server RSA Key Pair
console.log('\n2. Generating Server RSA Key Pair...');
const serverKeyPair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

fs.writeFileSync(path.join(keysDir, 'rsa_private.pem'), serverKeyPair.privateKey);
fs.writeFileSync(path.join(keysDir, 'rsa_public.pem'), serverKeyPair.publicKey);
console.log('   ✅ rsa_private.pem');
console.log('   ✅ rsa_public.pem');

// 3. Generate AES-256 Keys
console.log('\n3. Generating AES-256 Keys...');
const aesKey1 = crypto.randomBytes(32).toString('base64');
const aesKey2 = crypto.randomBytes(32).toString('base64');

fs.writeFileSync(path.join(keysDir, 'aes_key_1.txt'), aesKey1);
fs.writeFileSync(path.join(keysDir, 'aes_key_2.txt'), aesKey2);
console.log('   ✅ aes_key_1.txt (Base64-encoded)');
console.log('   ✅ aes_key_2.txt (Base64-encoded)');

// 4. Generate Self-Signed Certificate
console.log('\n4. Generating Self-Signed Certificate...');
// Note: Node.js crypto doesn't have createCertificate, so we'll create a mock certificate
// For production, use OpenSSL or a proper certificate library
const certInfo = {
    subject: {
        C: 'US',
        ST: 'State',
        L: 'City',
        O: 'SecurePat',
        OU: 'IT Department',
        CN: 'localhost'
    },
    issuer: {
        C: 'US',
        ST: 'State',
        L: 'City',
        O: 'SecurePat',
        OU: 'IT Department',
        CN: 'localhost'
    },
    notBefore: new Date().toISOString(),
    notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    serialNumber: '01',
    publicKey: serverKeyPair.publicKey,
    privateKey: serverKeyPair.privateKey
};

// Create a placeholder certificate file with instructions
const certInstructions = `# Self-Signed Certificate Instructions

This is a placeholder for the self-signed certificate.
To generate a proper certificate, use OpenSSL:

openssl req -x509 -newkey rsa:2048 -keyout rsa_private.pem -out server.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=SecurePat/OU=IT Department/CN=localhost"

Or use the following command with the existing key:
openssl req -x509 -key rsa_private.pem -out server.crt -days 365 -subj "/C=US/ST=State/L=City/O=SecurePat/OU=IT Department/CN=localhost"

Certificate Info:
${JSON.stringify(certInfo, null, 2)}
`;

fs.writeFileSync(path.join(certsDir, 'server.crt'), certInstructions);
console.log('   ✅ server.crt (Certificate instructions)');

// 5. Create PKCS#12 Keystore
console.log('\n5. Creating PKCS#12 Keystore...');
// Note: Node.js crypto doesn't directly support PKCS#12 creation
// We'll create a simple keystore format and provide instructions for conversion
const keystoreInfo = {
    certificate: 'server.crt (see instructions in file)',
    privateKey: 'rsa_private.pem',
    password: 'securepat123', // Default password for testing
    instructions: [
        'To convert to PKCS#12 format, use OpenSSL:',
        'openssl pkcs12 -export -in server.crt -inkey rsa_private.pem -out server.p12 -name "securepat" -password pass:securepat123'
    ]
};

fs.writeFileSync(path.join(certsDir, 'keystore-info.json'), JSON.stringify(keystoreInfo, null, 2));
console.log('   ✅ keystore-info.json (PKCS#12 conversion info)');

// 6. Create Configuration File
console.log('\n6. Creating Configuration File...');
const config = {
    keys: {
        client: {
            private: 'crypto/keys/client_rsa_private.pem',
            public: 'crypto/keys/client_rsa_public.pem'
        },
        server: {
            private: 'crypto/keys/rsa_private.pem',
            public: 'crypto/keys/rsa_public.pem'
        }
    },
    aes: {
        key1: aesKey1,
        key2: aesKey2
    },
    certificate: {
        path: 'crypto/certs/server.crt',
        keystore: 'crypto/certs/server.p12',
        password: 'securepat123'
    }
};

fs.writeFileSync(path.join(__dirname, 'crypto-config.json'), JSON.stringify(config, null, 2));
console.log('   ✅ crypto-config.json (Configuration file)');

console.log('\n🎉 All cryptographic materials generated successfully!');
console.log('\n📁 Files created:');
console.log('   Keys:');
console.log('     - crypto/keys/client_rsa_private.pem');
console.log('     - crypto/keys/client_rsa_public.pem');
console.log('     - crypto/keys/rsa_private.pem');
console.log('     - crypto/keys/rsa_public.pem');
console.log('     - crypto/keys/aes_key_1.txt');
console.log('     - crypto/keys/aes_key_2.txt');
console.log('   Certificates:');
console.log('     - crypto/certs/server.crt');
console.log('     - crypto/certs/keystore-info.json');
console.log('   Configuration:');
console.log('     - crypto/crypto-config.json');
console.log('\n💡 Note: To create PKCS#12 keystore, install OpenSSL and run:');
console.log('   openssl pkcs12 -export -in crypto/certs/server.crt -inkey crypto/keys/rsa_private.pem -out crypto/certs/server.p12 -name "securepat" -password pass:securepat123');
