const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const CryptoUtils = require('../crypto/crypto-utils');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Database configuration
const DATABASE_PATH = path.join(__dirname, 'securepat.db');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');
let db; // Global database connection

// Initialize database
function initDatabase() {
    return new Promise((resolve, reject) => {
        const db = new sqlite3.Database(DATABASE_PATH, (err) => {
            if (err) {
                console.error('Error opening database:', err);
                reject(err);
                return;
            }
            console.log('Connected to SQLite database');
        });

        // Read and execute schema
        fs.readFile(SCHEMA_PATH, 'utf8', (err, data) => {
            if (err) {
                console.error('Error reading schema file:', err);
                reject(err);
                return;
            }

            db.exec(data, (err) => {
                if (err) {
                    console.error('Error executing schema:', err);
                    reject(err);
                    return;
                }
                console.log('Database schema initialized');
                resolve(db);
            });
        });
    });
}

// Health check endpoint
app.get('/api/health', (req, res) => {
    if (!db) {
        return res.status(500).json({
            status: 'unhealthy',
            timestamp: new Date().toISOString(),
            error: 'Database not initialized',
            service: 'backend'
        });
    }
    
    db.get('SELECT 1 as test', (err, row) => {
        if (err) {
            return res.status(500).json({
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                error: err.message,
                service: 'backend'
            });
        }

        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            database: 'connected',
            service: 'backend'
        });
    });
});

// System status endpoint
app.get('/api/status', (req, res) => {
    if (!db) {
        return res.status(500).json({
            status: 'error',
            timestamp: new Date().toISOString(),
            error: 'Database not initialized'
        });
    }
    
    db.get('SELECT COUNT(*) as merchant_count FROM merchants', (err, row) => {
        if (err) {
            return res.status(500).json({
                status: 'error',
                timestamp: new Date().toISOString(),
                error: err.message
            });
        }
        
        res.json({
            status: 'operational',
            timestamp: new Date().toISOString(),
            database: 'connected',
            merchants_count: row.merchant_count,
            uptime: 'running'
        });
    });
});

// Crypto test endpoint
app.get('/api/crypto/test', (req, res) => {
    try {
        const config = CryptoUtils.loadConfig();
        const testMessage = 'SecurePat Crypto Test';
        
        // Test RSA signing
        const clientPrivateKey = CryptoUtils.loadPrivateKey(path.join(__dirname, '../crypto/keys/client_rsa_private.pem'));
        const signature = CryptoUtils.signRSA(testMessage, clientPrivateKey);
        
        // Test AES encryption
        const encrypted = CryptoUtils.encryptAES(testMessage, config.aes.key1);
        const decrypted = CryptoUtils.decryptAES(encrypted, config.aes.key2);
        
        // Test HMAC-SHA256
        const secret = Buffer.from('test-secret-key-32-bytes-long-12345', 'utf8');
        const message = Buffer.from(testMessage, 'utf8');
        const hmac = CryptoUtils.hmacSha256Base64Bytes(secret, message);
        const hmacValid = CryptoUtils.hmacSha256Verify(secret, message, hmac);
        
        // Test RSA methods
        const rsaMessage = Buffer.from(testMessage, 'utf8');
        const rsaEncrypted = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, rsaMessage);
        const rsaDecrypted = CryptoUtils.rsaDecryptWithPrivate(clientPrivateKey, rsaEncrypted);
        const rsaSignature = CryptoUtils.rsaSign(serverPrivateKey, rsaMessage);
        const rsaValid = CryptoUtils.rsaVerify(serverPublicKey, rsaMessage, rsaSignature);
        
        res.json({
            status: 'crypto_test_complete',
            timestamp: new Date().toISOString(),
            tests: {
                rsa_signing: {
                    message: testMessage,
                    signature: signature.substring(0, 50) + '...',
                    success: true
                },
                aes_encryption: {
                    original: testMessage,
                    encrypted: encrypted.encrypted.substring(0, 50) + '...',
                    decrypted: decrypted,
                    success: testMessage === decrypted
                },
                hmac_sha256: {
                    message: testMessage,
                    hmac: hmac,
                    verification: hmacValid,
                    success: hmacValid
                },
                rsa_oaep: {
                    message: testMessage,
                    encrypted_length: rsaEncrypted.length,
                    decrypted: rsaDecrypted.toString('utf8'),
                    success: rsaMessage.equals(rsaDecrypted)
                },
                rsa_pss: {
                    message: testMessage,
                    signature_length: rsaSignature.length,
                    verification: rsaValid,
                    success: rsaValid
                },
                key_fingerprints: {
                    client: CryptoUtils.getKeyFingerprint(CryptoUtils.loadPublicKey(path.join(__dirname, '../crypto/keys/client_rsa_public.pem'))),
                    server: CryptoUtils.getKeyFingerprint(CryptoUtils.loadPublicKey(path.join(__dirname, '../crypto/keys/rsa_public.pem')))
                }
            }
        });
    } catch (error) {
        res.status(500).json({
            status: 'crypto_test_failed',
            timestamp: new Date().toISOString(),
            error: error.message
        });
    }
});

// Create merchant endpoint
app.post('/api/merchants', (req, res) => {
    try {
        const { name, email } = req.body;

        // Input validation
        if (!name || !email) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'Both name and email are required',
                required_fields: ['name', 'email']
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                error: 'Invalid email format',
                message: 'Please provide a valid email address'
            });
        }

        // Validate name length
        if (name.length < 2 || name.length > 100) {
            return res.status(400).json({
                error: 'Invalid name length',
                message: 'Name must be between 2 and 100 characters'
            });
        }

        // Check if email already exists
        db.get('SELECT id FROM merchants WHERE email = ?', [email], (err, existingMerchant) => {
            if (err) {
                console.error('Database error checking email:', err);
                return res.status(500).json({
                    error: 'Database error',
                    message: 'Failed to check email uniqueness'
                });
            }

            if (existingMerchant) {
                return res.status(409).json({
                    error: 'Email already exists',
                    message: 'A merchant with this email already exists',
                    merchant_id: existingMerchant.id
                });
            }

            // Create new merchant (without keys for now - they'll be added during key exchange)
            const query = `
                INSERT INTO merchants (name, email, aes_key_base64, hmac_key_base64) 
                VALUES (?, ?, '', '')
            `;
            
            db.run(query, [name, email], function(err) {
                if (err) {
                    console.error('Database error creating merchant:', err);
                    return res.status(500).json({
                        error: 'Database error',
                        message: 'Failed to create merchant'
                    });
                }

                // Get the created merchant record
                db.get('SELECT id, name, email, created_at FROM merchants WHERE id = ?', [this.lastID], (err, merchant) => {
                    if (err) {
                        console.error('Database error fetching merchant:', err);
                        return res.status(500).json({
                            error: 'Database error',
                            message: 'Merchant created but failed to retrieve details'
                        });
                    }

                    res.status(201).json({
                        id: merchant.id,
                        name: merchant.name,
                        email: merchant.email,
                        created_at: merchant.created_at,
                        status: 'created',
                        message: 'Merchant registered successfully. Keys will be assigned during key exchange.'
                    });
                });
            });
        });

    } catch (error) {
        console.error('Error in merchant creation:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: 'An unexpected error occurred'
        });
    }
});

// Key exchange request endpoint
app.post('/api/keys/exchange/request', (req, res) => {
    try {
        const { ciphertext, signature } = req.body;

        // Input validation
        if (!ciphertext || !signature) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'Both ciphertext and signature are required',
                required_fields: ['ciphertext', 'signature']
            });
        }

        // Load server private key for decryption
        const serverPrivateKey = CryptoUtils.loadPrivateKey(path.join(__dirname, '../crypto/keys/rsa_private.pem'));
        
        // Load client public key for signature verification
        const clientPublicKey = CryptoUtils.loadPublicKey(path.join(__dirname, '../crypto/keys/client_rsa_public.pem'));

        // Decrypt the request using server private key
        const encryptedData = Buffer.from(ciphertext, 'base64');
        const decryptedData = CryptoUtils.rsaDecryptWithPrivate(serverPrivateKey, encryptedData);
        const requestJson = JSON.parse(decryptedData.toString('utf8'));

        // Verify signature using client public key
        const signatureBuffer = Buffer.from(signature, 'base64');
        const isValidSignature = CryptoUtils.rsaVerify(clientPublicKey, decryptedData, signatureBuffer);

        if (!isValidSignature) {
            return res.status(401).json({
                error: 'Invalid signature',
                message: 'Request signature verification failed'
            });
        }

        // Validate request data
        const { merchantId, nonce, timestamp } = requestJson;

        if (!merchantId || !nonce || !timestamp) {
            return res.status(400).json({
                error: 'Invalid request data',
                message: 'Missing merchantId, nonce, or timestamp in decrypted request'
            });
        }

        // Validate timestamp (within 5 minutes)
        const now = Date.now();
        const requestTime = parseInt(timestamp);
        const timeDiff = Math.abs(now - requestTime);
        const maxAge = 5 * 60 * 1000; // 5 minutes

        if (timeDiff > maxAge) {
            return res.status(400).json({
                error: 'Request expired',
                message: 'Request timestamp is too old',
                timeDiff: timeDiff,
                maxAge: maxAge
            });
        }

        // Check if merchant exists
        db.get('SELECT id, name, email FROM merchants WHERE id = ?', [merchantId], (err, merchant) => {
            if (err) {
                console.error('Database error checking merchant:', err);
                return res.status(500).json({
                    error: 'Database error',
                    message: 'Failed to verify merchant'
                });
            }

            if (!merchant) {
                return res.status(404).json({
                    error: 'Merchant not found',
                    message: `Merchant with ID ${merchantId} does not exist`
                });
            }

            // Generate new keys for the merchant
            const aesKey = CryptoUtils.generateRandomBytes(32).toString('base64');
            const hmacKey = CryptoUtils.generateRandomBytes(32).toString('base64');

            // Update merchant with new keys
            const updateQuery = `
                UPDATE merchants 
                SET aes_key_base64 = ?, hmac_key_base64 = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            `;

            db.run(updateQuery, [aesKey, hmacKey, merchantId], function(err) {
                if (err) {
                    console.error('Database error updating merchant keys:', err);
                    return res.status(500).json({
                        error: 'Database error',
                        message: 'Failed to update merchant keys'
                    });
                }

                // Prepare response payload
                const responsePayload = {
                    merchantId: merchantId,
                    aesKeyBase64: aesKey,
                    hmacKeyBase64: hmacKey,
                    issuedAt: new Date().toISOString(),
                    nonce: nonce // Echo the nonce back
                };

                // Sign the response with server private key
                const responseJson = JSON.stringify(responsePayload);
                const responseBuffer = Buffer.from(responseJson, 'utf8');
                const responseSignature = CryptoUtils.rsaSign(serverPrivateKey, responseBuffer);

                // Encrypt the response with client public key
                const responseEncrypted = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, responseBuffer);

                // Send encrypted and signed response
                res.status(200).json({
                    ciphertext: responseEncrypted.toString('base64'),
                    signature: responseSignature.toString('base64')
                });
            });
        });

    } catch (error) {
        console.error('Error in key exchange request:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: 'An unexpected error occurred during key exchange'
        });
    }
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'SecurePat Backend API',
        version: '1.0.0',
        endpoints: {
            health: '/api/health',
            status: '/api/status',
            crypto_test: '/api/crypto/test',
            merchants: '/api/merchants',
            key_exchange: '/api/keys/exchange/request'
        }
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        status: 'error',
        message: 'Something went wrong!',
        timestamp: new Date().toISOString()
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        status: 'error',
        message: 'Endpoint not found',
        timestamp: new Date().toISOString()
    });
});

// Start server
async function startServer() {
    try {
        db = await initDatabase();
        
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Backend server running on http://localhost:${PORT}`);
            console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
            console.log(`📈 System status: http://localhost:${PORT}/api/status`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();
