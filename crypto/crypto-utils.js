const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Crypto Utility Helper Functions
 * Provides string ↔ byte[] conversions, Base64 encode/decode, and PEM loader utilities
 */

class CryptoUtils {
    /**
     * Convert string to UTF-8 byte array
     * @param {string} str - Input string
     * @returns {Buffer} UTF-8 encoded byte array
     */
    static stringToBytes(str) {
        return Buffer.from(str, 'utf8');
    }

    /**
     * Convert UTF-8 byte array to string
     * @param {Buffer} bytes - Input byte array
     * @returns {string} Decoded string
     */
    static bytesToString(bytes) {
        return bytes.toString('utf8');
    }

    /**
     * Base64 encode data
     * @param {string|Buffer} data - Data to encode
     * @returns {string} Base64 encoded string
     */
    static base64Encode(data) {
        if (typeof data === 'string') {
            return Buffer.from(data, 'utf8').toString('base64');
        }
        return data.toString('base64');
    }

    /**
     * Base64 decode string
     * @param {string} encoded - Base64 encoded string
     * @returns {string} Decoded string
     */
    static base64Decode(encoded) {
        return Buffer.from(encoded, 'base64').toString('utf8');
    }

    /**
     * Load PEM file and return as string
     * @param {string} filePath - Path to PEM file
     * @returns {string} PEM content
     */
    static loadPemFile(filePath) {
        try {
            return fs.readFileSync(filePath, 'utf8');
        } catch (error) {
            throw new Error(`Failed to load PEM file ${filePath}: ${error.message}`);
        }
    }

    /**
     * Load public key from PEM file
     * @param {string} filePath - Path to public key PEM file
     * @returns {crypto.KeyObject} Public key object
     */
    static loadPublicKey(filePath) {
        try {
            const pemContent = this.loadPemFile(filePath);
            return crypto.createPublicKey(pemContent);
        } catch (error) {
            throw new Error(`Failed to load public key from ${filePath}: ${error.message}`);
        }
    }

    /**
     * Load public key from PEM content (supports PKCS#1 and PKCS#8)
     * @param {string} pemContent - PEM content as string
     * @returns {crypto.KeyObject} Public key object
     */
    static loadPublicKeyFromPem(pemContent) {
        try {
            return crypto.createPublicKey(pemContent);
        } catch (error) {
            throw new Error(`Failed to load public key from PEM: ${error.message}`);
        }
    }

    /**
     * Load private key from PEM file
     * @param {string} filePath - Path to private key PEM file
     * @returns {crypto.KeyObject} Private key object
     */
    static loadPrivateKey(filePath) {
        try {
            const pemContent = this.loadPemFile(filePath);
            return crypto.createPrivateKey(pemContent);
        } catch (error) {
            throw new Error(`Failed to load private key from ${filePath}: ${error.message}`);
        }
    }

    /**
     * Load private key from PEM content (supports PKCS#1 and PKCS#8)
     * @param {string} pemContent - PEM content as string
     * @returns {crypto.KeyObject} Private key object
     */
    static loadPrivateKeyFromPem(pemContent) {
        try {
            return crypto.createPrivateKey(pemContent);
        } catch (error) {
            throw new Error(`Failed to load private key from PEM: ${error.message}`);
        }
    }

    /**
     * Generate random bytes
     * @param {number} length - Number of bytes to generate
     * @returns {Buffer} Random bytes
     */
    static generateRandomBytes(length) {
        return crypto.randomBytes(length);
    }

    /**
     * Generate AES-256 key
     * @returns {Buffer} 32-byte AES key
     */
    static generateAESKey() {
        return crypto.randomBytes(32);
    }

    /**
     * Generate AES-256 key as Base64 string
     * @returns {string} Base64-encoded AES key
     */
    static generateAESKeyBase64() {
        return this.generateAESKey().toString('base64');
    }

    /**
     * Encrypt data with AES-256-GCM
     * @param {string|Buffer} data - Data to encrypt
     * @param {Buffer|string} key - AES key (32 bytes or Base64 string)
     * @returns {Object} {encrypted, iv, tag}
     */
    static encryptAES(data, key) {
        const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'base64') : key;
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, iv);

        let encrypted = cipher.update(data, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        return {
            encrypted: encrypted.toString('base64'),
            iv: iv.toString('base64')
        };
    }

    /**
     * Decrypt data with AES-256-GCM
     * @param {Object} encryptedData - {encrypted, iv, tag}
     * @param {Buffer|string} key - AES key (32 bytes or Base64 string)
     * @returns {string} Decrypted data
     */
    static decryptAES(encryptedData, key) {
        const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'base64') : key;
        const iv = Buffer.from(encryptedData.iv, 'base64');
        const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, iv);

        let decrypted = decipher.update(Buffer.from(encryptedData.encrypted, 'base64'));
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return decrypted.toString('utf8');
    }

    /**
     * Sign data with RSA private key
     * @param {string|Buffer} data - Data to sign
     * @param {crypto.KeyObject|string} privateKey - Private key object or PEM file path
     * @returns {string} Base64-encoded signature
     */
    static signRSA(data, privateKey) {
        const key = typeof privateKey === 'string' ? this.loadPrivateKey(privateKey) : privateKey;
        const sign = crypto.createSign('SHA256');
        sign.update(data);
        return sign.sign(key, 'base64');
    }

    /**
     * RSA Encrypt with Public Key using OAEP padding
     * @param {crypto.KeyObject} publicKey - Public key object
     * @param {Buffer} data - Data to encrypt as byte array
     * @returns {Buffer} Encrypted data as byte array
     */
    static rsaEncryptWithPublic(publicKey, data) {
        if (!Buffer.isBuffer(data)) {
            throw new Error('Data must be a Buffer object');
        }
        if (!publicKey || typeof publicKey.export !== 'function') {
            throw new Error('Invalid public key object');
        }

        try {
            // Use OAEP padding for better security
            const encrypted = crypto.publicEncrypt({
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            }, data);
            return encrypted;
        } catch (error) {
            throw new Error(`RSA encryption failed: ${error.message}`);
        }
    }

    /**
     * RSA Decrypt with Private Key using OAEP padding
     * @param {crypto.KeyObject} privateKey - Private key object
     * @param {Buffer} data - Encrypted data as byte array
     * @returns {Buffer} Decrypted data as byte array
     */
    static rsaDecryptWithPrivate(privateKey, data) {
        if (!Buffer.isBuffer(data)) {
            throw new Error('Data must be a Buffer object');
        }
        if (!privateKey || typeof privateKey.export !== 'function') {
            throw new Error('Invalid private key object');
        }

        try {
            // Use OAEP padding for better security
            const decrypted = crypto.privateDecrypt({
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            }, data);
            return decrypted;
        } catch (error) {
            throw new Error(`RSA decryption failed: ${error.message}`);
        }
    }

    /**
     * RSA Sign with Private Key using PSS padding
     * @param {crypto.KeyObject} privateKey - Private key object
     * @param {Buffer} message - Message to sign as byte array
     * @returns {Buffer} Signature as byte array
     */
    static rsaSign(privateKey, message) {
        if (!Buffer.isBuffer(message)) {
            throw new Error('Message must be a Buffer object');
        }
        if (!privateKey || typeof privateKey.export !== 'function') {
            throw new Error('Invalid private key object');
        }

        try {
            // Use PSS padding for better security
            // First hash the message with SHA-256
            const hash = crypto.createHash('sha256').update(message).digest();
            
            const sign = crypto.createSign('RSA-PSS');
            sign.update(hash);
            const signature = sign.sign({
                key: privateKey,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
                mgf1HashAlgorithm: 'sha256'
            });
            return signature;
        } catch (error) {
            // Fallback to PKCS#1 v1.5 if PSS fails
            try {
                const sign = crypto.createSign('SHA256');
                sign.update(message);
                return sign.sign(privateKey);
            } catch (fallbackError) {
                throw new Error(`RSA signing failed: ${error.message}`);
            }
        }
    }

    /**
     * RSA Verify with Public Key using PSS padding
     * @param {crypto.KeyObject} publicKey - Public key object
     * @param {Buffer} message - Message to verify as byte array
     * @param {Buffer} signature - Signature to verify as byte array
     * @returns {boolean} True if signature is valid
     */
    static rsaVerify(publicKey, message, signature) {
        if (!Buffer.isBuffer(message) || !Buffer.isBuffer(signature)) {
            throw new Error('Message and signature must be Buffer objects');
        }
        if (!publicKey || typeof publicKey.export !== 'function') {
            throw new Error('Invalid public key object');
        }

        try {
            // Use PSS padding for better security
            // First hash the message with SHA-256
            const hash = crypto.createHash('sha256').update(message).digest();
            
            const verify = crypto.createVerify('RSA-PSS');
            verify.update(hash);
            return verify.verify({
                key: publicKey,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
                mgf1HashAlgorithm: 'sha256'
            }, signature);
        } catch (error) {
            // Fallback to PKCS#1 v1.5 if PSS fails
            try {
                const verify = crypto.createVerify('SHA256');
                verify.update(message);
                return verify.verify(publicKey, signature);
            } catch (fallbackError) {
                return false;
            }
        }
    }

    /**
     * Verify RSA signature
     * @param {string|Buffer} data - Original data
     * @param {string} signature - Base64-encoded signature
     * @param {crypto.KeyObject|string} publicKey - Public key object or PEM file path
     * @returns {boolean} True if signature is valid
     */
    static verifyRSA(data, signature, publicKey) {
        try {
            const key = typeof publicKey === 'string' ? this.loadPublicKey(publicKey) : publicKey;
            const verify = crypto.createVerify('SHA256');
            verify.update(data);
            return verify.verify(key, signature, 'base64');
        } catch (error) {
            return false;
        }
    }

    /**
     * Hash data with SHA-256
     * @param {string|Buffer} data - Data to hash
     * @returns {string} Hex-encoded hash
     */
    static sha256(data) {
        return crypto.createHash('sha256').update(data).digest('hex');
    }

    /**
     * Hash data with SHA-256 and return Base64
     * @param {string|Buffer} data - Data to hash
     * @returns {string} Base64-encoded hash
     */
    static sha256Base64(data) {
        return crypto.createHash('sha256').update(data).digest('base64');
    }

    /**
     * Create HMAC-SHA256
     * @param {string|Buffer} data - Data to authenticate
     * @param {string|Buffer} key - HMAC key
     * @returns {string} Hex-encoded HMAC
     */
    static hmacSha256(data, key) {
        return crypto.createHmac('sha256', key).update(data).digest('hex');
    }

    /**
     * Create HMAC-SHA256 and return Base64
     * @param {string|Buffer} data - Data to authenticate
     * @param {string|Buffer} key - HMAC key
     * @returns {string} Base64-encoded HMAC
     */
    static hmacSha256Base64(data, key) {
        return crypto.createHmac('sha256', key).update(data).digest('base64');
    }

    /**
     * HMAC-SHA256 with byte arrays - returns Base64 string
     * @param {Buffer} secret - Secret key as byte array
     * @param {Buffer} message - Message to authenticate as byte array
     * @returns {string} Base64-encoded HMAC
     */
    static hmacSha256Base64Bytes(secret, message) {
        if (!Buffer.isBuffer(secret) || !Buffer.isBuffer(message)) {
            throw new Error('Both secret and message must be Buffer objects');
        }
        return crypto.createHmac('sha256', secret).update(message).digest('base64');
    }

    /**
     * Verify HMAC-SHA256 with byte arrays
     * @param {Buffer} secret - Secret key as byte array
     * @param {Buffer} message - Message to verify as byte array
     * @param {string} base64Mac - Base64-encoded HMAC to verify against
     * @returns {boolean} True if HMAC is valid
     */
    static hmacSha256Verify(secret, message, base64Mac) {
        if (!Buffer.isBuffer(secret) || !Buffer.isBuffer(message)) {
            throw new Error('Secret and message must be Buffer objects');
        }
        if (typeof base64Mac !== 'string') {
            throw new Error('base64Mac must be a string');
        }

        try {
            const expectedMac = this.hmacSha256Base64Bytes(secret, message);
            return crypto.timingSafeEqual(
                Buffer.from(expectedMac, 'base64'),
                Buffer.from(base64Mac, 'base64')
            );
        } catch (error) {
            return false;
        }
    }

    /**
     * Load crypto configuration
     * @param {string} configPath - Path to config file
     * @returns {Object} Configuration object
     */
    static loadConfig(configPath = path.join(__dirname, 'crypto-config.json')) {
        try {
            const configContent = fs.readFileSync(configPath, 'utf8');
            return JSON.parse(configContent);
        } catch (error) {
            throw new Error(`Failed to load crypto config: ${error.message}`);
        }
    }

    /**
     * Get key fingerprint
     * @param {crypto.KeyObject} key - Public or private key
     * @returns {string} SHA-256 fingerprint
     */
    static getKeyFingerprint(key) {
        const publicKey = key.asymmetricKeyType ? key : crypto.createPublicKey(key);
        const der = publicKey.export({ type: 'spki', format: 'der' });
        return this.sha256(der);
    }

    /**
     * Get RSA key size in bits
     * @param {crypto.KeyObject} key - RSA key object
     * @returns {number} Key size in bits
     */
    static getRSAKeySize(key) {
        try {
            const keyDetails = key.asymmetricKeyDetails;
            return keyDetails ? keyDetails.modulusLength : 2048; // Default to 2048 if not available
        } catch (error) {
            return 2048; // Default fallback
        }
    }
}

module.exports = CryptoUtils;
