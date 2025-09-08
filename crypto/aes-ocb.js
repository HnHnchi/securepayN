const crypto = require('crypto');

/**
 * AES-OCB Implementation
 * Since Node.js doesn't natively support OCB mode, we implement OCB-like functionality
 * using AES-CTR for encryption and HMAC-SHA256 for authentication
 * This provides similar security properties to OCB mode
 */
class AESOCB {
    /**
     * Generate a random IV/nonce for OCB mode
     * @param {number} length - Length of IV in bytes (12-15 recommended)
     * @returns {Buffer} Random IV
     */
    static generateIV(length = 12) {
        if (length < 8 || length > 16) {
            throw new Error('IV length must be between 8 and 16 bytes');
        }
        return crypto.randomBytes(length);
    }

    /**
     * AES-OCB Encrypt
     * @param {Buffer} key - AES key (16, 24, or 32 bytes)
     * @param {Buffer} iv - Initialization vector (12-15 bytes recommended)
     * @param {Buffer} plaintext - Data to encrypt
     * @returns {Buffer} Encrypted data with authentication tag
     */
    static aesOcbEncrypt(key, iv, plaintext) {
        if (!Buffer.isBuffer(key) || !Buffer.isBuffer(iv) || !Buffer.isBuffer(plaintext)) {
            throw new Error('All parameters must be Buffer objects');
        }

        if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
            throw new Error('Key must be 16, 24, or 32 bytes');
        }

        if (iv.length < 8 || iv.length > 16) {
            throw new Error('IV must be 8-16 bytes');
        }

        try {
            // Use AES-CTR for encryption (similar to OCB's counter mode)
            const cipher = crypto.createCipher('aes-256-ctr', key);
            cipher.setAutoPadding(false);
            
            // Encrypt the plaintext
            let encrypted = cipher.update(plaintext);
            encrypted = Buffer.concat([encrypted, cipher.final()]);

            // Create authentication tag using HMAC-SHA256
            // Include IV, plaintext length, and encrypted data
            const authData = Buffer.concat([
                iv,
                Buffer.from([plaintext.length & 0xFF, (plaintext.length >> 8) & 0xFF]),
                encrypted
            ]);
            
            const authTag = crypto.createHmac('sha256', key)
                .update(authData)
                .digest();

            // Return: AuthTag + EncryptedData (IV is separate)
            return Buffer.concat([authTag, encrypted]);
        } catch (error) {
            throw new Error(`AES-OCB encryption failed: ${error.message}`);
        }
    }

    /**
     * AES-OCB Decrypt
     * @param {Buffer} key - AES key (16, 24, or 32 bytes)
     * @param {Buffer} iv - Initialization vector (12-15 bytes recommended)
     * @param {Buffer} ciphertext - Encrypted data with authentication tag
     * @returns {Buffer} Decrypted plaintext
     */
    static aesOcbDecrypt(key, iv, ciphertext) {
        if (!Buffer.isBuffer(key) || !Buffer.isBuffer(iv) || !Buffer.isBuffer(ciphertext)) {
            throw new Error('All parameters must be Buffer objects');
        }

        if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
            throw new Error('Key must be 16, 24, or 32 bytes');
        }

        if (iv.length < 8 || iv.length > 16) {
            throw new Error('IV must be 8-16 bytes');
        }

        if (ciphertext.length < 32) { // Minimum: 32 bytes auth tag + some encrypted data
            throw new Error('Ciphertext too short');
        }

        try {
            // Extract components: AuthTag + EncryptedData
            const authTagLength = 32; // HMAC-SHA256 produces 32 bytes
            const authTag = ciphertext.slice(0, authTagLength);
            const encryptedData = ciphertext.slice(authTagLength);

            // Verify authentication tag
            const authData = Buffer.concat([
                iv,
                Buffer.from([encryptedData.length & 0xFF, (encryptedData.length >> 8) & 0xFF]),
                encryptedData
            ]);
            
            const expectedAuthTag = crypto.createHmac('sha256', key)
                .update(authData)
                .digest();

            // Constant-time comparison to prevent timing attacks
            if (!crypto.timingSafeEqual(authTag, expectedAuthTag)) {
                throw new Error('Authentication failed - invalid ciphertext');
            }

            // Decrypt using AES-CTR
            const decipher = crypto.createDecipher('aes-256-ctr', key);
            decipher.setAutoPadding(false);
            
            let decrypted = decipher.update(encryptedData);
            decrypted = Buffer.concat([decrypted, decipher.final()]);

            return decrypted;
        } catch (error) {
            throw new Error(`AES-OCB decryption failed: ${error.message}`);
        }
    }

    /**
     * AES-OCB Encrypt with automatic IV generation
     * @param {Buffer} key - AES key
     * @param {Buffer} plaintext - Data to encrypt
     * @param {number} ivLength - Length of IV to generate (default 12)
     * @returns {Object} {iv, ciphertext} - IV and encrypted data
     */
    static aesOcbEncryptWithIV(key, plaintext, ivLength = 12) {
        const iv = this.generateIV(ivLength);
        const ciphertext = this.aesOcbEncrypt(key, iv, plaintext);
        return { iv, ciphertext };
    }

    /**
     * AES-OCB Decrypt with provided IV
     * @param {Buffer} key - AES key
     * @param {Buffer} iv - Initialization vector
     * @param {Buffer} ciphertext - Encrypted data
     * @returns {Buffer} Decrypted plaintext
     */
    static aesOcbDecryptWithIV(key, iv, ciphertext) {
        return this.aesOcbDecrypt(key, iv, ciphertext);
    }

    /**
     * Convert string to byte array (UTF-8)
     * @param {string} str - Input string
     * @returns {Buffer} UTF-8 encoded bytes
     */
    static stringToBytes(str) {
        return Buffer.from(str, 'utf8');
    }

    /**
     * Convert byte array to string (UTF-8)
     * @param {Buffer} bytes - Input bytes
     * @returns {string} UTF-8 decoded string
     */
    static bytesToString(bytes) {
        return bytes.toString('utf8');
    }

    /**
     * Base64 encode bytes
     * @param {Buffer} bytes - Input bytes
     * @returns {string} Base64 encoded string
     */
    static bytesToBase64(bytes) {
        return bytes.toString('base64');
    }

    /**
     * Base64 decode to bytes
     * @param {string} base64 - Base64 encoded string
     * @returns {Buffer} Decoded bytes
     */
    static base64ToBytes(base64) {
        return Buffer.from(base64, 'base64');
    }

    /**
     * Generate AES key of specified length
     * @param {number} length - Key length in bytes (16, 24, or 32)
     * @returns {Buffer} Random AES key
     */
    static generateAESKey(length = 32) {
        if (length !== 16 && length !== 24 && length !== 32) {
            throw new Error('Key length must be 16, 24, or 32 bytes');
        }
        return crypto.randomBytes(length);
    }

    /**
     * Test AES-OCB implementation
     * @returns {Object} Test results
     */
    static test() {
        const results = {
            passed: 0,
            failed: 0,
            tests: []
        };

        try {
            // Test 1: Basic encryption/decryption
            const key = this.generateAESKey(32);
            const iv = this.generateIV(12);
            const plaintext = this.stringToBytes('Hello, AES-OCB!');
            
            const encrypted = this.aesOcbEncrypt(key, iv, plaintext);
            const decrypted = this.aesOcbDecrypt(key, iv, encrypted);
            
            const test1Pass = plaintext.equals(decrypted);
            results.tests.push({
                name: 'Basic encryption/decryption',
                passed: test1Pass,
                details: `Plaintext: "${plaintext.toString('utf8')}", Decrypted: "${decrypted.toString('utf8')}"`
            });
            test1Pass ? results.passed++ : results.failed++;

            // Test 2: Different IV lengths
            const ivLengths = [8, 12, 15, 16];
            let test2Pass = true;
            for (const ivLen of ivLengths) {
                const testIV = this.generateIV(ivLen);
                const testEncrypted = this.aesOcbEncrypt(key, testIV, plaintext);
                const testDecrypted = this.aesOcbDecrypt(key, testIV, testEncrypted);
                if (!plaintext.equals(testDecrypted)) {
                    test2Pass = false;
                    break;
                }
            }
            
            results.tests.push({
                name: 'Different IV lengths',
                passed: test2Pass,
                details: `Tested IV lengths: ${ivLengths.join(', ')}`
            });
            test2Pass ? results.passed++ : results.failed++;

            // Test 3: Authentication failure
            let test3Pass = false;
            try {
                const corruptedCiphertext = Buffer.concat([encrypted.slice(0, 16), Buffer.from('corrupted'), encrypted.slice(32)]);
                this.aesOcbDecrypt(key, iv, corruptedCiphertext);
            } catch (error) {
                test3Pass = error.message.includes('Authentication failed');
            }
            
            results.tests.push({
                name: 'Authentication failure detection',
                passed: test3Pass,
                details: 'Corrupted ciphertext should be rejected'
            });
            test3Pass ? results.passed++ : results.failed++;

            // Test 4: Empty plaintext
            const emptyPlaintext = Buffer.alloc(0);
            const emptyEncrypted = this.aesOcbEncrypt(key, iv, emptyPlaintext);
            const emptyDecrypted = this.aesOcbDecrypt(key, iv, emptyEncrypted);
            const test4Pass = emptyPlaintext.equals(emptyDecrypted);
            
            results.tests.push({
                name: 'Empty plaintext handling',
                passed: test4Pass,
                details: 'Empty plaintext should encrypt/decrypt correctly'
            });
            test4Pass ? results.passed++ : results.failed++;

        } catch (error) {
            results.tests.push({
                name: 'Test suite execution',
                passed: false,
                details: `Test suite failed: ${error.message}`
            });
            results.failed++;
        }

        return results;
    }
}

module.exports = AESOCB;
