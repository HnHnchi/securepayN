const CryptoUtils = require('./crypto-utils');
const fs = require('fs');
const path = require('path');

console.log('🔐 RSA Methods Usage Examples...\n');

try {
    // Load test keys
    const clientPublicKey = CryptoUtils.loadPublicKey(path.join(__dirname, 'keys', 'client_rsa_public.pem'));
    const clientPrivateKey = CryptoUtils.loadPrivateKey(path.join(__dirname, 'keys', 'client_rsa_private.pem'));
    const serverPublicKey = CryptoUtils.loadPublicKey(path.join(__dirname, 'keys', 'rsa_public.pem'));
    const serverPrivateKey = CryptoUtils.loadPrivateKey(path.join(__dirname, 'keys', 'rsa_private.pem'));

    console.log('📋 Example 1: Basic RSA Encryption/Decryption');
    const message = Buffer.from('Hello, SecurePat RSA!', 'utf8');
    console.log(`   Original: "${message.toString('utf8')}"`);
    
    // Encrypt with public key
    const encrypted = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, message);
    console.log(`   Encrypted: ${encrypted.length} bytes`);
    console.log(`   Encrypted (hex): ${encrypted.toString('hex').substring(0, 50)}...`);
    
    // Decrypt with private key
    const decrypted = CryptoUtils.rsaDecryptWithPrivate(clientPrivateKey, encrypted);
    console.log(`   Decrypted: "${decrypted.toString('utf8')}"`);
    console.log(`   Success: ${message.equals(decrypted) ? '✅ YES' : '❌ NO'}\n`);

    console.log('📋 Example 2: RSA Digital Signatures');
    const document = Buffer.from('Important document content', 'utf8');
    console.log(`   Document: "${document.toString('utf8')}"`);
    
    // Sign with private key
    const signature = CryptoUtils.rsaSign(serverPrivateKey, document);
    console.log(`   Signature: ${signature.length} bytes`);
    console.log(`   Signature (hex): ${signature.toString('hex').substring(0, 50)}...`);
    
    // Verify with public key
    const isValid = CryptoUtils.rsaVerify(serverPublicKey, document, signature);
    console.log(`   Verification: ${isValid ? '✅ VALID' : '❌ INVALID'}\n`);

    console.log('📋 Example 3: Secure Message Exchange');
    const senderMessage = Buffer.from('Confidential message from Alice to Bob', 'utf8');
    console.log(`   Sender message: "${senderMessage.toString('utf8')}"`);
    
    // Alice encrypts with Bob's public key
    const encryptedMessage = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, senderMessage);
    console.log(`   Encrypted message: ${encryptedMessage.length} bytes`);
    
    // Alice signs with her private key
    const messageSignature = CryptoUtils.rsaSign(serverPrivateKey, encryptedMessage);
    console.log(`   Message signature: ${messageSignature.length} bytes`);
    
    // Bob verifies Alice's signature
    const signatureValid = CryptoUtils.rsaVerify(serverPublicKey, encryptedMessage, messageSignature);
    console.log(`   Signature verification: ${signatureValid ? '✅ VALID' : '❌ INVALID'}`);
    
    // Bob decrypts with his private key
    const decryptedMessage = CryptoUtils.rsaDecryptWithPrivate(clientPrivateKey, encryptedMessage);
    console.log(`   Decrypted message: "${decryptedMessage.toString('utf8')}"`);
    console.log(`   Message integrity: ${senderMessage.equals(decryptedMessage) ? '✅ INTACT' : '❌ CORRUPTED'}\n`);

    console.log('📋 Example 4: PEM Key Loading');
    const publicKeyPem = fs.readFileSync(path.join(__dirname, 'keys', 'client_rsa_public.pem'), 'utf8');
    const privateKeyPem = fs.readFileSync(path.join(__dirname, 'keys', 'client_rsa_private.pem'), 'utf8');
    
    const loadedPublicKey = CryptoUtils.loadPublicKeyFromPem(publicKeyPem);
    const loadedPrivateKey = CryptoUtils.loadPrivateKeyFromPem(privateKeyPem);
    
    console.log(`   Public key type: ${loadedPublicKey.asymmetricKeyType}`);
    console.log(`   Private key type: ${loadedPrivateKey.asymmetricKeyType}`);
    
    // Test with loaded keys
    const testData = Buffer.from('PEM loading test', 'utf8');
    const testEncrypted = CryptoUtils.rsaEncryptWithPublic(loadedPublicKey, testData);
    const testDecrypted = CryptoUtils.rsaDecryptWithPrivate(loadedPrivateKey, testEncrypted);
    console.log(`   PEM loading test: ${testData.equals(testDecrypted) ? '✅ SUCCESS' : '❌ FAILED'}\n`);

    console.log('📋 Example 5: Key Fingerprints');
    const clientFingerprint = CryptoUtils.getKeyFingerprint(clientPublicKey);
    const serverFingerprint = CryptoUtils.getKeyFingerprint(serverPublicKey);
    
    console.log(`   Client key fingerprint: ${clientFingerprint}`);
    console.log(`   Server key fingerprint: ${serverFingerprint}`);
    console.log(`   Keys are different: ${clientFingerprint !== serverFingerprint ? '✅ YES' : '❌ NO'}\n`);

    console.log('📋 Example 6: Maximum Message Size');
    const keySize = CryptoUtils.getRSAKeySize(clientPublicKey);
    const maxMessageSize = Math.floor(keySize / 8) - 66; // OAEP overhead (2 * hash_size + 2)
    console.log(`   Key size: ${keySize} bits`);
    console.log(`   Maximum message size: ${maxMessageSize} bytes`);
    
    // Test maximum size
    try {
        const maxMessage = Buffer.alloc(maxMessageSize, 'A');
        const maxEncrypted = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, maxMessage);
        const maxDecrypted = CryptoUtils.rsaDecryptWithPrivate(clientPrivateKey, maxEncrypted);
        console.log(`   Maximum size test: ${maxMessage.equals(maxDecrypted) ? '✅ SUCCESS' : '❌ FAILED'}`);
    } catch (error) {
        console.log(`   Maximum size test: ❌ FAILED - ${error.message}`);
    }
    console.log();

    console.log('📋 Example 7: Error Handling');
    
    // Test invalid data
    try {
        CryptoUtils.rsaEncryptWithPublic(clientPublicKey, 'not-a-buffer');
        console.log(`   ❌ Should have rejected non-buffer data`);
    } catch (error) {
        console.log(`   ✅ Correctly rejected non-buffer data: ${error.message}`);
    }
    
    // Test invalid key
    try {
        CryptoUtils.rsaEncryptWithPublic(null, Buffer.from('test'));
        console.log(`   ❌ Should have rejected null key`);
    } catch (error) {
        console.log(`   ✅ Correctly rejected null key: ${error.message}`);
    }
    
    // Test invalid signature
    const invalidSignature = Buffer.alloc(256, 0);
    const invalidVerify = CryptoUtils.rsaVerify(clientPublicKey, Buffer.from('test'), invalidSignature);
    console.log(`   ✅ Invalid signature correctly rejected: ${invalidVerify ? 'NO' : 'YES'}\n`);

    console.log('📋 Example 8: Performance Comparison');
    const perfMessage = Buffer.from('Performance test message', 'utf8');
    const iterations = 50;
    
    // OAEP encryption/decryption
    const start1 = Date.now();
    for (let i = 0; i < iterations; i++) {
        const encrypted = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, perfMessage);
        const decrypted = CryptoUtils.rsaDecryptWithPrivate(clientPrivateKey, encrypted);
    }
    const time1 = Date.now() - start1;
    
    // PSS signing/verification
    const start2 = Date.now();
    for (let i = 0; i < iterations; i++) {
        const signature = CryptoUtils.rsaSign(serverPrivateKey, perfMessage);
        const isValid = CryptoUtils.rsaVerify(serverPublicKey, perfMessage, signature);
    }
    const time2 = Date.now() - start2;
    
    console.log(`   ${iterations} OAEP encrypt/decrypt operations: ${time1}ms`);
    console.log(`   ${iterations} PSS sign/verify operations: ${time2}ms`);
    console.log(`   Average OAEP: ${(time1/iterations).toFixed(2)}ms per operation`);
    console.log(`   Average PSS: ${(time2/iterations).toFixed(2)}ms per operation\n`);

    console.log('🎉 RSA Examples Complete!');
    console.log('\n📚 Usage Summary:');
    console.log('   • Use rsaEncryptWithPublic(publicKey, data) for encryption');
    console.log('   • Use rsaDecryptWithPrivate(privateKey, data) for decryption');
    console.log('   • Use rsaSign(privateKey, message) for signing');
    console.log('   • Use rsaVerify(publicKey, message, signature) for verification');
    console.log('   • All methods work with Buffer objects (byte arrays)');
    console.log('   • OAEP padding for encryption (better security)');
    console.log('   • PSS padding for signatures (better security)');
    console.log('   • PEM loaders support both PKCS#1 and PKCS#8 formats');
    console.log('   • Comprehensive error handling and validation');

} catch (error) {
    console.error('❌ Example failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
}
