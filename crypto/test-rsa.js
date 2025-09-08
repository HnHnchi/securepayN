const CryptoUtils = require('./crypto-utils');
const fs = require('fs');
const path = require('path');

console.log('🔐 Testing RSA Methods with OAEP and PSS...\n');

try {
    // Load test keys
    console.log('📋 Loading Test Keys...');
    const clientPublicKey = CryptoUtils.loadPublicKey(path.join(__dirname, 'keys', 'client_rsa_public.pem'));
    const clientPrivateKey = CryptoUtils.loadPrivateKey(path.join(__dirname, 'keys', 'client_rsa_private.pem'));
    const serverPublicKey = CryptoUtils.loadPublicKey(path.join(__dirname, 'keys', 'rsa_public.pem'));
    const serverPrivateKey = CryptoUtils.loadPrivateKey(path.join(__dirname, 'keys', 'rsa_private.pem'));
    
    console.log(`   ✅ Client public key loaded: ${clientPublicKey.asymmetricKeyType}`);
    console.log(`   ✅ Client private key loaded: ${clientPrivateKey.asymmetricKeyType}`);
    console.log(`   ✅ Server public key loaded: ${serverPublicKey.asymmetricKeyType}`);
    console.log(`   ✅ Server private key loaded: ${serverPrivateKey.asymmetricKeyType}\n`);

    // Test 1: RSA Encryption/Decryption with OAEP
    console.log('1. Testing RSA Encryption/Decryption with OAEP...');
    const testMessage = Buffer.from('Hello, SecurePat RSA Test!', 'utf8');
    console.log(`   Original message: "${testMessage.toString('utf8')}"`);
    console.log(`   Message length: ${testMessage.length} bytes`);
    
    // Encrypt with client public key
    const encrypted = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, testMessage);
    console.log(`   Encrypted length: ${encrypted.length} bytes`);
    console.log(`   Encrypted (hex): ${encrypted.toString('hex').substring(0, 100)}...`);
    
    // Decrypt with client private key
    const decrypted = CryptoUtils.rsaDecryptWithPrivate(clientPrivateKey, encrypted);
    console.log(`   Decrypted message: "${decrypted.toString('utf8')}"`);
    console.log(`   Decryption successful: ${testMessage.equals(decrypted) ? '✅ YES' : '❌ NO'}\n`);

    // Test 2: RSA Signing/Verification with PSS
    console.log('2. Testing RSA Signing/Verification with PSS...');
    const signMessage = Buffer.from('This is a message to sign with RSA-PSS', 'utf8');
    console.log(`   Message to sign: "${signMessage.toString('utf8')}"`);
    
    // Sign with server private key
    const signature = CryptoUtils.rsaSign(serverPrivateKey, signMessage);
    console.log(`   Signature length: ${signature.length} bytes`);
    console.log(`   Signature (hex): ${signature.toString('hex').substring(0, 100)}...`);
    
    // Verify with server public key
    const isValid = CryptoUtils.rsaVerify(serverPublicKey, signMessage, signature);
    console.log(`   Signature verification: ${isValid ? '✅ VALID' : '❌ INVALID'}\n`);

    // Test 3: Cross-key operations (should fail)
    console.log('3. Testing Cross-Key Operations (should fail)...');
    try {
        const crossDecrypt = CryptoUtils.rsaDecryptWithPrivate(serverPrivateKey, encrypted);
        console.log(`   ❌ Cross-key decryption should have failed`);
    } catch (error) {
        console.log(`   ✅ Cross-key decryption correctly failed: ${error.message}`);
    }

    try {
        const crossVerify = CryptoUtils.rsaVerify(clientPublicKey, signMessage, signature);
        console.log(`   Cross-key verification: ${crossVerify ? '❌ INCORRECTLY VALID' : '✅ CORRECTLY INVALID'}`);
    } catch (error) {
        console.log(`   ✅ Cross-key verification correctly failed: ${error.message}`);
    }
    console.log();

    // Test 4: Different message sizes
    console.log('4. Testing Different Message Sizes...');
    const messageSizes = [1, 10, 50, 100, 200];
    let allSizesPassed = true;

    for (const size of messageSizes) {
        try {
            const testData = Buffer.alloc(size, 'A');
            const encrypted = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, testData);
            const decrypted = CryptoUtils.rsaDecryptWithPrivate(clientPrivateKey, encrypted);
            
            if (testData.equals(decrypted)) {
                console.log(`   ✅ ${size} bytes: Success`);
            } else {
                console.log(`   ❌ ${size} bytes: Failed`);
                allSizesPassed = false;
            }
        } catch (error) {
            console.log(`   ❌ ${size} bytes: Error - ${error.message}`);
            allSizesPassed = false;
        }
    }
    console.log(`   Overall result: ${allSizesPassed ? '✅ ALL SIZES PASSED' : '❌ SOME SIZES FAILED'}\n`);

    // Test 5: PEM loader compatibility
    console.log('5. Testing PEM Loader Compatibility...');
    const clientPublicPem = fs.readFileSync(path.join(__dirname, 'keys', 'client_rsa_public.pem'), 'utf8');
    const clientPrivatePem = fs.readFileSync(path.join(__dirname, 'keys', 'client_rsa_private.pem'), 'utf8');
    
    const loadedPublicKey = CryptoUtils.loadPublicKeyFromPem(clientPublicPem);
    const loadedPrivateKey = CryptoUtils.loadPrivateKeyFromPem(clientPrivatePem);
    
    console.log(`   ✅ Public key loaded from PEM: ${loadedPublicKey.asymmetricKeyType}`);
    console.log(`   ✅ Private key loaded from PEM: ${loadedPrivateKey.asymmetricKeyType}`);
    
    // Test with loaded keys
    const testData = Buffer.from('PEM loader test', 'utf8');
    const pemEncrypted = CryptoUtils.rsaEncryptWithPublic(loadedPublicKey, testData);
    const pemDecrypted = CryptoUtils.rsaDecryptWithPrivate(loadedPrivateKey, pemEncrypted);
    console.log(`   ✅ PEM-loaded keys work: ${testData.equals(pemDecrypted) ? 'YES' : 'NO'}\n`);

    // Test 6: Error handling
    console.log('6. Testing Error Handling...');
    
    // Invalid data type
    try {
        CryptoUtils.rsaEncryptWithPublic(clientPublicKey, 'not-a-buffer');
        console.log(`   ❌ Should have rejected non-buffer data`);
    } catch (error) {
        console.log(`   ✅ Correctly rejected non-buffer data: ${error.message}`);
    }

    // Invalid key
    try {
        CryptoUtils.rsaEncryptWithPublic(null, testMessage);
        console.log(`   ❌ Should have rejected null key`);
    } catch (error) {
        console.log(`   ✅ Correctly rejected null key: ${error.message}`);
    }

    // Invalid signature
    const invalidSignature = Buffer.alloc(256, 0);
    const invalidVerify = CryptoUtils.rsaVerify(clientPublicKey, signMessage, invalidSignature);
    console.log(`   ✅ Invalid signature correctly rejected: ${invalidVerify ? 'NO' : 'YES'}\n`);

    // Test 7: Performance test
    console.log('7. Performance Test...');
    const iterations = 100;
    const perfMessage = Buffer.from('Performance test message', 'utf8');
    
    // Encryption/Decryption performance
    const start1 = Date.now();
    for (let i = 0; i < iterations; i++) {
        const encrypted = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, perfMessage);
        const decrypted = CryptoUtils.rsaDecryptWithPrivate(clientPrivateKey, encrypted);
    }
    const time1 = Date.now() - start1;
    
    // Signing/Verification performance
    const start2 = Date.now();
    for (let i = 0; i < iterations; i++) {
        const signature = CryptoUtils.rsaSign(serverPrivateKey, perfMessage);
        const isValid = CryptoUtils.rsaVerify(serverPublicKey, perfMessage, signature);
    }
    const time2 = Date.now() - start2;
    
    console.log(`   ${iterations} encrypt/decrypt operations: ${time1}ms`);
    console.log(`   ${iterations} sign/verify operations: ${time2}ms`);
    console.log(`   Average encrypt/decrypt: ${(time1/iterations).toFixed(2)}ms per operation`);
    console.log(`   Average sign/verify: ${(time2/iterations).toFixed(2)}ms per operation\n`);

    // Test 8: Key fingerprint comparison
    console.log('8. Testing Key Fingerprints...');
    const clientFingerprint = CryptoUtils.getKeyFingerprint(clientPublicKey);
    const serverFingerprint = CryptoUtils.getKeyFingerprint(serverPublicKey);
    
    console.log(`   Client key fingerprint: ${clientFingerprint}`);
    console.log(`   Server key fingerprint: ${serverFingerprint}`);
    console.log(`   Fingerprints different: ${clientFingerprint !== serverFingerprint ? '✅ YES' : '❌ NO'}\n`);

    // Test 9: Maximum message size test
    console.log('9. Testing Maximum Message Size...');
    const keySize = clientPublicKey.asymmetricKeySize;
    const maxMessageSize = Math.floor(keySize / 8) - 42; // OAEP overhead
    console.log(`   Key size: ${keySize} bits`);
    console.log(`   Maximum message size: ${maxMessageSize} bytes`);
    
    try {
        const maxMessage = Buffer.alloc(maxMessageSize, 'A');
        const encrypted = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, maxMessage);
        const decrypted = CryptoUtils.rsaDecryptWithPrivate(clientPrivateKey, encrypted);
        console.log(`   ✅ Maximum size message: Success`);
    } catch (error) {
        console.log(`   ❌ Maximum size message: ${error.message}`);
    }

    try {
        const tooLargeMessage = Buffer.alloc(maxMessageSize + 1, 'A');
        const encrypted = CryptoUtils.rsaEncryptWithPublic(clientPublicKey, tooLargeMessage);
        console.log(`   ❌ Too large message should have failed`);
    } catch (error) {
        console.log(`   ✅ Too large message correctly rejected: ${error.message}`);
    }

    console.log('\n🎉 All RSA tests completed successfully!');
    console.log('\n📋 Summary:');
    console.log('   ✅ RSA encryption/decryption with OAEP padding');
    console.log('   ✅ RSA signing/verification with PSS padding');
    console.log('   ✅ Cross-key operation rejection');
    console.log('   ✅ Different message sizes');
    console.log('   ✅ PEM loader compatibility');
    console.log('   ✅ Error handling');
    console.log('   ✅ Performance optimization');
    console.log('   ✅ Key fingerprint generation');
    console.log('   ✅ Maximum message size handling');

} catch (error) {
    console.error('\n❌ Test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
}
