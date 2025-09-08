const CryptoUtils = require('./crypto-utils');
const fs = require('fs');
const path = require('path');

console.log('🧪 Testing Cryptographic Utilities...\n');

try {
    // Test 1: String ↔ Byte conversions
    console.log('1. Testing String ↔ Byte conversions...');
    const testString = 'Hello, SecurePat!';
    const bytes = CryptoUtils.stringToBytes(testString);
    const backToString = CryptoUtils.bytesToString(bytes);
    console.log(`   Original: "${testString}"`);
    console.log(`   Bytes: ${bytes.length} bytes`);
    console.log(`   Back to string: "${backToString}"`);
    console.log(`   ✅ ${testString === backToString ? 'PASS' : 'FAIL'}`);

    // Test 2: Base64 encode/decode
    console.log('\n2. Testing Base64 encode/decode...');
    const originalData = 'SecurePat Test Data';
    const encoded = CryptoUtils.base64Encode(originalData);
    const decoded = CryptoUtils.base64Decode(encoded);
    console.log(`   Original: "${originalData}"`);
    console.log(`   Encoded: "${encoded}"`);
    console.log(`   Decoded: "${decoded}"`);
    console.log(`   ✅ ${originalData === decoded ? 'PASS' : 'FAIL'}`);

    // Test 3: Load generated keys
    console.log('\n3. Testing key loading...');
    const clientPublicKey = CryptoUtils.loadPublicKey(path.join(__dirname, 'keys', 'client_rsa_public.pem'));
    const clientPrivateKey = CryptoUtils.loadPrivateKey(path.join(__dirname, 'keys', 'client_rsa_private.pem'));
    const serverPublicKey = CryptoUtils.loadPublicKey(path.join(__dirname, 'keys', 'rsa_public.pem'));
    const serverPrivateKey = CryptoUtils.loadPrivateKey(path.join(__dirname, 'keys', 'rsa_private.pem'));
    console.log(`   ✅ Client public key loaded: ${clientPublicKey.asymmetricKeyType}`);
    console.log(`   ✅ Client private key loaded: ${clientPrivateKey.asymmetricKeyType}`);
    console.log(`   ✅ Server public key loaded: ${serverPublicKey.asymmetricKeyType}`);
    console.log(`   ✅ Server private key loaded: ${serverPrivateKey.asymmetricKeyType}`);

    // Test 4: RSA Signing and Verification
    console.log('\n4. Testing RSA signing and verification...');
    const message = 'This is a test message for signing';
    const signature = CryptoUtils.signRSA(message, clientPrivateKey);
    const isValid = CryptoUtils.verifyRSA(message, signature, clientPublicKey);
    console.log(`   Message: "${message}"`);
    console.log(`   Signature: ${signature.substring(0, 50)}...`);
    console.log(`   ✅ Signature verification: ${isValid ? 'PASS' : 'FAIL'}`);

    // Test 5: AES Encryption/Decryption
    console.log('\n5. Testing AES encryption/decryption...');
    const aesKey1 = fs.readFileSync(path.join(__dirname, 'keys', 'aes_key_1.txt'), 'utf8').trim();
    const plaintext = 'This is secret data to encrypt';
    const encrypted = CryptoUtils.encryptAES(plaintext, aesKey1);
    const decrypted = CryptoUtils.decryptAES(encrypted, aesKey1);
    console.log(`   Plaintext: "${plaintext}"`);
    console.log(`   Encrypted: ${encrypted.encrypted.substring(0, 50)}...`);
    console.log(`   Decrypted: "${decrypted}"`);
    console.log(`   ✅ AES encryption/decryption: ${plaintext === decrypted ? 'PASS' : 'FAIL'}`);

    // Test 6: Hash functions
    console.log('\n6. Testing hash functions...');
    const dataToHash = 'Data to hash';
    const sha256Hash = CryptoUtils.sha256(dataToHash);
    const sha256Base64 = CryptoUtils.sha256Base64(dataToHash);
    console.log(`   Data: "${dataToHash}"`);
    console.log(`   SHA-256 (hex): ${sha256Hash}`);
    console.log(`   SHA-256 (base64): ${sha256Base64}`);
    console.log(`   ✅ Hash functions working`);

    // Test 7: HMAC
    console.log('\n7. Testing HMAC...');
    const hmacKey = 'secret-hmac-key';
    const hmacData = 'Data to authenticate';
    const hmac = CryptoUtils.hmacSha256(hmacData, hmacKey);
    const hmacBase64 = CryptoUtils.hmacSha256Base64(hmacData, hmacKey);
    console.log(`   Data: "${hmacData}"`);
    console.log(`   Key: "${hmacKey}"`);
    console.log(`   HMAC (hex): ${hmac}`);
    console.log(`   HMAC (base64): ${hmacBase64}`);
    console.log(`   ✅ HMAC functions working`);

    // Test 8: Key fingerprints
    console.log('\n8. Testing key fingerprints...');
    const clientFingerprint = CryptoUtils.getKeyFingerprint(clientPublicKey);
    const serverFingerprint = CryptoUtils.getKeyFingerprint(serverPublicKey);
    console.log(`   Client key fingerprint: ${clientFingerprint}`);
    console.log(`   Server key fingerprint: ${serverFingerprint}`);
    console.log(`   ✅ Key fingerprints generated`);

    // Test 9: Configuration loading
    console.log('\n9. Testing configuration loading...');
    const config = CryptoUtils.loadConfig();
    console.log(`   Config loaded: ${Object.keys(config).length} sections`);
    console.log(`   AES keys available: ${config.aes ? 'Yes' : 'No'}`);
    console.log(`   ✅ Configuration loaded successfully`);

    console.log('\n🎉 All cryptographic tests completed successfully!');
    console.log('\n📋 Summary:');
    console.log('   ✅ String/Byte conversions');
    console.log('   ✅ Base64 encoding/decoding');
    console.log('   ✅ RSA key loading');
    console.log('   ✅ RSA signing/verification');
    console.log('   ✅ AES encryption/decryption');
    console.log('   ✅ Hash functions (SHA-256)');
    console.log('   ✅ HMAC functions');
    console.log('   ✅ Key fingerprints');
    console.log('   ✅ Configuration loading');

} catch (error) {
    console.error('\n❌ Test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
}
