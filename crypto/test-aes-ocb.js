const AESOCB = require('./aes-ocb');

console.log('🔐 Testing AES-OCB Implementation...\n');

// Run comprehensive tests
const testResults = AESOCB.test();

console.log('📊 Test Results:');
console.log(`   ✅ Passed: ${testResults.passed}`);
console.log(`   ❌ Failed: ${testResults.failed}`);
console.log(`   📈 Success Rate: ${((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1)}%\n`);

console.log('📋 Detailed Results:');
testResults.tests.forEach((test, index) => {
    console.log(`   ${index + 1}. ${test.name}: ${test.passed ? '✅ PASS' : '❌ FAIL'}`);
    console.log(`      ${test.details}\n`);
});

// Additional demonstration
console.log('🎯 AES-OCB Demonstration:\n');

try {
    // Generate test data
    const key = AESOCB.generateAESKey(32);
    const plaintext = AESOCB.stringToBytes('SecurePat AES-OCB Test Data');
    
    console.log('1. Encryption Process:');
    console.log(`   Key: ${AESOCB.bytesToBase64(key)}`);
    console.log(`   Plaintext: "${plaintext.toString('utf8')}"`);
    console.log(`   Plaintext (hex): ${plaintext.toString('hex')}`);
    
    // Encrypt with automatic IV generation
    const { iv, ciphertext } = AESOCB.aesOcbEncryptWithIV(key, plaintext, 12);
    console.log(`   IV: ${AESOCB.bytesToBase64(iv)}`);
    console.log(`   Ciphertext: ${AESOCB.bytesToBase64(ciphertext)}`);
    console.log(`   Ciphertext length: ${ciphertext.length} bytes`);
    
    console.log('\n2. Decryption Process:');
    const decrypted = AESOCB.aesOcbDecryptWithIV(key, iv, ciphertext);
    console.log(`   Decrypted: "${decrypted.toString('utf8')}"`);
    console.log(`   Decrypted (hex): ${decrypted.toString('hex')}`);
    console.log(`   Match: ${plaintext.equals(decrypted) ? '✅ YES' : '❌ NO'}`);
    
    console.log('\n3. Base64 API Usage:');
    const base64Key = AESOCB.bytesToBase64(key);
    const base64Plaintext = AESOCB.bytesToBase64(plaintext);
    const base64IV = AESOCB.bytesToBase64(iv);
    const base64Ciphertext = AESOCB.bytesToBase64(ciphertext);
    
    console.log(`   Base64 Key: ${base64Key}`);
    console.log(`   Base64 Plaintext: ${base64Plaintext}`);
    console.log(`   Base64 IV: ${base64IV}`);
    console.log(`   Base64 Ciphertext: ${base64Ciphertext}`);
    
    // Convert back and test
    const keyFromBase64 = AESOCB.base64ToBytes(base64Key);
    const plaintextFromBase64 = AESOCB.base64ToBytes(base64Plaintext);
    const ivFromBase64 = AESOCB.base64ToBytes(base64IV);
    const ciphertextFromBase64 = AESOCB.base64ToBytes(base64Ciphertext);
    
    const decryptedFromBase64 = AESOCB.aesOcbDecryptWithIV(keyFromBase64, ivFromBase64, ciphertextFromBase64);
    console.log(`   Decrypted from Base64: "${decryptedFromBase64.toString('utf8')}"`);
    console.log(`   Base64 round-trip match: ${plaintext.equals(decryptedFromBase64) ? '✅ YES' : '❌ NO'}`);
    
    console.log('\n4. Performance Test:');
    const iterations = 1000;
    const startTime = Date.now();
    
    for (let i = 0; i < iterations; i++) {
        const testKey = AESOCB.generateAESKey(32);
        const testIV = AESOCB.generateIV(12);
        const testData = AESOCB.stringToBytes(`Test data ${i}`);
        const encrypted = AESOCB.aesOcbEncrypt(testKey, testIV, testData);
        const decrypted = AESOCB.aesOcbDecrypt(testKey, testIV, encrypted);
    }
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    const opsPerSecond = Math.round((iterations * 2) / (duration / 1000)); // 2 operations per iteration (encrypt + decrypt)
    
    console.log(`   ${iterations} encrypt/decrypt operations in ${duration}ms`);
    console.log(`   Performance: ${opsPerSecond} operations/second`);
    
    console.log('\n🎉 AES-OCB Implementation Test Complete!');
    
    if (testResults.failed === 0) {
        console.log('✅ All tests passed! The implementation is ready for use.');
    } else {
        console.log('❌ Some tests failed. Please review the implementation.');
        process.exit(1);
    }
    
} catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
}
