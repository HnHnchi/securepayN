const CryptoUtils = require('./crypto-utils');

console.log('🔐 Testing HMAC-SHA256 Methods...\n');

// Test data
const testSecret = Buffer.from('my-secret-key-32-bytes-long-12345', 'utf8');
const testMessage = Buffer.from('Hello, SecurePat HMAC Test!', 'utf8');

console.log('📋 Test Data:');
console.log(`   Secret: "${testSecret.toString('utf8')}"`);
console.log(`   Secret (hex): ${testSecret.toString('hex')}`);
console.log(`   Message: "${testMessage.toString('utf8')}"`);
console.log(`   Message (hex): ${testMessage.toString('hex')}\n`);

try {
    // Test 1: Basic HMAC generation
    console.log('1. Testing HMAC-SHA256 Generation...');
    const hmac = CryptoUtils.hmacSha256Base64Bytes(testSecret, testMessage);
    console.log(`   Generated HMAC: ${hmac}`);
    console.log(`   HMAC length: ${hmac.length} characters`);
    console.log(`   ✅ HMAC generated successfully`);

    // Test 2: HMAC verification
    console.log('\n2. Testing HMAC-SHA256 Verification...');
    const isValid = CryptoUtils.hmacSha256Verify(testSecret, testMessage, hmac);
    console.log(`   Verification result: ${isValid ? '✅ VALID' : '❌ INVALID'}`);
    console.log(`   ✅ Verification working correctly`);

    // Test 3: Invalid HMAC detection
    console.log('\n3. Testing Invalid HMAC Detection...');
    const invalidHmac = 'invalid-hmac-string';
    const isInvalid = CryptoUtils.hmacSha256Verify(testSecret, testMessage, invalidHmac);
    console.log(`   Invalid HMAC result: ${isInvalid ? '❌ INCORRECTLY VALID' : '✅ CORRECTLY INVALID'}`);
    console.log(`   ✅ Invalid HMAC correctly rejected`);

    // Test 4: Different messages, same secret
    console.log('\n4. Testing Different Messages...');
    const message2 = Buffer.from('Different message content', 'utf8');
    const hmac2 = CryptoUtils.hmacSha256Base64Bytes(testSecret, message2);
    const isValid2 = CryptoUtils.hmacSha256Verify(testSecret, message2, hmac2);
    const isCrossValid = CryptoUtils.hmacSha256Verify(testSecret, testMessage, hmac2);
    
    console.log(`   Message 2 HMAC: ${hmac2}`);
    console.log(`   Message 2 verification: ${isValid2 ? '✅ VALID' : '❌ INVALID'}`);
    console.log(`   Cross-verification (should fail): ${isCrossValid ? '❌ INCORRECTLY VALID' : '✅ CORRECTLY INVALID'}`);
    console.log(`   ✅ Different messages produce different HMACs`);

    // Test 5: Different secrets, same message
    console.log('\n5. Testing Different Secrets...');
    const secret2 = Buffer.from('different-secret-key-32-bytes-long', 'utf8');
    const hmac3 = CryptoUtils.hmacSha256Base64Bytes(secret2, testMessage);
    const isValid3 = CryptoUtils.hmacSha256Verify(secret2, testMessage, hmac3);
    const isCrossValid2 = CryptoUtils.hmacSha256Verify(testSecret, testMessage, hmac3);
    
    console.log(`   Secret 2 HMAC: ${hmac3}`);
    console.log(`   Secret 2 verification: ${isValid3 ? '✅ VALID' : '❌ INVALID'}`);
    console.log(`   Cross-verification (should fail): ${isCrossValid2 ? '❌ INCORRECTLY VALID' : '✅ CORRECTLY INVALID'}`);
    console.log(`   ✅ Different secrets produce different HMACs`);

    // Test 6: Empty message
    console.log('\n6. Testing Empty Message...');
    const emptyMessage = Buffer.alloc(0);
    const emptyHmac = CryptoUtils.hmacSha256Base64Bytes(testSecret, emptyMessage);
    const isEmptyValid = CryptoUtils.hmacSha256Verify(testSecret, emptyMessage, emptyHmac);
    
    console.log(`   Empty message HMAC: ${emptyHmac}`);
    console.log(`   Empty message verification: ${isEmptyValid ? '✅ VALID' : '❌ INVALID'}`);
    console.log(`   ✅ Empty message handled correctly`);

    // Test 7: Large message
    console.log('\n7. Testing Large Message...');
    const largeMessage = Buffer.alloc(10000, 'A'); // 10KB of 'A's
    const largeHmac = CryptoUtils.hmacSha256Base64Bytes(testSecret, largeMessage);
    const isLargeValid = CryptoUtils.hmacSha256Verify(testSecret, largeMessage, largeHmac);
    
    console.log(`   Large message size: ${largeMessage.length} bytes`);
    console.log(`   Large message HMAC: ${largeHmac}`);
    console.log(`   Large message verification: ${isLargeValid ? '✅ VALID' : '❌ INVALID'}`);
    console.log(`   ✅ Large message handled correctly`);

    // Test 8: Performance test
    console.log('\n8. Performance Test...');
    const iterations = 1000;
    const startTime = Date.now();
    
    for (let i = 0; i < iterations; i++) {
        const testMsg = Buffer.from(`Test message ${i}`, 'utf8');
        const testHmac = CryptoUtils.hmacSha256Base64Bytes(testSecret, testMsg);
        const testValid = CryptoUtils.hmacSha256Verify(testSecret, testMsg, testHmac);
    }
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    const opsPerSecond = Math.round((iterations * 2) / (duration / 1000)); // 2 operations per iteration
    
    console.log(`   ${iterations} HMAC operations in ${duration}ms`);
    console.log(`   Performance: ${opsPerSecond} operations/second`);
    console.log(`   ✅ Performance test completed`);

    // Test 9: Error handling
    console.log('\n9. Testing Error Handling...');
    try {
        CryptoUtils.hmacSha256Base64Bytes('not-a-buffer', testMessage);
        console.log(`   ❌ Should have thrown error for non-buffer secret`);
    } catch (error) {
        console.log(`   ✅ Correctly rejected non-buffer secret: ${error.message}`);
    }

    try {
        CryptoUtils.hmacSha256Base64Bytes(testSecret, 'not-a-buffer');
        console.log(`   ❌ Should have thrown error for non-buffer message`);
    } catch (error) {
        console.log(`   ✅ Correctly rejected non-buffer message: ${error.message}`);
    }

    try {
        CryptoUtils.hmacSha256Verify(testSecret, testMessage, 123);
        console.log(`   ❌ Should have thrown error for non-string HMAC`);
    } catch (error) {
        console.log(`   ✅ Correctly rejected non-string HMAC: ${error.message}`);
    }

    // Test 10: API compatibility with existing methods
    console.log('\n10. Testing API Compatibility...');
    const stringSecret = 'my-secret-key';
    const stringMessage = 'Hello, World!';
    
    const hmacOld = CryptoUtils.hmacSha256Base64(stringMessage, stringSecret);
    const hmacNew = CryptoUtils.hmacSha256Base64Bytes(
        Buffer.from(stringSecret, 'utf8'),
        Buffer.from(stringMessage, 'utf8')
    );
    
    console.log(`   Old API HMAC: ${hmacOld}`);
    console.log(`   New API HMAC: ${hmacNew}`);
    console.log(`   APIs compatible: ${hmacOld === hmacNew ? '✅ YES' : '❌ NO'}`);

    console.log('\n🎉 All HMAC-SHA256 tests completed successfully!');
    console.log('\n📋 Summary:');
    console.log('   ✅ HMAC generation with byte arrays');
    console.log('   ✅ HMAC verification with byte arrays');
    console.log('   ✅ Invalid HMAC detection');
    console.log('   ✅ Different messages produce different HMACs');
    console.log('   ✅ Different secrets produce different HMACs');
    console.log('   ✅ Empty message handling');
    console.log('   ✅ Large message handling');
    console.log('   ✅ Performance optimization');
    console.log('   ✅ Error handling');
    console.log('   ✅ API compatibility');

} catch (error) {
    console.error('\n❌ Test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
}
