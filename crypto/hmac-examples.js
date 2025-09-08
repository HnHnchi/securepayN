const CryptoUtils = require('./crypto-utils');

console.log('🔐 HMAC-SHA256 Usage Examples...\n');

// Example 1: Basic HMAC generation and verification
console.log('📋 Example 1: Basic HMAC Operations');
const secret = Buffer.from('my-secret-key-32-bytes-long-12345', 'utf8');
const message = Buffer.from('Hello, SecurePat!', 'utf8');

// Generate HMAC
const hmac = CryptoUtils.hmacSha256Base64Bytes(secret, message);
console.log(`   Secret: "${secret.toString('utf8')}"`);
console.log(`   Message: "${message.toString('utf8')}"`);
console.log(`   HMAC: ${hmac}`);

// Verify HMAC
const isValid = CryptoUtils.hmacSha256Verify(secret, message, hmac);
console.log(`   Verification: ${isValid ? '✅ VALID' : '❌ INVALID'}\n`);

// Example 2: API authentication
console.log('📋 Example 2: API Authentication');
const apiSecret = Buffer.from('api-secret-key-for-authentication', 'utf8');
const apiRequest = Buffer.from(JSON.stringify({
    method: 'POST',
    path: '/api/users',
    timestamp: Date.now(),
    data: { name: 'John Doe', email: 'john@example.com' }
}), 'utf8');

const apiHmac = CryptoUtils.hmacSha256Base64Bytes(apiSecret, apiRequest);
console.log(`   API Request: ${apiRequest.toString('utf8').substring(0, 100)}...`);
console.log(`   API HMAC: ${apiHmac}`);

// Simulate verification on server side
const apiValid = CryptoUtils.hmacSha256Verify(apiSecret, apiRequest, apiHmac);
console.log(`   API Authentication: ${apiValid ? '✅ AUTHENTIC' : '❌ INVALID'}\n`);

// Example 3: Message integrity verification
console.log('📋 Example 3: Message Integrity');
const originalMessage = Buffer.from('Important document content', 'utf8');
const documentSecret = Buffer.from('document-integrity-secret-key', 'utf8');

const documentHmac = CryptoUtils.hmacSha256Base64Bytes(documentSecret, originalMessage);
console.log(`   Original: "${originalMessage.toString('utf8')}"`);
console.log(`   Integrity HMAC: ${documentHmac}`);

// Simulate message tampering
const tamperedMessage = Buffer.from('Important document content MODIFIED', 'utf8');
const tamperedValid = CryptoUtils.hmacSha256Verify(documentSecret, tamperedMessage, documentHmac);
console.log(`   Tampered message: "${tamperedMessage.toString('utf8')}"`);
console.log(`   Tampered verification: ${tamperedValid ? '❌ INCORRECTLY VALID' : '✅ CORRECTLY INVALID'}\n`);

// Example 4: Session token generation
console.log('📋 Example 4: Session Token Generation');
const sessionSecret = Buffer.from('session-secret-key-32-bytes-long', 'utf8');
const sessionData = Buffer.from(JSON.stringify({
    userId: 12345,
    username: 'john_doe',
    role: 'admin',
    expires: Date.now() + 3600000 // 1 hour
}), 'utf8');

const sessionToken = CryptoUtils.hmacSha256Base64Bytes(sessionSecret, sessionData);
console.log(`   Session Data: ${sessionData.toString('utf8')}`);
console.log(`   Session Token: ${sessionToken}`);

// Verify session token
const sessionValid = CryptoUtils.hmacSha256Verify(sessionSecret, sessionData, sessionToken);
console.log(`   Session Verification: ${sessionValid ? '✅ VALID SESSION' : '❌ INVALID SESSION'}\n`);

// Example 5: File integrity checking
console.log('📋 Example 5: File Integrity Checking');
const fileContent = Buffer.from('This is the content of an important file that needs integrity verification.', 'utf8');
const fileSecret = Buffer.from('file-integrity-secret-key-32-bytes', 'utf8');

const fileHmac = CryptoUtils.hmacSha256Base64Bytes(fileSecret, fileContent);
console.log(`   File Content: "${fileContent.toString('utf8')}"`);
console.log(`   File HMAC: ${fileHmac}`);

// Simulate file corruption
const corruptedContent = Buffer.from('This is the content of an important file that needs integrity verification CORRUPTED.', 'utf8');
const corruptedValid = CryptoUtils.hmacSha256Verify(fileSecret, corruptedContent, fileHmac);
console.log(`   Corrupted Content: "${corruptedContent.toString('utf8')}"`);
console.log(`   Corruption Detection: ${corruptedValid ? '❌ NOT DETECTED' : '✅ DETECTED'}\n`);

// Example 6: Password reset token
console.log('📋 Example 6: Password Reset Token');
const resetSecret = Buffer.from('password-reset-secret-key-32-bytes', 'utf8');
const resetData = Buffer.from(JSON.stringify({
    userId: 12345,
    email: 'user@example.com',
    timestamp: Date.now(),
    nonce: 'random-nonce-12345'
}), 'utf8');

const resetToken = CryptoUtils.hmacSha256Base64Bytes(resetSecret, resetData);
console.log(`   Reset Data: ${resetData.toString('utf8')}`);
console.log(`   Reset Token: ${resetToken}`);

// Verify reset token
const resetValid = CryptoUtils.hmacSha256Verify(resetSecret, resetData, resetToken);
console.log(`   Reset Token Verification: ${resetValid ? '✅ VALID TOKEN' : '❌ INVALID TOKEN'}\n`);

// Example 7: Performance comparison
console.log('📋 Example 7: Performance Comparison');
const perfSecret = Buffer.from('performance-test-secret-key-32-bytes', 'utf8');
const perfMessage = Buffer.from('Performance test message', 'utf8');

// Test new byte array methods
const start1 = Date.now();
for (let i = 0; i < 1000; i++) {
    const hmac = CryptoUtils.hmacSha256Base64Bytes(perfSecret, perfMessage);
    CryptoUtils.hmacSha256Verify(perfSecret, perfMessage, hmac);
}
const time1 = Date.now() - start1;

// Test old string methods
const start2 = Date.now();
for (let i = 0; i < 1000; i++) {
    const hmac = CryptoUtils.hmacSha256Base64(perfMessage.toString('utf8'), perfSecret.toString('utf8'));
    // Note: No direct verification method for old API
}
const time2 = Date.now() - start2;

console.log(`   New byte array methods: ${time1}ms for 1000 operations`);
console.log(`   Old string methods: ${time2}ms for 1000 operations`);
console.log(`   Performance difference: ${time1 < time2 ? '✅ New methods faster' : '❌ Old methods faster'}\n`);

console.log('🎉 HMAC-SHA256 Examples Complete!');
console.log('\n📚 Usage Summary:');
console.log('   • Use hmacSha256Base64Bytes(secret, message) to generate HMAC');
console.log('   • Use hmacSha256Verify(secret, message, hmac) to verify HMAC');
console.log('   • Both methods work with Buffer objects (byte arrays)');
console.log('   • HMAC is returned as Base64 string for easy JSON transport');
console.log('   • Verification uses constant-time comparison for security');
console.log('   • Perfect for API authentication, message integrity, and token generation');

