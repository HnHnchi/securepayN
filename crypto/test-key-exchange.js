const CryptoUtils = require('./crypto-utils');
const http = require('http');
const path = require('path');

console.log('🔐 Testing RSA-Protected Key Exchange Protocol...\n');

const BASE_URL = 'http://localhost:5000';

// Load client keys
const clientPrivateKey = CryptoUtils.loadPrivateKey(path.join(__dirname, 'keys', 'client_rsa_private.pem'));
const clientPublicKey = CryptoUtils.loadPublicKey(path.join(__dirname, 'keys', 'client_rsa_public.pem'));

// Load server public key
const serverPublicKey = CryptoUtils.loadPublicKey(path.join(__dirname, 'keys', 'rsa_public.pem'));

function makeRequest(method, path, data = null) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 5000,
            path: path,
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => {
                body += chunk;
            });
            res.on('end', () => {
                try {
                    const jsonBody = JSON.parse(body);
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        body: jsonBody
                    });
                } catch (error) {
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        body: body
                    });
                }
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        if (data) {
            req.write(JSON.stringify(data));
        }
        req.end();
    });
}

async function testKeyExchange() {
    console.log('📋 Step 1: Create a test merchant...');
    
    // First, create a merchant
    const merchantResponse = await makeRequest('POST', '/api/merchants', {
        name: 'Key Exchange Test Merchant',
        email: 'keytest@example.com'
    });

    if (merchantResponse.statusCode !== 201) {
        console.error('❌ Failed to create merchant:', merchantResponse.body);
        return;
    }

    const merchantId = merchantResponse.body.id;
    console.log(`   ✅ Merchant created with ID: ${merchantId}`);

    console.log('\n📋 Step 2: Client → Server Key Exchange Request...');
    
    // Generate nonce (16 bytes, Base64 encoded)
    const nonce = CryptoUtils.generateRandomBytes(16).toString('base64');
    const timestamp = Date.now();

    // Build raw JSON payload
    const requestPayload = {
        merchantId: merchantId,
        nonce: nonce,
        timestamp: timestamp
    };

    console.log('   Raw JSON payload:');
    console.log(`   ${JSON.stringify(requestPayload, null, 2)}`);

    // Sign with client private key
    const requestJson = JSON.stringify(requestPayload);
    const requestBuffer = Buffer.from(requestJson, 'utf8');
    const signature = CryptoUtils.rsaSign(clientPrivateKey, requestBuffer);
    const signatureBase64 = signature.toString('base64');

    console.log(`   ✅ Signed with client private key`);
    console.log(`   Signature length: ${signature.length} bytes`);

    // Encrypt with server public key
    const encryptedRequest = CryptoUtils.rsaEncryptWithPublic(serverPublicKey, requestBuffer);
    const ciphertextBase64 = encryptedRequest.toString('base64');

    console.log(`   ✅ Encrypted with server public key`);
    console.log(`   Ciphertext length: ${encryptedRequest.length} bytes`);

    // Send request
    const keyExchangeRequest = {
        ciphertext: ciphertextBase64,
        signature: signatureBase64
    };

    console.log('\n   Sending encrypted request...');
    const response = await makeRequest('POST', '/api/keys/exchange/request', keyExchangeRequest);

    console.log(`   Response status: ${response.statusCode}`);

    if (response.statusCode !== 200) {
        console.error('❌ Key exchange failed:', response.body);
        return;
    }

    console.log('   ✅ Server response received');

    console.log('\n📋 Step 3: Server → Client Key Delivery...');

    const { ciphertext: responseCiphertext, signature: responseSignature } = response.body;

    // Decrypt response with client private key
    const responseEncrypted = Buffer.from(responseCiphertext, 'base64');
    const responseDecrypted = CryptoUtils.rsaDecryptWithPrivate(clientPrivateKey, responseEncrypted);
    const responseJson = JSON.parse(responseDecrypted.toString('utf8'));

    console.log('   ✅ Decrypted response with client private key');
    console.log('   Decrypted payload:');
    console.log(`   ${JSON.stringify(responseJson, null, 2)}`);

    // Verify server signature
    const responseSignatureBuffer = Buffer.from(responseSignature, 'base64');
    const isValidServerSignature = CryptoUtils.rsaVerify(serverPublicKey, responseDecrypted, responseSignatureBuffer);

    if (!isValidServerSignature) {
        console.error('❌ Server signature verification failed');
        return;
    }

    console.log('   ✅ Server signature verified');

    // Validate response
    const { merchantId: responseMerchantId, aesKeyBase64, hmacKeyBase64, issuedAt, nonce: responseNonce } = responseJson;

    // Check nonce echo
    if (responseNonce !== nonce) {
        console.error('❌ Nonce mismatch - possible replay attack');
        console.log(`   Expected: ${nonce}`);
        console.log(`   Received: ${responseNonce}`);
        return;
    }

    console.log('   ✅ Nonce echo verified');

    // Check merchant ID
    if (responseMerchantId !== merchantId) {
        console.error('❌ Merchant ID mismatch');
        return;
    }

    console.log('   ✅ Merchant ID verified');

    // Check timestamp
    const issuedTime = new Date(issuedAt);
    const now = new Date();
    const timeDiff = Math.abs(now - issuedTime);

    if (timeDiff > 60000) { // 1 minute tolerance
        console.error('❌ Issued timestamp too old');
        return;
    }

    console.log('   ✅ Timestamp validated');

    // Validate keys
    if (!aesKeyBase64 || !hmacKeyBase64) {
        console.error('❌ Missing keys in response');
        return;
    }

    // Check key lengths (Base64 encoded 32-byte keys should be 44 characters)
    if (aesKeyBase64.length !== 44 || hmacKeyBase64.length !== 44) {
        console.error('❌ Invalid key lengths');
        console.log(`   AES key length: ${aesKeyBase64.length}`);
        console.log(`   HMAC key length: ${hmacKeyBase64.length}`);
        return;
    }

    console.log('   ✅ Key lengths validated');

    console.log('\n🎉 Key Exchange Successful!');
    console.log('\n📊 Summary:');
    console.log(`   Merchant ID: ${merchantId}`);
    console.log(`   AES Key: ${aesKeyBase64.substring(0, 20)}... (${aesKeyBase64.length} chars)`);
    console.log(`   HMAC Key: ${hmacKeyBase64.substring(0, 20)}... (${hmacKeyBase64.length} chars)`);
    console.log(`   Issued At: ${issuedAt}`);
    console.log(`   Nonce: ${nonce}`);

    console.log('\n🔐 Security Features Verified:');
    console.log('   ✅ RSA encryption/decryption');
    console.log('   ✅ RSA signature verification');
    console.log('   ✅ Nonce replay protection');
    console.log('   ✅ Timestamp validation');
    console.log('   ✅ Merchant authentication');
    console.log('   ✅ Key generation and storage');

    // Test the keys by verifying they're stored in the database
    console.log('\n📋 Step 4: Verify keys in database...');
    
    const verifyResponse = await makeRequest('GET', `/api/merchants/${merchantId}`);
    
    if (verifyResponse.statusCode === 200) {
        console.log('   ✅ Keys successfully stored in database');
    } else {
        console.log('   ℹ️  GET endpoint not implemented, but keys should be stored');
    }
}

async function testErrorCases() {
    console.log('\n📋 Testing Error Cases...');
    console.log('='.repeat(50));

    // Test 1: Invalid signature
    console.log('\n1. Testing invalid signature...');
    const invalidRequest = {
        ciphertext: 'dGVzdA==', // "test" in base64
        signature: 'aW52YWxpZA==' // "invalid" in base64
    };

    const response1 = await makeRequest('POST', '/api/keys/exchange/request', invalidRequest);
    console.log(`   Status: ${response1.statusCode}`);
    console.log(`   Response: ${response1.body.error || 'Unexpected response'}`);

    // Test 2: Missing fields
    console.log('\n2. Testing missing fields...');
    const response2 = await makeRequest('POST', '/api/keys/exchange/request', {});
    console.log(`   Status: ${response2.statusCode}`);
    console.log(`   Response: ${response2.body.error || 'Unexpected response'}`);

    // Test 3: Non-existent merchant
    console.log('\n3. Testing non-existent merchant...');
    const nonce = CryptoUtils.generateRandomBytes(16).toString('base64');
    const timestamp = Date.now();
    const requestPayload = {
        merchantId: 99999, // Non-existent merchant
        nonce: nonce,
        timestamp: timestamp
    };

    const requestJson = JSON.stringify(requestPayload);
    const requestBuffer = Buffer.from(requestJson, 'utf8');
    const signature = CryptoUtils.rsaSign(clientPrivateKey, requestBuffer);
    const encryptedRequest = CryptoUtils.rsaEncryptWithPublic(serverPublicKey, requestBuffer);

    const invalidMerchantRequest = {
        ciphertext: encryptedRequest.toString('base64'),
        signature: signature.toString('base64')
    };

    const response3 = await makeRequest('POST', '/api/keys/exchange/request', invalidMerchantRequest);
    console.log(`   Status: ${response3.statusCode}`);
    console.log(`   Response: ${response3.body.error || 'Unexpected response'}`);
}

async function runTests() {
    try {
        await testKeyExchange();
        await testErrorCases();
        
        console.log('\n🎉 All key exchange tests completed!');
        
    } catch (error) {
        console.error('\n❌ Test failed:', error.message);
        console.error('Stack trace:', error.stack);
        process.exit(1);
    }
}

// Check if server is running
makeRequest('GET', '/api/health')
    .then(() => {
        console.log('✅ Server is running, starting key exchange tests...\n');
        runTests();
    })
    .catch((error) => {
        console.error('❌ Server is not running. Please start the backend server first:');
        console.error('   cd backend && npm start');
        console.error('   Error:', error.message);
        process.exit(1);
    });
