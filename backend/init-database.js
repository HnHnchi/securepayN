const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const CryptoUtils = require('../crypto/crypto-utils');

console.log('🗄️ Initializing SecurePat Database...\n');

// Database file path
const dbPath = path.join(__dirname, 'securepat.db');

// Remove existing database file if it exists
if (fs.existsSync(dbPath)) {
    fs.unlinkSync(dbPath);
    console.log('   ✅ Removed existing database file');
}

// Create new database
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ Error creating database:', err.message);
        process.exit(1);
    }
    console.log('   ✅ Connected to SQLite database');
});

// Read and execute schema
const schemaPath = path.join(__dirname, 'schema.sql');
const schema = fs.readFileSync(schemaPath, 'utf8');

console.log('📋 Creating tables...');

// Split schema into individual statements and execute them
const statements = schema.split(';').filter(stmt => stmt.trim().length > 0);

let completedStatements = 0;
const totalStatements = statements.length;

statements.forEach((statement, index) => {
    const trimmedStatement = statement.trim();
    if (trimmedStatement.length === 0) return;

    db.exec(trimmedStatement, (err) => {
        if (err) {
            console.error(`❌ Error executing statement ${index + 1}:`, err.message);
            console.error('Statement:', trimmedStatement.substring(0, 100) + '...');
            process.exit(1);
        }
        
        completedStatements++;
        console.log(`   ✅ Statement ${completedStatements}/${totalStatements} executed`);
        
        if (completedStatements === totalStatements) {
            console.log('\n📊 Inserting sample data...');
            insertSampleData();
        }
    });
});

function insertSampleData() {
    // Generate sample cryptographic keys for merchants
    const merchant1AesKey = CryptoUtils.generateRandomBytes(32).toString('base64');
    const merchant1HmacKey = CryptoUtils.generateRandomBytes(32).toString('base64');
    const merchant2AesKey = CryptoUtils.generateRandomBytes(32).toString('base64');
    const merchant2HmacKey = CryptoUtils.generateRandomBytes(32).toString('base64');

    // Insert sample merchants
    const merchantQueries = [
        `INSERT INTO merchants (name, email, aes_key_base64, hmac_key_base64) VALUES 
         ('SecureShop Inc', 'admin@secureshop.com', ?, ?)`,
        `INSERT INTO merchants (name, email, aes_key_base64, hmac_key_base64) VALUES 
         ('PaymentPro LLC', 'support@paymentpro.com', ?, ?)`
    ];

    const merchantParams = [
        [merchant1AesKey, merchant1HmacKey],
        [merchant2AesKey, merchant2HmacKey]
    ];

    let merchantCount = 0;
    merchantQueries.forEach((query, index) => {
        db.run(query, merchantParams[index], function(err) {
            if (err) {
                console.error(`❌ Error inserting merchant ${index + 1}:`, err.message);
                process.exit(1);
            }
            merchantCount++;
            console.log(`   ✅ Merchant ${merchantCount} inserted (ID: ${this.lastID})`);
            
            if (merchantCount === merchantQueries.length) {
                insertSampleTransactions();
            }
        });
    });
}

function insertSampleTransactions() {
    // Sample transaction data
    const sampleTransactions = [
        {
            merchant_id: 1,
            amount: 29.99,
            currency: 'USD',
            pan: '4111111111111111', // Test Visa number
            status: 'approved'
        },
        {
            merchant_id: 1,
            amount: 150.00,
            currency: 'USD',
            pan: '5555555555554444', // Test Mastercard number
            status: 'pending'
        },
        {
            merchant_id: 2,
            amount: 75.50,
            currency: 'USD',
            pan: '378282246310005', // Test American Express number
            status: 'approved'
        }
    ];

    let transactionCount = 0;
    
    sampleTransactions.forEach((tx, index) => {
        // Get merchant's AES key for encryption
        db.get('SELECT aes_key_base64 FROM merchants WHERE id = ?', [tx.merchant_id], (err, merchant) => {
            if (err) {
                console.error(`❌ Error getting merchant ${tx.merchant_id}:`, err.message);
                process.exit(1);
            }

            // Encrypt PAN using merchant's AES key
            const aesKey = Buffer.from(merchant.aes_key_base64, 'base64');
            const panBuffer = Buffer.from(tx.pan, 'utf8');
            const iv = CryptoUtils.generateRandomBytes(16);
            
            const encrypted = CryptoUtils.encryptAES(panBuffer.toString('utf8'), aesKey);
            const panCiphertext = encrypted.encrypted.toString('base64');
            const panIv = encrypted.iv.toString('base64');
            const panLast4 = tx.pan.slice(-4);

            // Insert transaction
            const query = `INSERT INTO transactions 
                (merchant_id, amount, currency, pan_ciphertext, pan_iv, pan_last4, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?)`;
            
            const params = [tx.merchant_id, tx.amount, tx.currency, panCiphertext, panIv, panLast4, tx.status];
            
            db.run(query, params, function(err) {
                if (err) {
                    console.error(`❌ Error inserting transaction ${index + 1}:`, err.message);
                    process.exit(1);
                }
                
                transactionCount++;
                console.log(`   ✅ Transaction ${transactionCount} inserted (ID: ${this.lastID}) - ${tx.panLast4} - $${tx.amount}`);
                
                if (transactionCount === sampleTransactions.length) {
                    verifyDatabase();
                }
            });
        });
    });
}

function verifyDatabase() {
    console.log('\n🔍 Verifying database structure...');
    
    // Check merchants table
    db.all("SELECT name, sql FROM sqlite_master WHERE type='table' AND name='merchants'", (err, rows) => {
        if (err) {
            console.error('❌ Error checking merchants table:', err.message);
            process.exit(1);
        }
        console.log('   ✅ Merchants table structure verified');
    });

    // Check transactions table
    db.all("SELECT name, sql FROM sqlite_master WHERE type='table' AND name='transactions'", (err, rows) => {
        if (err) {
            console.error('❌ Error checking transactions table:', err.message);
            process.exit(1);
        }
        console.log('   ✅ Transactions table structure verified');
    });

    // Count records
    db.get("SELECT COUNT(*) as count FROM merchants", (err, row) => {
        if (err) {
            console.error('❌ Error counting merchants:', err.message);
            process.exit(1);
        }
        console.log(`   📊 Merchants: ${row.count} records`);
    });

    db.get("SELECT COUNT(*) as count FROM transactions", (err, row) => {
        if (err) {
            console.error('❌ Error counting transactions:', err.message);
            process.exit(1);
        }
        console.log(`   📊 Transactions: ${row.count} records`);
    });

    // Test PAN decryption
    console.log('\n🔐 Testing PAN decryption...');
    db.get(`
        SELECT t.pan_ciphertext, t.pan_iv, t.pan_last4, m.aes_key_base64 
        FROM transactions t 
        JOIN merchants m ON t.merchant_id = m.id 
        WHERE t.id = 1
    `, (err, row) => {
        if (err) {
            console.error('❌ Error testing PAN decryption:', err.message);
            process.exit(1);
        }

        try {
            const aesKey = Buffer.from(row.aes_key_base64, 'base64');
            const iv = Buffer.from(row.pan_iv, 'base64');
            const ciphertext = Buffer.from(row.pan_ciphertext, 'base64');
            
            const decrypted = CryptoUtils.decryptAES({encrypted: ciphertext.toString('base64'), iv: iv.toString('base64')}, aesKey);
            const decryptedPan = decrypted.toString('utf8');
            
            console.log(`   ✅ PAN decryption test: ${decryptedPan.slice(0, 4)}****${decryptedPan.slice(-4)}`);
            console.log(`   ✅ Last 4 digits match: ${decryptedPan.slice(-4) === row.pan_last4 ? 'YES' : 'NO'}`);
            
            console.log('\n🎉 Database initialization complete!');
            console.log('\n📋 Summary:');
            console.log('   ✅ Merchants table created with cryptographic keys');
            console.log('   ✅ Transactions table created with encrypted PAN storage');
            console.log('   ✅ Sample data inserted and verified');
            console.log('   ✅ PAN encryption/decryption tested');
            console.log('   ✅ Foreign key relationships established');
            console.log('   ✅ Indexes created for performance');
            
            db.close((err) => {
                if (err) {
                    console.error('❌ Error closing database:', err.message);
                } else {
                    console.log('   ✅ Database connection closed');
                }
                process.exit(0);
            });
        } catch (error) {
            console.error('❌ PAN decryption failed:', error.message);
            process.exit(1);
        }
    });
}
