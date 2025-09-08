const sqlite3 = require('sqlite3').verbose();
const path = require('path');

console.log('🔍 Verifying SecurePat Database Structure...\n');

const dbPath = path.join(__dirname, 'securepat.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ Error opening database:', err.message);
        process.exit(1);
    }
    console.log('   ✅ Connected to database');
});

// Show table structure
console.log('📋 Table Structures:');
console.log('='.repeat(50));

// Merchants table
db.all("PRAGMA table_info(merchants)", (err, rows) => {
    if (err) {
        console.error('❌ Error getting merchants table info:', err.message);
        return;
    }
    
    console.log('\n🏪 MERCHANTS Table:');
    console.log('   Column Name        | Type    | Not Null | Primary Key');
    console.log('   -------------------|---------|----------|------------');
    rows.forEach(row => {
        const name = row.name.padEnd(18);
        const type = row.type.padEnd(7);
        const notNull = row.notnull ? 'YES' : 'NO';
        const pk = row.pk ? 'YES' : 'NO';
        console.log(`   ${name} | ${type} | ${notNull.padEnd(8)} | ${pk}`);
    });
});

// Transactions table
db.all("PRAGMA table_info(transactions)", (err, rows) => {
    if (err) {
        console.error('❌ Error getting transactions table info:', err.message);
        return;
    }
    
    console.log('\n💳 TRANSACTIONS Table:');
    console.log('   Column Name        | Type    | Not Null | Primary Key');
    console.log('   -------------------|---------|----------|------------');
    rows.forEach(row => {
        const name = row.name.padEnd(18);
        const type = row.type.padEnd(7);
        const notNull = row.notnull ? 'YES' : 'NO';
        const pk = row.pk ? 'YES' : 'NO';
        console.log(`   ${name} | ${type} | ${notNull.padEnd(8)} | ${pk}`);
    });
});

// Show foreign keys
console.log('\n🔗 Foreign Key Relationships:');
db.all("PRAGMA foreign_key_list(transactions)", (err, rows) => {
    if (err) {
        console.error('❌ Error getting foreign key info:', err.message);
        return;
    }
    
    if (rows.length > 0) {
        rows.forEach(row => {
            console.log(`   ${row.from} → ${row.table}.${row.to}`);
        });
    } else {
        console.log('   No foreign keys found');
    }
});

// Show indexes
console.log('\n📊 Indexes:');
db.all("SELECT name, sql FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'", (err, rows) => {
    if (err) {
        console.error('❌ Error getting index info:', err.message);
        return;
    }
    
    if (rows.length > 0) {
        rows.forEach(row => {
            console.log(`   ${row.name}`);
        });
    } else {
        console.log('   No custom indexes found');
    }
});

// Show sample data
console.log('\n📊 Sample Data:');
console.log('='.repeat(50));

// Merchants
db.all("SELECT id, name, email, LENGTH(aes_key_base64) as aes_key_len, LENGTH(hmac_key_base64) as hmac_key_len FROM merchants", (err, rows) => {
    if (err) {
        console.error('❌ Error getting merchants data:', err.message);
        return;
    }
    
    console.log('\n🏪 Merchants:');
    console.log('   ID | Name              | Email                    | AES Key | HMAC Key');
    console.log('   ---|-------------------|--------------------------|---------|---------');
    rows.forEach(row => {
        const id = row.id.toString().padEnd(3);
        const name = row.name.padEnd(17);
        const email = row.email.padEnd(24);
        const aesLen = row.aes_key_len.toString().padEnd(7);
        const hmacLen = row.hmac_key_len.toString();
        console.log(`   ${id} | ${name} | ${email} | ${aesLen} | ${hmacLen}`);
    });
});

// Transactions
db.all("SELECT id, merchant_id, amount, currency, pan_last4, status, created_at FROM transactions", (err, rows) => {
    if (err) {
        console.error('❌ Error getting transactions data:', err.message);
        return;
    }
    
    console.log('\n💳 Transactions:');
    console.log('   ID | Merchant | Amount  | Currency | Last 4 | Status   | Created');
    console.log('   ---|----------|---------|----------|--------|----------|-------------------');
    rows.forEach(row => {
        const id = row.id.toString().padEnd(3);
        const merchantId = row.merchant_id.toString().padEnd(8);
        const amount = `$${row.amount}`.padEnd(7);
        const currency = row.currency.padEnd(8);
        const last4 = row.pan_last4.padEnd(6);
        const status = row.status.padEnd(8);
        const created = new Date(row.created_at).toLocaleString();
        console.log(`   ${id} | ${merchantId} | ${amount} | ${currency} | ${last4} | ${status} | ${created}`);
    });
    
    // Close database
    db.close((err) => {
        if (err) {
            console.error('❌ Error closing database:', err.message);
        } else {
            console.log('\n✅ Database verification complete!');
        }
    });
});
