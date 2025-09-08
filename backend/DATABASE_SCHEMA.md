# SecurePat Database Schema - Phase 2

## Overview
This document describes the security-focused database schema for the SecurePat payment processing application.

## Tables

### 1. Merchants Table
Stores merchant information and their cryptographic keys for secure communication.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique merchant identifier |
| `name` | VARCHAR(100) | NOT NULL | Merchant business name |
| `email` | VARCHAR(100) | UNIQUE, NOT NULL | Merchant contact email |
| `aes_key_base64` | TEXT | NOT NULL | AES-256 encryption key (Base64 encoded) |
| `hmac_key_base64` | TEXT | NOT NULL | HMAC authentication key (Base64 encoded) |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Record creation timestamp |
| `updated_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Record update timestamp |

**Security Features:**
- Each merchant has unique cryptographic keys
- Keys are stored in Base64 format for easy handling
- Email uniqueness prevents duplicate merchant accounts

### 2. Transactions Table
Stores payment transaction data with encrypted Primary Account Numbers (PAN).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique transaction identifier |
| `merchant_id` | INTEGER | NOT NULL, FK → merchants.id | Reference to merchant |
| `amount` | DECIMAL(10,2) | NOT NULL | Transaction amount |
| `currency` | VARCHAR(3) | NOT NULL, DEFAULT 'USD' | Currency code (ISO 4217) |
| `pan_ciphertext` | TEXT | NOT NULL | Encrypted PAN (Base64 encoded) |
| `pan_iv` | TEXT | NOT NULL | Initialization Vector for PAN encryption (Base64) |
| `pan_last4` | VARCHAR(4) | NOT NULL | Last 4 digits of PAN for display |
| `status` | VARCHAR(20) | NOT NULL, DEFAULT 'pending' | Transaction status |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Transaction timestamp |

**Security Features:**
- PAN is encrypted using merchant's AES key
- IV is stored separately for each transaction
- Only last 4 digits stored in plaintext for display
- Foreign key constraint ensures data integrity
- Cascade delete removes transactions when merchant is deleted

**Transaction Status Values:**
- `pending` - Transaction submitted, awaiting processing
- `approved` - Transaction approved and completed
- `declined` - Transaction declined by processor
- `failed` - Transaction failed due to technical issues

## Indexes

Performance indexes are created for optimal query performance:

- `idx_merchants_email` - Fast merchant lookup by email
- `idx_transactions_merchant_id` - Fast transaction lookup by merchant
- `idx_transactions_status` - Fast filtering by transaction status
- `idx_transactions_created_at` - Fast date range queries

## Security Considerations

### PAN Encryption
- Primary Account Numbers are encrypted using AES-256-CBC
- Each transaction uses a unique IV (Initialization Vector)
- Encryption keys are unique per merchant
- Only last 4 digits stored in plaintext for display purposes

### Key Management
- AES and HMAC keys are generated using cryptographically secure random number generation
- Keys are stored in Base64 format for easy handling
- Each merchant has separate keys for encryption and authentication

### Data Integrity
- Foreign key constraints ensure referential integrity
- NOT NULL constraints prevent incomplete records
- UNIQUE constraints prevent duplicate data

## Sample Data

The database includes sample data for testing:

### Merchants
1. **SecureShop Inc** (admin@secureshop.com)
2. **PaymentPro LLC** (support@paymentpro.com)

### Transactions
1. $29.99 USD - Visa ending in 1111 (approved)
2. $150.00 USD - Mastercard ending in 4444 (pending)
3. $75.50 USD - American Express ending in 0005 (approved)

## Usage Examples

### Creating a New Merchant
```sql
INSERT INTO merchants (name, email, aes_key_base64, hmac_key_base64) 
VALUES ('New Merchant', 'contact@newmerchant.com', 'base64_aes_key', 'base64_hmac_key');
```

### Creating a New Transaction
```sql
INSERT INTO transactions (merchant_id, amount, currency, pan_ciphertext, pan_iv, pan_last4, status)
VALUES (1, 99.99, 'USD', 'encrypted_pan_base64', 'iv_base64', '1234', 'pending');
```

### Querying Transactions by Merchant
```sql
SELECT t.*, m.name as merchant_name 
FROM transactions t 
JOIN merchants m ON t.merchant_id = m.id 
WHERE m.email = 'admin@secureshop.com';
```

## File Structure

- `schema.sql` - Complete database schema with table definitions
- `init-database.js` - Database initialization script with sample data
- `verify-database.js` - Database structure verification script
- `securepat.db` - SQLite database file (created after initialization)

## Initialization

To initialize the database:

```bash
cd backend
node init-database.js
```

To verify the database structure:

```bash
node verify-database.js
```

## Compliance Notes

This schema is designed with security best practices in mind:

- **PCI DSS Compliance**: PAN data is encrypted at rest
- **Data Minimization**: Only necessary data is stored
- **Access Control**: Cryptographic keys are merchant-specific
- **Audit Trail**: All transactions are timestamped
- **Data Integrity**: Foreign key constraints and validation rules

