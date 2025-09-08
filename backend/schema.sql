-- Database schema for SecurePat application
-- Phase 2: Security-focused tables for payment processing

-- Merchants table - stores merchant information and cryptographic keys
CREATE TABLE IF NOT EXISTS merchants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    aes_key_base64 TEXT NOT NULL,  -- AES-256 key for encryption (Base64 encoded)
    hmac_key_base64 TEXT NOT NULL, -- HMAC key for authentication (Base64 encoded)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Transactions table - stores payment transaction data with encrypted PAN
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    merchant_id INTEGER NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    pan_ciphertext TEXT NOT NULL,  -- Encrypted Primary Account Number (Base64)
    pan_iv TEXT NOT NULL,          -- Initialization Vector for PAN encryption (Base64)
    pan_last4 VARCHAR(4) NOT NULL, -- Last 4 digits of PAN for display
    status VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending, approved, declined, failed
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (merchant_id) REFERENCES merchants(id) ON DELETE CASCADE
);

-- System status table for tracking health checks
CREATE TABLE IF NOT EXISTS system_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status VARCHAR(20) NOT NULL,
    message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial system status
INSERT OR IGNORE INTO system_status (status, message) VALUES 
    ('healthy', 'System initialized successfully');

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_merchants_email ON merchants(email);
CREATE INDEX IF NOT EXISTS idx_transactions_merchant_id ON transactions(merchant_id);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at);
