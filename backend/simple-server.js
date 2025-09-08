const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

console.log('🚀 Starting Simple Server...\n');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Database configuration
const DATABASE_PATH = path.join(__dirname, 'securepat.db');

// Test database connection
console.log('📊 Testing database connection...');
const db = new sqlite3.Database(DATABASE_PATH, (err) => {
    if (err) {
        console.error('❌ Error opening database:', err.message);
        process.exit(1);
    }
    console.log('✅ Connected to SQLite database');
});

// Test database query
db.get('SELECT COUNT(*) as count FROM merchants', (err, row) => {
    if (err) {
        console.error('❌ Error querying database:', err.message);
        process.exit(1);
    }
    console.log(`✅ Database query successful: ${row.count} merchants`);
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        database: 'connected',
        service: 'simple-backend'
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'Simple SecurePat Backend API',
        version: '1.0.0',
        status: 'running'
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Simple server running on http://localhost:${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
});

// Handle errors
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error.message);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});
