const express = require('express');
const cors = require('cors');

console.log('🧪 Testing Server Startup...\n');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Simple test endpoint
app.get('/test', (req, res) => {
    res.json({ message: 'Server is working!' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Test server running on http://localhost:${PORT}`);
    console.log(`📊 Test endpoint: http://localhost:${PORT}/test`);
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
