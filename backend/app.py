from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

# Database configuration
DATABASE = 'app.db'

def init_db():
    """Initialize the database with the schema"""
    conn = sqlite3.connect(DATABASE)
    with open('schema.sql', 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint that returns backend status"""
    try:
        # Check database connection
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT 1')
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected',
            'service': 'backend'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'error': str(e),
            'service': 'backend'
        }), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get detailed system status"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get some basic stats
        cursor.execute('SELECT COUNT(*) FROM users')
        user_count = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'status': 'operational',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected',
            'users_count': user_count,
            'uptime': 'running'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # Initialize database on startup
    if not os.path.exists(DATABASE):
        init_db()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
