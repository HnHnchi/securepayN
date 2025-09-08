import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [healthStatus, setHealthStatus] = useState(null);
  const [systemStatus, setSystemStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchHealthStatus = async () => {
    try {
      const response = await axios.get('/api/health');
      setHealthStatus(response.data);
      setError(null);
    } catch (err) {
      setError('Failed to fetch health status');
      console.error('Health check error:', err);
    }
  };

  const fetchSystemStatus = async () => {
    try {
      const response = await axios.get('/api/status');
      setSystemStatus(response.data);
      setError(null);
    } catch (err) {
      setError('Failed to fetch system status');
      console.error('System status error:', err);
    }
  };

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      await Promise.all([fetchHealthStatus(), fetchSystemStatus()]);
      setLoading(false);
    };

    fetchData();
    
    // Refresh data every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status) => {
    switch (status) {
      case 'healthy':
      case 'operational':
        return '#4CAF50';
      case 'unhealthy':
      case 'error':
        return '#F44336';
      default:
        return '#FF9800';
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  if (loading) {
    return (
      <div className="app">
        <div className="container">
          <div className="loading">
            <div className="spinner"></div>
            <p>Loading system status...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <div className="container">
        <header className="header">
          <h1>SecurePat System Status</h1>
          <p>Real-time backend monitoring dashboard</p>
        </header>

        {error && (
          <div className="error-banner">
            <p>⚠️ {error}</p>
          </div>
        )}

        <div className="status-grid">
          <div className="status-card">
            <h2>Health Check</h2>
            {healthStatus ? (
              <div className="status-content">
                <div 
                  className="status-indicator"
                  style={{ backgroundColor: getStatusColor(healthStatus.status) }}
                >
                  {healthStatus.status.toUpperCase()}
                </div>
                <div className="status-details">
                  <p><strong>Service:</strong> {healthStatus.service}</p>
                  <p><strong>Database:</strong> {healthStatus.database}</p>
                  <p><strong>Timestamp:</strong> {formatTimestamp(healthStatus.timestamp)}</p>
                  {healthStatus.error && (
                    <p className="error-text"><strong>Error:</strong> {healthStatus.error}</p>
                  )}
                </div>
              </div>
            ) : (
              <p>No health data available</p>
            )}
          </div>

          <div className="status-card">
            <h2>System Status</h2>
            {systemStatus ? (
              <div className="status-content">
                <div 
                  className="status-indicator"
                  style={{ backgroundColor: getStatusColor(systemStatus.status) }}
                >
                  {systemStatus.status.toUpperCase()}
                </div>
                <div className="status-details">
                  <p><strong>Database:</strong> {systemStatus.database}</p>
                  <p><strong>Users Count:</strong> {systemStatus.users_count}</p>
                  <p><strong>Uptime:</strong> {systemStatus.uptime}</p>
                  <p><strong>Timestamp:</strong> {formatTimestamp(systemStatus.timestamp)}</p>
                  {systemStatus.error && (
                    <p className="error-text"><strong>Error:</strong> {systemStatus.error}</p>
                  )}
                </div>
              </div>
            ) : (
              <p>No system data available</p>
            )}
          </div>
        </div>

        <div className="actions">
          <button onClick={() => window.location.reload()} className="refresh-btn">
            🔄 Refresh Status
          </button>
        </div>

        <footer className="footer">
          <p>Last updated: {new Date().toLocaleString()}</p>
        </footer>
      </div>
    </div>
  );
}

export default App;
