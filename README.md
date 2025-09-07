# SecurePat - Full Stack Application

A full-stack application with a Python Flask backend and React frontend for monitoring system health and status.

## Project Structure

```
securepat/
├── backend/
│   ├── app.py              # Flask application with health endpoints
│   ├── requirements.txt    # Python dependencies
│   └── schema.sql         # Database schema
├── frontend/
│   ├── public/
│   │   └── index.html     # HTML template
│   ├── src/
│   │   ├── App.js         # Main React component
│   │   ├── App.css        # Styling for the application
│   │   ├── index.js       # React entry point
│   │   └── index.css      # Global styles
│   └── package.json       # Node.js dependencies
└── README.md              # This file
```

## Features

- **Backend Health Monitoring**: RESTful API with `/api/health` and `/api/status` endpoints
- **Real-time Status Display**: React frontend showing backend health status
- **Database Integration**: SQLite database with user management
- **Auto-refresh**: Frontend automatically updates every 30 seconds
- **Responsive Design**: Modern, mobile-friendly UI

## Prerequisites

Before running this application, make sure you have the following installed:

### Option 1: Docker (Recommended - No Python/Node.js needed locally)
- **Docker Desktop** - Download from https://www.docker.com/products/docker-desktop/
- **Docker Compose** (included with Docker Desktop)

### Option 2: Local Development
- **Python 3.7+** with pip
- **Node.js 14+** with npm
- **Git** (for cloning the repository)

## Setup Instructions

### 1. Clone the Repository

```bash
git clone <repository-url>
cd securepat
```

## Quick Start with Docker (Recommended)

### Option 1: Production Mode
```bash
# Start the application
docker-compose up --build

# Or use the convenience script
# Windows: Double-click run.bat
# Linux/macOS: ./run.sh
```

### Option 2: Development Mode
```bash
# Start in development mode with hot reload
docker-compose -f docker-compose.dev.yml up --build

# Or use the development script
# Windows: Double-click docker-dev.bat
```

### Stop the Application
```bash
# Stop all containers
docker-compose down

# Or use the stop script
# Windows: Double-click docker-stop.bat
```

## Local Development Setup (Alternative)

### 2. Backend Setup

Navigate to the backend directory and set up the Python environment:

```bash
cd backend

# Create a virtual environment (recommended)
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Frontend Setup

Navigate to the frontend directory and install dependencies:

```bash
cd ../frontend
npm install
```

## Running the Application

### Option 1: Run Both Services Separately

#### Start the Backend

```bash
cd backend
python app.py
```

The backend will start on `http://localhost:5000`

#### Start the Frontend

In a new terminal:

```bash
cd frontend
npm start
```

The frontend will start on `http://localhost:3000` and automatically open in your browser.

### Option 2: Using Development Scripts

You can create batch/shell scripts to run both services simultaneously:

#### Windows (run.bat)
```batch
@echo off
start "Backend" cmd /k "cd backend && python app.py"
timeout /t 3
start "Frontend" cmd /k "cd frontend && npm start"
```

#### macOS/Linux (run.sh)
```bash
#!/bin/bash
cd backend && python app.py &
cd ../frontend && npm start
```

## API Endpoints

### Health Check
- **URL**: `GET /api/health`
- **Description**: Returns the current health status of the backend
- **Response**:
```json
{
  "status": "healthy",
  "timestamp": "2023-12-07T10:30:00.000Z",
  "database": "connected",
  "service": "backend"
}
```

### System Status
- **URL**: `GET /api/status`
- **Description**: Returns detailed system status including user count
- **Response**:
```json
{
  "status": "operational",
  "timestamp": "2023-12-07T10:30:00.000Z",
  "database": "connected",
  "users_count": 3,
  "uptime": "running"
}
```

## Database Schema

The application uses SQLite with the following tables:

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### System Status Table
```sql
CREATE TABLE system_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status VARCHAR(20) NOT NULL,
    message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Configuration

### Backend Configuration
- **Port**: 5000 (configurable in `app.py`)
- **Database**: SQLite (`app.db`)
- **CORS**: Enabled for frontend communication

### Frontend Configuration
- **Port**: 3000 (default React port)
- **Proxy**: Configured to proxy API calls to backend
- **Auto-refresh**: 30-second intervals

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   - Backend: Change port in `app.py` (line with `app.run()`)
   - Frontend: React will prompt to use a different port

2. **Database Connection Issues**
   - Ensure the `schema.sql` file is in the backend directory
   - Check file permissions for database creation

3. **CORS Issues**
   - Ensure Flask-CORS is installed: `pip install Flask-CORS`
   - Check that the frontend proxy is configured correctly

4. **Dependencies Issues**
   - Backend: `pip install -r requirements.txt`
   - Frontend: `npm install`

### Logs and Debugging

- **Backend logs**: Check the terminal where you ran `python app.py`
- **Frontend logs**: Check the browser console and terminal where you ran `npm start`
- **Database**: The SQLite database file (`app.db`) will be created in the backend directory

## Development

### Adding New Features

1. **Backend**: Add new routes in `app.py`
2. **Frontend**: Create new components in `src/`
3. **Database**: Modify `schema.sql` and update the database initialization

### Testing

- **Backend**: Test API endpoints using curl, Postman, or browser
- **Frontend**: Use React's built-in testing tools

## Production Deployment

For production deployment:

1. **Backend**:
   - Use a production WSGI server (e.g., Gunicorn)
   - Set up environment variables for configuration
   - Use a production database (PostgreSQL, MySQL)

2. **Frontend**:
   - Build the production version: `npm run build`
   - Serve static files with a web server (Nginx, Apache)

## License

This project is open source and available under the MIT License.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the logs for error messages
3. Ensure all dependencies are properly installed
4. Verify that both services are running on the correct ports
