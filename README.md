Overview
Full-stack app with a Node.js/Express backend and React frontend.

Project Structure

securepayN/
├── backend/            # New Node.js server (Express APIs)
├── frontend/           # React UI
├── docker-compose.yml  # Docker setup for both services
└── scripts/            # Batch/shell launchers


Features

API endpoints /api/health and /api/status

Real-time health dashboard

Auto-refresh for frontend (e.g., every 30 sec)

Prerequisites

Node.js (version)

npm

Docker (optional)

Setup Instructions

a. With Docker

docker-compose up --build


b. Manual Setup

cd backend
npm install
npm start         # runs Express server

cd ../frontend
npm install
npm start         # starts React dev server


Endpoints

GET /api/health

GET /api/status

Troubleshooting

Port conflicts

CORS setup if using different ports

Dependency installation issues

Deployment Tips

Use a process manager like PM2 for Express backend

Build frontend with npm run build and serve as static files
