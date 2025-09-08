# 🚀 SecurePayN  

**SecurePayN** is a lightweight **full-stack application** featuring a **Node.js/Express backend** and a **React frontend**. It provides a simple health/status monitoring dashboard with real-time updates.  

---

## 📂 Project Structure  

    securepayN/
    ├── backend/             # Node.js + Express API server
    ├── frontend/            # React UI for the dashboard
    ├── docker-compose.yml   # Docker setup for both frontend & backend
    └── scripts/             # Helper batch/shell launchers

---

## ✨ Features  

- **REST APIs** for health and status checks:  
  - `GET /api/health`  
  - `GET /api/status`  
- **Real-time dashboard** to visualize system health.  
- **Auto-refresh UI** (e.g., every 30 seconds).  
- **Docker-ready** for easy deployment.  

---

## 🛠 Prerequisites  

- [Node.js](https://nodejs.org/) (v16+ recommended)  
- npm (comes with Node.js)  
- [Docker](https://www.docker.com/) (optional, for containerized setup)  

---

## ⚡ Getting Started  

### 🔹 Option 1 — Run with Docker  
    docker-compose up --build  

This spins up both frontend and backend in containers.  

---

### 🔹 Option 2 — Run Manually  

**Backend** (Express server)  
cd backend
npm install
npm start

**Frontend** (React app)  
cd ../frontend
npm install
npm start

By default:  
- Backend runs on **http://localhost:5000**  
- Frontend runs on **http://localhost:3000**  

---

## 🔗 API Endpoints  

- `GET /api/health` → Returns health status of the server.  
- `GET /api/status` → Returns current system/application status.  

---

## 🧰 Troubleshooting  

- **Port conflicts** → Change default ports in `backend/server.js` or React config.  
- **CORS issues** → Ensure backend allows requests from frontend’s origin.  
- **Dependency errors** →  
    rm -rf node_modules package-lock.json  
    npm install  

---

## 🚀 Deployment Tips  

- Use **PM2** or another process manager to run the backend in production.  
- Build the frontend for production:  
    cd frontend  
    npm run build  

Then serve the static files using Express or Nginx.  

---

## 📜 License  

MIT License – feel free to use and modify.   
