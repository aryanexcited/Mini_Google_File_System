# 🗄️ Mini Google File System - Distribution Package

## 📦 What's Inside

This package contains a complete distributed file system simulation with:
- Distributed storage across multiple servers
- Automatic fault tolerance and replication
- Web-based management dashboard
- Role-based access control

## 🚀 Quick Setup

1. **Extract** this ZIP file
2. **Open terminal** in the extracted folder
3. **Run these commands**:
   ```bash
   cd web
   npm install
   cd ..
   docker-compose up -d --build
   ```
4. **Open browser** to http://localhost:8080
5. **Login** with `admin` / `admin123`

## 📖 Documentation

- **SETUP_INSTRUCTIONS.md** - Complete setup guide with troubleshooting
- **readme.md** - Full technical documentation

## ⚡ Quick Start Time

- First run: 2-5 minutes (downloads Docker images)
- Subsequent runs: 30 seconds

## 💻 System Requirements

- Docker Desktop
- Internet connection (first run only)
- Ports: 8000, 8001, 8080, 9001-9003
- 4 GB RAM recommended

## ✅ What You'll Get

- 6 Docker containers (master, 3 chunk servers, client, frontend)
- Web interface with real-time monitoring
- Fault-tolerant file storage system
- Complete API for file operations