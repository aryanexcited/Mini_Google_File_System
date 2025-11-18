# Mini Google File System - Setup Instructions

## 📋 Prerequisites

Before starting, ensure you have:
- **Docker Desktop** installed and running
- **Internet connection** (for downloading Docker images)
- **Available ports**: 8000, 8001, 8080, 9001, 9002, 9003

## 🚀 Quick Start (3 Easy Steps)

### Step 1: Extract the Files
```bash
# Extract the ZIP file to your desired location
# Open terminal/command prompt in the extracted folder
cd Mini_Google_File_System
```

### Step 2: Install Node.js Dependencies
```bash
# Navigate to web directory
cd web

# Install dependencies
npm install

# Return to root directory
cd ..
```

### Step 3: Start the System
```bash
# Build and start all containers
docker-compose up -d --build

# This will download Docker images and build containers
# First run may take 2-5 minutes depending on your internet speed
```

### Step 4: Verify Installation
```bash
# Check that all 6 containers are running
docker-compose ps

# You should see:
# - mini_google_file_system-master-1    (Up)
# - mini_google_file_system-client-1    (Up)
# - mini_google_file_system-chunk1-1    (Up)
# - mini_google_file_system-chunk2-1    (Up)
# - mini_google_file_system-chunk3-1    (Up)
# - mini_google_file_system-frontend-1  (Up)
```

## 🌐 Access the System

Once all containers are running, access:

- **Web Dashboard**: http://localhost:8080
- **Master API**: http://localhost:8000/status
- **Client API**: http://localhost:8001

### Default Login Credentials

| Username | Password | Role  |
|----------|----------|-------|
| admin    | admin123 | Admin |

## 📊 What Gets Installed

The setup creates the following containers:

1. **Master Node** (Port 8000)
   - Coordinates all operations
   - Manages metadata and chunk assignments
   - Monitors server health

2. **Chunk Servers** (Ports 9001-9003)
   - Store file chunks with replication
   - 3 servers for fault tolerance

3. **Client Service** (Port 8001)
   - Handles file uploads
   - Splits files into chunks
   - Distributes to chunk servers

4. **Web Frontend** (Port 8080)
   - React-based dashboard
   - Real-time monitoring
   - File management interface

## ✅ Testing the System

### Upload Your First File

1. Open http://localhost:8080
2. Login with `admin` / `admin123`
3. Navigate to "Upload File" section
4. Enter:
   - **Filename**: `test.txt`
   - **Content**: `Hello World! This is my first file.`
5. Click **Upload File**
6. Watch progress bar and see file appear in "My Files"

### Test Fault Tolerance

1. Go to "Chunk Servers" section
2. Click **Simulate Failure** on any server
3. Observe system continues to work with 2 active servers
4. Restart the failed server:
   ```bash
   docker-compose restart chunk1
   ```

## 🛑 Managing the System

### Stop the System
```bash
# Stop all containers (preserves data)
docker-compose stop
```

### Start After Stop
```bash
# Start existing containers
docker-compose start
```

### Complete Shutdown
```bash
# Stop and remove containers (keeps volumes)
docker-compose down
```

### Clean Reset
```bash
# Remove everything including stored data
docker-compose down -v
docker-compose up -d --build
```

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f master
docker-compose logs -f client
docker-compose logs -f chunk1
```

## 🔧 Troubleshooting

### Containers Not Starting

**Check logs:**
```bash
docker-compose logs
```

**Rebuild from scratch:**
```bash
docker-compose down -v
docker-compose up -d --build
```

### Port Already in Use

If you see port conflict errors, edit `docker-compose.yml`:
```yaml
# Change conflicting ports
ports:
  - "8080:8080"  # Change left number, e.g., "8081:8080"
```

### Cannot Access Dashboard

1. Verify containers are running: `docker-compose ps`
2. Check Docker Desktop is running
3. Try accessing: http://127.0.0.1:8080
4. Check firewall isn't blocking ports

### Upload Failures

1. Check all chunk servers are active in dashboard
2. Verify client container: `docker-compose ps client`
3. Check logs: `docker-compose logs client`
4. Restart client: `docker-compose restart client`

### Web Interface Not Loading

1. Check frontend container: `docker-compose logs frontend`
2. Verify `web/node_modules` exists (run `npm install` in web/ if missing)
3. Restart frontend: `docker-compose restart frontend`

## 🔒 Security Notes

**This is an educational simulation. For production:**
- Change default passwords
- Implement JWT authentication
- Use HTTPS/TLS encryption
- Add rate limiting
- Implement input validation
- Use secrets management

## 📚 Additional Features

### Creating Users
1. Login as admin
2. Click **+ Add User**
3. Enter username, password, select role
4. New user can login immediately

### Monitoring System Health
- Dashboard shows real-time metrics
- Active/failed servers
- Fault tolerance percentage
- File distribution across servers

### File Operations
- **Upload**: Automatic chunking and distribution
- **Download**: Automatic chunk reassembly
- **Delete**: Removes all chunks from servers
- **View**: See chunk distribution and metadata

## 📖 Documentation

- **Full Documentation**: See `readme.md`
- **API Reference**: See `readme.md` → API Endpoints section
- **Architecture**: See `readme.md` → Architecture section

## 💡 Tips

1. **First Upload**: Try small text files first
2. **Monitor**: Keep dashboard open to watch real-time activity
3. **Experiment**: Use "Simulate Failure" to test fault tolerance
4. **Logs**: Use `docker-compose logs -f` to debug issues

## 🆘 Need Help?

1. Check this file for common solutions
2. Review `readme.md` for detailed information
3. Check container logs: `docker-compose logs`
4. Verify all prerequisites are met
5. Try a clean restart: `docker-compose down -v && docker-compose up -d --build`

## 🎯 System Requirements

**Minimum:**
- 2 CPU cores
- 4 GB RAM
- 2 GB free disk space

**Recommended:**
- 4 CPU cores
- 8 GB RAM
- 5 GB free disk space

---

**Version**: 1.0  
**Last Updated**: November 2025  
**License**: Educational Use