import json
import os
import time
import threading
import hashlib
import secrets
import socketserver
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta

# Configuration
HEARTBEAT_TIMEOUT = 15  # seconds
REPLICATION_FACTOR = 2
CHUNK_SIZE = 1024 * 1024  # 1MB

# Use project root directory for data storage
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data", "master")
METADATA_FILE = os.path.join(DATA_DIR, "chunks.json")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
SESSIONS_FILE = os.path.join(DATA_DIR, "sessions.json")
SERVERS_FILE = os.path.join(DATA_DIR, "servers.json")

chunk_servers = {}
metadata = {"files": {}, "chunks": {}}
users = {}
sessions = {}
heartbeat_lock = threading.Lock()
metadata_lock = threading.Lock()
session_lock = threading.Lock()

# Initialize data directory
os.makedirs(DATA_DIR, exist_ok=True)

# Create a threaded HTTP server class
class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True

def load_data():
    global metadata, users, sessions, chunk_servers
    
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, 'r') as f:
            metadata = json.load(f)
    
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            users_data = json.load(f)
            users.update(users_data)
    else:
        users["admin"] = {
            "password": hashlib.sha256("admin123".encode()).hexdigest(),
            "role": "admin",
            "created_by": "system"
        }
        save_users()
    
    if os.path.exists(SESSIONS_FILE):
        with open(SESSIONS_FILE, 'r') as f:
            sessions.update(json.load(f))
        clean_expired_sessions()
    
    if os.path.exists(SERVERS_FILE):
        with open(SERVERS_FILE, 'r') as f:
            chunk_servers.update(json.load(f))
    else:
        chunk_servers.clear()

def save_servers():
    """Persist chunk server states"""
    with heartbeat_lock:
        with open(SERVERS_FILE, 'w') as f:
            json.dump(chunk_servers, f, indent=2)

def save_metadata():
    """Save metadata to disk"""
    with metadata_lock:
        with open(METADATA_FILE, 'w') as f:
            json.dump(metadata, f, indent=2)

def save_users():
    """Save users to disk"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def save_sessions():
    """Save sessions to disk"""
    with session_lock:
        with open(SESSIONS_FILE, 'w') as f:
            json.dump(sessions, f, indent=2)

def create_session(username, role):
    """Create a new session token"""
    token = secrets.token_urlsafe(32)
    expiry = (datetime.now() + timedelta(hours=24)).isoformat()
    
    with session_lock:
        sessions[token] = {
            "username": username,
            "role": role,
            "expiry": expiry
        }
        with open(SESSIONS_FILE, 'w') as f:
            json.dump(sessions, f, indent=2)
    
    return token

def validate_session(token):
    """Validate session token"""
    with session_lock:
        if token not in sessions:
            return None
        
        session = sessions[token]
        expiry = datetime.fromisoformat(session["expiry"])
        
        if datetime.now() > expiry:
            del sessions[token]
            with open(SESSIONS_FILE, 'w') as f:
                json.dump(sessions, f, indent=2)
            return None
        
        return session

def clean_expired_sessions():
    """Remove expired sessions"""
    with session_lock:
        now = datetime.now()
        expired = [token for token, session in sessions.items()
                  if datetime.fromisoformat(session["expiry"]) < now]
        
        for token in expired:
            del sessions[token]
        
        if expired:
            with open(SESSIONS_FILE, 'w') as f:
                json.dump(sessions, f, indent=2)

def register_chunk_server(server_id, host, port):
    """Register or update a chunk server"""
    with heartbeat_lock:
        chunk_servers[server_id] = {
            "host": host,
            "port": port,
            "last_heartbeat": time.time(),
            "status": "active"
        }
    print(f"[MASTER] Registered chunk server: {server_id}")

def check_heartbeats():
    """Monitor chunk server heartbeats and detect failures"""
    while True:
        time.sleep(5)
        current_time = time.time()
        
        with heartbeat_lock:
            for server_id, info in chunk_servers.items():
                if info["status"] == "active":
                    if current_time - info["last_heartbeat"] > HEARTBEAT_TIMEOUT:
                        info["status"] = "failed"
                        print(f"[MASTER] Server {server_id} marked as FAILED")
                        # Removed re-replication thread
        
        # Clean expired sessions periodically
        clean_expired_sessions()

class MasterHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    def do_OPTIONS(self):
        self._set_headers()
    
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        
        if path == "/status":
            self._handle_status()
        elif path == "/users":
            self._handle_get_users()
        elif path == "/logs":
            self._handle_logs()
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
    
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else "{}"
        
        try:
            data = json.loads(body)
        except:
            data = {}
        
        if path == "/heartbeat":
            self._handle_heartbeat(data)
        elif path == "/login":
            self._handle_login(data)
        elif path == "/logout":
            self._handle_logout(data)
        elif path == "/signup":
            self._handle_signup(data)
        elif path == "/create_user":
            self._handle_create_user(data)
        elif path == "/promote_user":
            self._handle_promote_user(data)
        elif path == "/demote_user":
            self._handle_demote_user(data)
        elif path == "/allocate_chunks":
            self._handle_allocate_chunks(data)
        elif path == "/register_chunk":
            self._handle_register_chunk(data)
        elif path == "/simulate_failure":
            self._handle_simulate_failure(data)
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
    
    def _handle_status(self):
        """Return system status"""
        with heartbeat_lock:
            servers_status = {sid: {
                "status": info["status"],
                "last_heartbeat": info["last_heartbeat"],
                "host": info["host"],
                "port": info["port"]
            } for sid, info in chunk_servers.items()}
        
        with metadata_lock:
            files_info = metadata["files"]
            chunks_info = metadata["chunks"]
        
        active_count = sum(1 for s in chunk_servers.values() if s["status"] == "active")
        total_count = len(chunk_servers)
        fault_tolerance = (active_count / total_count * 100) if total_count > 0 else 0
        
        response = {
            "servers": servers_status,
            "files": files_info,
            "chunks": chunks_info,
            "fault_tolerance": round(fault_tolerance, 2),
            "timestamp": datetime.now().isoformat()
        }
        
        self._set_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def _handle_heartbeat(self, data):
        """Handle heartbeat from chunk server"""
        server_id = data.get("server_id")
        host = data.get("host", "unknown")
        port = data.get("port", 0)
        
        if server_id:
            register_chunk_server(server_id, host, port)
            self._set_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode())
        else:
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": "Missing server_id"}).encode())
    
    def _handle_login(self, data):
        """Authenticate user and create session"""
        print(f"[MASTER] Login request received for user: {data.get('username')}")
        username = data.get("username")
        password = data.get("password")
        
        if not username or not password:
            print("[MASTER] Login failed: Missing credentials")
            self._set_headers(400)
            self.wfile.write(json.dumps({"success": False, "error": "Missing credentials"}).encode())
            return
        
        print(f"[MASTER] Hashing password for {username}")
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        print(f"[MASTER] Checking credentials for {username}")
        
        if username in users and users[username]["password"] == password_hash:
            print(f"[MASTER] Credentials valid, creating session for {username}")
            token = create_session(username, users[username]["role"])
            print(f"[MASTER] Session created, sending response")
            
            self._set_headers()
            self.wfile.write(json.dumps({
                "success": True,
                "role": users[username]["role"],
                "username": username,
                "token": token
            }).encode())
            print(f"[MASTER] Login successful for {username}")
        else:
            print(f"[MASTER] Login failed: Invalid credentials for {username}")
            self._set_headers(401)
            self.wfile.write(json.dumps({"success": False, "error": "Invalid credentials"}).encode())
    
    def _handle_logout(self, data):
        """Logout user and invalidate session"""
        token = data.get("token")
        
        if token:
            with session_lock:
                if token in sessions:
                    del sessions[token]
                    with open(SESSIONS_FILE, 'w') as f:
                        json.dump(sessions, f, indent=2)
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_signup(self, data):
        """Public signup - creates basic user account"""
        username = data.get("username")
        password = data.get("password")
        
        if not username or not password:
            self._set_headers(400)
            self.wfile.write(json.dumps({"success": False, "error": "Missing credentials"}).encode())
            return
        
        if username in users:
            self._set_headers(400)
            self.wfile.write(json.dumps({"success": False, "error": "Username already exists"}).encode())
            return
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        users[username] = {
            "password": password_hash,
            "role": "user",
            "created_by": "self",
            "created_at": datetime.now().isoformat()
        }
        save_users()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True, "message": "Account created successfully"}).encode())
    
    def _handle_get_users(self):
        """Get all users (admin only)"""
        user_list = [{
            "username": username,
            "role": info["role"],
            "created_by": info.get("created_by", "unknown")
        } for username, info in users.items()]
        
        self._set_headers()
        self.wfile.write(json.dumps({"users": user_list}).encode())
    
    def _handle_create_user(self, data):
        """Create new user (admin/manager only)"""
        username = data.get("username")
        password = data.get("password")
        role = data.get("role", "user")
        created_by = data.get("created_by", "admin")
        
        if username in users:
            self._set_headers(400)
            self.wfile.write(json.dumps({"success": False, "error": "User exists"}).encode())
            return
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        users[username] = {
            "password": password_hash,
            "role": role,
            "created_by": created_by,
            "created_at": datetime.now().isoformat()
        }
        save_users()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_promote_user(self, data):
        """Promote user to manager"""
        username = data.get("username")
        
        if username not in users:
            self._set_headers(404)
            self.wfile.write(json.dumps({"success": False, "error": "User not found"}).encode())
            return
        
        users[username]["role"] = "manager"
        save_users()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_demote_user(self, data):
        """Demote manager to user"""
        username = data.get("username")
        
        if username not in users:
            self._set_headers(404)
            self.wfile.write(json.dumps({"success": False, "error": "User not found"}).encode())
            return
        
        if users[username]["role"] != "manager":
            self._set_headers(400)
            self.wfile.write(json.dumps({"success": False, "error": "User is not a manager"}).encode())
            return
        
        users[username]["role"] = "user"
        save_users()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_allocate_chunks(self, data):
        """Allocate chunks for a file upload"""
        filename = data.get("filename")
        filesize = data.get("filesize", 0)
        
        num_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE
        
        with heartbeat_lock:
            active_servers = [sid for sid, info in chunk_servers.items() 
                            if info["status"] == "active"]
        
        if not active_servers:
            self._set_headers(503)
            self.wfile.write(json.dumps({"error": "No active servers"}).encode())
            return
        
        allocations = []
        for i in range(num_chunks):
            chunk_id = f"{filename}_chunk_{i}"
            servers = [active_servers[j % len(active_servers)] 
                      for j in range(i, i + min(REPLICATION_FACTOR, len(active_servers)))]
            allocations.append({
                "chunk_id": chunk_id,
                "servers": servers,
                "index": i
            })
        
        self._set_headers()
        self.wfile.write(json.dumps({"allocations": allocations}).encode())
    
    def _handle_register_chunk(self, data):
        """Register completed chunk upload"""
        filename = data.get("filename")
        chunk_id = data.get("chunk_id")
        servers = data.get("servers", [])
        uploaded_by = data.get("uploaded_by", "unknown")
        
        with metadata_lock:
            if filename not in metadata["files"]:
                metadata["files"][filename] = {
                    "chunks": [],
                    "upload_time": datetime.now().isoformat(),
                    "uploaded_by": uploaded_by
                }
            else:
                # Update uploaded_by even if file exists (in case it wasn't set)
                if "uploaded_by" not in metadata["files"][filename]:
                    metadata["files"][filename]["uploaded_by"] = uploaded_by
            
            # Only add chunk if not already present
            if chunk_id not in metadata["files"][filename]["chunks"]:
                metadata["files"][filename]["chunks"].append(chunk_id)
            
            metadata["chunks"][chunk_id] = {
                "servers": servers,
                "filename": filename
            }
            save_metadata()
        
        print(f"[MASTER] Registered chunk {chunk_id} for file {filename} by user {uploaded_by}")
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_simulate_failure(self, data):
        """Simulate server failure (without re-replication)"""
        server_id = data.get("server_id")
        
        if server_id not in chunk_servers:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Server not found"}).encode())
            return
        
        with heartbeat_lock:
            chunk_servers[server_id]["status"] = "failed"
            chunk_servers[server_id]["last_heartbeat"] = 0
        
        # Removed re-replication call
        print(f"[MASTER] Server {server_id} marked as failed (re-replication disabled)")
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_logs(self):
        """Return system logs"""
        logs = []
        
        with heartbeat_lock:
            for sid, info in chunk_servers.items():
                logs.append({
                    "timestamp": datetime.fromtimestamp(info["last_heartbeat"]).isoformat(),
                    "server": sid,
                    "event": f"Status: {info['status']}"
                })
        
        self._set_headers()
        self.wfile.write(json.dumps({"logs": logs[-50:]}).encode())
    
    def log_message(self, format, *args):
        """Log HTTP requests"""
        print(f"[MASTER] {self.address_string()} - {format % args}")

def autosave_state():
    """Periodically save all runtime data"""
    while True:
        save_metadata()
        save_users()
        save_sessions()
        save_servers()
        time.sleep(60)

def main():
    load_data()
    
    # Print storage location for user reference
    print(f"[MASTER] Data directory: {DATA_DIR}")
    print(f"[MASTER] Metadata file: {METADATA_FILE}")
    
    # Start heartbeat monitor
    threading.Thread(target=check_heartbeats, daemon=True).start()
    
    # Start autosave thread
    threading.Thread(target=autosave_state, daemon=True).start()
    
    # Start HTTP server with threading support
    server = ThreadedHTTPServer(('0.0.0.0', 8000), MasterHandler)
    print("[MASTER] Master Node started on port 8000 (threaded)")
    print("[MASTER] Re-replication disabled")
    server.serve_forever()

if __name__ == "__main__":
    main()