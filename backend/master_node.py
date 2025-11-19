import json
import os
import time
import threading
import hashlib
import secrets
import base64
import socketserver
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
import urllib.request

HEARTBEAT_TIMEOUT = 15
REPLICATION_FACTOR = 2
CHUNK_SIZE = 1024 * 1024
DATA_DIR = "/data/master"
METADATA_FILE = f"{DATA_DIR}/chunks.json"
USERS_FILE = f"{DATA_DIR}/users.json"
SESSIONS_FILE = f"{DATA_DIR}/sessions.json"
SERVERS_FILE = f"{DATA_DIR}/servers.json"

chunk_servers = {}
metadata = {"files": {}, "chunks": {}}
users = {}
sessions = {}
heartbeat_lock = threading.RLock()
metadata_lock = threading.RLock()
session_lock = threading.RLock()

os.makedirs(DATA_DIR, exist_ok=True)

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

def save_metadata():
    with metadata_lock:
        with open(METADATA_FILE, 'w') as f:
            json.dump(metadata, f, indent=2)

def save_users():
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def save_sessions():
    with session_lock:
        with open(SESSIONS_FILE, 'w') as f:
            json.dump(sessions, f, indent=2)

def save_servers():
    with heartbeat_lock:
        with open(SERVERS_FILE, 'w') as f:
            json.dump(chunk_servers, f, indent=2)

def register_chunk_server(server_id, host, port):
    with heartbeat_lock:
        chunk_servers[server_id] = {
            "host": host,
            "port": port,
            "last_heartbeat": time.time(),
            "status": "active"
        }
        save_servers()
    print(f"[MASTER] Registered chunk server: {server_id}")

def clean_expired_sessions():
    with session_lock:
        current_time = time.time()
        expired = [token for token, info in sessions.items() 
                   if 'created_at' in info and current_time - info['created_at'] > 86400]
        for token in expired:
            del sessions[token]

def check_heartbeats():
    while True:
        time.sleep(5)
        current_time = time.time()
        
        with heartbeat_lock:
            changed = False
            for server_id, info in chunk_servers.items():
                if info["status"] == "active":
                    if current_time - info["last_heartbeat"] > HEARTBEAT_TIMEOUT:
                        info["status"] = "failed"
                        print(f"[MASTER] Server {server_id} marked as FAILED")
                        changed = True
            
            if changed:
                save_servers()
        
        clean_expired_sessions()

def re_replicate_chunks(failed_server):
    print(f"[MASTER] Re-replication disabled for {failed_server}")

class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

class MasterHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200, content_type='application/json'):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_OPTIONS(self):
        try:
            self._set_headers()
        except Exception as e:
            print(f"[MASTER ERROR] do_OPTIONS exception: {e}")
    
    def do_GET(self):
        try:
            print(f"[MASTER] GET request: {self.path}")
            if self.path == "/status":
                self._handle_status()
            elif self.path == "/users":
                self._handle_get_users()
            elif self.path.startswith("/download/"):
                self._handle_download()
            else:
                print(f"[MASTER] Path not matched: {self.path}")
                self._set_headers(404)
                self.wfile.write(json.dumps({"error": "Not found"}).encode())
        except Exception as e:
            print(f"[MASTER ERROR] do_GET exception: {e}")
            import traceback
            traceback.print_exc()
            try:
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            except:
                pass
    
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode() if content_length > 0 else '{}'
            
            try:
                data = json.loads(body) if body else {}
            except:
                data = {}
            
            if self.path == "/heartbeat":
                self._handle_heartbeat(data)
            elif self.path == "/allocate_chunks":
                self._handle_allocate_chunks(data)
            elif self.path == "/register_chunk":
                self._handle_register_chunk(data)
            elif self.path == "/login":
                self._handle_login(data)
            elif self.path == "/signup":
                self._handle_signup(data)
            elif self.path == "/logout":
                self._handle_logout(data)
            elif self.path == "/create_user":
                self._handle_create_user(data)
            elif self.path == "/promote_user":
                self._handle_promote_user(data)
            elif self.path == "/demote_user":
                self._handle_demote_user(data)
            elif self.path == "/simulate_failure":
                self._handle_simulate_failure(data)
            elif self.path == "/delete_file":
                self._handle_delete_file(data)
            else:
                self._set_headers(404)
                self.wfile.write(json.dumps({"error": "Not found"}).encode())
        except Exception as e:
            print(f"[MASTER ERROR] do_POST exception: {e}")
            import traceback
            traceback.print_exc()
            try:
                self._set_headers(500)
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            except:
                pass
    
    def _handle_heartbeat(self, data):
        server_id = data.get("server_id")
        host = data.get("host")
        port = data.get("port")
        
        if not all([server_id, host, port]):
            self._set_headers(400)
            self.wfile.write(json.dumps({"error": "Missing parameters"}).encode())
            return
        
        register_chunk_server(server_id, host, port)
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True, "server_id": server_id}).encode())
    
    def _handle_allocate_chunks(self, data):
        filename = data.get("filename")
        filesize = data.get("filesize", 0)
        
        num_chunks = (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE
        
        with heartbeat_lock:
            active_servers = [sid for sid, info in chunk_servers.items() 
                             if info["status"] == "active"]
        
        if len(active_servers) < REPLICATION_FACTOR:
            self._set_headers(503)
            self.wfile.write(json.dumps({
                "error": "Insufficient servers",
                "active": len(active_servers),
                "required": REPLICATION_FACTOR
            }).encode())
            return
        
        allocations = []
        for i in range(num_chunks):
            chunk_id = f"{filename}_chunk_{i}_{secrets.token_hex(8)}"
            
            import random
            selected_servers = random.sample(active_servers, 
                                            min(REPLICATION_FACTOR, len(active_servers)))
            
            allocations.append({
                "chunk_id": chunk_id,
                "index": i,
                "servers": selected_servers
            })
        
        self._set_headers()
        self.wfile.write(json.dumps({
            "success": True,
            "allocations": allocations
        }).encode())
    
    def _handle_register_chunk(self, data):
        filename = data.get("filename")
        chunk_id = data.get("chunk_id")
        servers = data.get("servers", [])
        uploaded_by = data.get("uploaded_by", "unknown")
        
        with metadata_lock:
            if filename not in metadata["files"]:
                metadata["files"][filename] = {
                    "chunks": [],
                    "upload_time": time.time(),
                    "uploaded_by": uploaded_by
                }
            
            if chunk_id not in metadata["files"][filename]["chunks"]:
                metadata["files"][filename]["chunks"].append(chunk_id)
            
            metadata["chunks"][chunk_id] = {
                "filename": filename,
                "servers": servers,
                "created_at": time.time()
            }
            
            save_metadata()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_status(self):
        with heartbeat_lock:
            servers_copy = dict(chunk_servers)
        
        with metadata_lock:
            files_copy = dict(metadata["files"])
        
        active_count = sum(1 for s in servers_copy.values() if s["status"] == "active")
        total_count = len(servers_copy)
        fault_tolerance = (active_count / total_count * 100) if total_count > 0 else 0
        
        self._set_headers()
        self.wfile.write(json.dumps({
            "servers": servers_copy,
            "files": files_copy,
            "fault_tolerance": int(fault_tolerance)
        }).encode())
    
    def _handle_login(self, data):
        username = data.get("username")
        password = data.get("password")
        
        if username not in users:
            self._set_headers(401)
            self.wfile.write(json.dumps({
                "success": False,
                "error": "Invalid credentials"
            }).encode())
            return
        
        hashed = hashlib.sha256(password.encode()).hexdigest()
        if users[username]["password"] != hashed:
            self._set_headers(401)
            self.wfile.write(json.dumps({
                "success": False,
                "error": "Invalid credentials"
            }).encode())
            return
        
        token = secrets.token_urlsafe(32)
        with session_lock:
            sessions[token] = {
                "username": username,
                "role": users[username]["role"],
                "created_at": time.time()
            }
            save_sessions()
        
        self._set_headers()
        self.wfile.write(json.dumps({
            "success": True,
            "token": token,
            "role": users[username]["role"]
        }).encode())
    
    def _handle_signup(self, data):
        username = data.get("username")
        password = data.get("password")
        
        if username in users:
            self._set_headers(400)
            self.wfile.write(json.dumps({
                "success": False,
                "error": "Username already exists"
            }).encode())
            return
        
        users[username] = {
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "role": "user",
            "created_by": "self"
        }
        save_users()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_logout(self, data):
        token = data.get("token")
        with session_lock:
            if token in sessions:
                del sessions[token]
                save_sessions()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_get_users(self):
        user_list = [
            {
                "username": username,
                "role": info["role"],
                "created_by": info.get("created_by", "unknown")
            }
            for username, info in users.items()
        ]
        
        self._set_headers()
        self.wfile.write(json.dumps({"users": user_list}).encode())
    
    def _handle_create_user(self, data):
        username = data.get("username")
        password = data.get("password")
        role = data.get("role", "user")
        created_by = data.get("created_by", "unknown")
        
        if username in users:
            self._set_headers(400)
            self.wfile.write(json.dumps({
                "success": False,
                "error": "Username already exists"
            }).encode())
            return
        
        users[username] = {
            "password": hashlib.sha256(password.encode()).hexdigest(),
            "role": role,
            "created_by": created_by
        }
        save_users()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_promote_user(self, data):
        username = data.get("username")
        
        if username not in users or users[username]["role"] != "user":
            self._set_headers(400)
            self.wfile.write(json.dumps({"success": False}).encode())
            return
        
        users[username]["role"] = "manager"
        save_users()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_demote_user(self, data):
        username = data.get("username")
        
        if username not in users or users[username]["role"] != "manager":
            self._set_headers(400)
            self.wfile.write(json.dumps({"success": False}).encode())
            return
        
        users[username]["role"] = "user"
        save_users()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_simulate_failure(self, data):
        server_id = data.get("server_id")
        
        if server_id not in chunk_servers:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Server not found"}).encode())
            return
        
        with heartbeat_lock:
            chunk_servers[server_id]["status"] = "failed"
            chunk_servers[server_id]["last_heartbeat"] = 0
            save_servers()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def _handle_download(self):
        import urllib.parse
        filename = urllib.parse.unquote(self.path.split('/')[-1])
        print(f"[MASTER] Download request for: {filename}")
        
        with metadata_lock:
            if filename not in metadata["files"]:
                self._set_headers(404)
                self.wfile.write(json.dumps({
                    "success": False,
                    "error": "File not found"
                }).encode())
                return
            
            file_info = metadata["files"][filename]
            chunk_ids = file_info["chunks"]
        
        # Download all chunks
        chunks_data = []
        for chunk_id in sorted(chunk_ids):
            chunk_info = metadata["chunks"].get(chunk_id, {})
            servers = chunk_info.get("servers", [])
            
            chunk_data = None
            for server_id in servers:
                try:
                    server_info = chunk_servers.get(server_id, {})
                    if server_info.get("status") != "active":
                        continue
                    
                    hostname_map = {
                        "chunk_server_1": "chunk1",
                        "chunk_server_2": "chunk2",
                        "chunk_server_3": "chunk3"
                    }
                    hostname = hostname_map.get(server_id, server_id)
                    port = server_info.get("port", 9001)
                    encoded_chunk_id = urllib.parse.quote(chunk_id)
                    url = f"http://{hostname}:{port}/download/{encoded_chunk_id}"
                    
                    print(f"[MASTER] Downloading {chunk_id} from {url}")
                    req = urllib.request.Request(url)
                    with urllib.request.urlopen(req, timeout=10) as response:
                        result = json.loads(response.read().decode())
                        chunk_data = result.get("data")
                        is_binary = result.get("is_binary", False)
                        
                        if is_binary:
                            chunk_data = base64.b64decode(chunk_data)
                        else:
                            chunk_data = chunk_data.encode()
                        
                        print(f"[MASTER] Successfully downloaded {chunk_id}")
                        break
                except Exception as e:
                    print(f"[MASTER] Failed to download {chunk_id} from {server_id}: {e}")
                    import traceback
                    traceback.print_exc()
                    continue
            
            if chunk_data is None:
                self._set_headers(500)
                self.wfile.write(json.dumps({
                    "success": False,
                    "error": f"Failed to download chunk {chunk_id}"
                }).encode())
                return
            
            chunks_data.append(chunk_data)
        
        # Combine chunks
        file_content = b''.join(chunks_data)
        file_content_b64 = base64.b64encode(file_content).decode()
        
        self._set_headers()
        self.wfile.write(json.dumps({
            "success": True,
            "filename": filename,
            "data": file_content_b64,
            "is_binary": True
        }).encode())
    
    def _handle_delete_file(self, data):
        filename = data.get("filename")
        
        with metadata_lock:
            if filename not in metadata["files"]:
                self._set_headers(404)
                self.wfile.write(json.dumps({
                    "success": False,
                    "error": "File not found"
                }).encode())
                return
            
            # Get chunks to delete
            chunk_ids = metadata["files"][filename]["chunks"]
            
            # Delete from metadata
            del metadata["files"][filename]
            for chunk_id in chunk_ids:
                if chunk_id in metadata["chunks"]:
                    del metadata["chunks"][chunk_id]
            
            save_metadata()
        
        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    
    def log_message(self, format, *args):
        # Suppress default HTTP logging to reduce noise
        pass

def autosave_state():
    while True:
        save_metadata()
        save_users()
        save_sessions()
        save_servers()
        time.sleep(60)

def main():
    load_data()
    threading.Thread(target=check_heartbeats, daemon=True).start()
    threading.Thread(target=autosave_state, daemon=True).start()
    
    server = ThreadedHTTPServer(('0.0.0.0', 8000), MasterHandler)
    print("[MASTER] Master Node started on port 8000")
    print(f"[MASTER] Loaded {len(users)} users, {len(metadata['files'])} files")
    server.serve_forever()

if __name__ == "__main__":
    main()