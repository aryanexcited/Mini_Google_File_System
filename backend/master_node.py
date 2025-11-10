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
heartbeat_lock = threading.Lock()
metadata_lock = threading.Lock()
session_lock = threading.Lock()

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

def save_servers():
    """Persist chunk server states"""
    with heartbeat_lock:
        with open(SERVERS_FILE, 'w') as f:
            json.dump(chunk_servers, f, indent=2)

   
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

def register_chunk_server(server_id, host, port):
    """Register or update a chunk server"""
    with heartbeat_lock:
        chunk_servers[server_id] = {
            "host": host,
            "port": port,
            "last_heartbeat": time.time(),
            "status": "active"
        }
        
        save_servers()
    print(f"[MASTER] Registered chunk server: {server_id}")


def check_heartbeats():
    """Monitor chunk server heartbeats and detect failures"""
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
                        threading.Thread(
                            target=re_replicate_chunks, args=(server_id,), daemon=True
                        ).start()

            
            if changed:
                save_servers()

        clean_expired_sessions()


class MasterHandler(BaseHTTPRequestHandler):
    ...
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
            
            save_servers()

        threading.Thread(target=re_replicate_chunks, args=(server_id,), daemon=True).start()

        self._set_headers()
        self.wfile.write(json.dumps({"success": True}).encode())
    ...


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

    
    threading.Thread(target=check_heartbeats, daemon=True).start()

   
    threading.Thread(target=autosave_state, daemon=True).start()

    
    server = ThreadedHTTPServer(('0.0.0.0', 8000), MasterHandler)
    print("[MASTER] Master Node started on port 8000 (threaded)")
    print("[MASTER] Re-replication disabled")
    server.serve_forever()

if __name__ == "__main__":
    main()
