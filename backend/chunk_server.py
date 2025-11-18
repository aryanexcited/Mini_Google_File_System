import json
import os
import sys
import time
import threading
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error

MASTER_URL = "http://master:8000"
HEARTBEAT_INTERVAL = 5  
DATA_DIR = "/data/chunks"

SERVER_ID = os.environ.get("SERVER_ID", "chunk_server_1")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "9001"))

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(f"{DATA_DIR}/text", exist_ok=True)
os.makedirs(f"{DATA_DIR}/images", exist_ok=True)
os.makedirs(f"{DATA_DIR}/documents", exist_ok=True)
os.makedirs(f"{DATA_DIR}/other", exist_ok=True)

def get_file_category(filename):
    """Determine file category based on extension"""
    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    
    if ext in ['txt', 'log', 'md', 'json', 'xml', 'csv']:
        return 'text'
    elif ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp']:
        return 'images'
    elif ext in ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']:
        return 'documents'
    else:
        return 'other'

def send_heartbeat():
    """Send periodic heartbeat to master"""
    while True:
        try:
            data = json.dumps({
                "server_id": SERVER_ID,
                "host": SERVER_ID,
                "port": SERVER_PORT
            }).encode()
            
            req = urllib.request.Request(
                f"{MASTER_URL}/heartbeat",
                data=data,
                headers={"Content-Type": "application/json"}
            )
            
            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode())
                print(f"[{SERVER_ID}] Heartbeat sent: {result}")
        
        except Exception as e:
            print(f"[{SERVER_ID}] Heartbeat failed: {e}")
        
        time.sleep(HEARTBEAT_INTERVAL)

class ChunkServerHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200, content_type='application/json'):
        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_OPTIONS(self):
        self._set_headers()
    
    def do_POST(self):
        if self.path == "/upload":
            self._handle_upload()
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
    
    def do_GET(self):
        if self.path.startswith("/download/"):
            self._handle_download()
        elif self.path == "/health":
            self._handle_health()
        elif self.path == "/storage":
            self._handle_storage_info()
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
    
    def _handle_upload(self):
        """Handle chunk upload with binary support"""
        content_length = int(self.headers.get('Content-Length', 0))
        content_type = self.headers.get('Content-Type', '')
        
        try:
            if 'application/json' in content_type:
                body = self.rfile.read(content_length).decode()
                data = json.loads(body)
                
                chunk_id = data.get('chunk_id')
                chunk_data_b64 = data.get('data')
                is_binary = data.get('is_binary', False)
                filename = data.get('filename', '')
                
                if not chunk_id:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Missing chunk_id"}).encode())
                    return
                
                category = get_file_category(filename)
                chunk_path = os.path.join(DATA_DIR, category, chunk_id)
                
                if is_binary:
                    chunk_data = base64.b64decode(chunk_data_b64)
                    with open(chunk_path, 'wb') as f:
                        f.write(chunk_data)
                else:
                    with open(chunk_path, 'w') as f:
                        f.write(chunk_data_b64)
                
                print(f"[{SERVER_ID}] Stored chunk: {chunk_id} in {category}/")
                
            else:
                body = self.rfile.read(content_length).decode()
                parts = body.split('&')
                chunk_id = None
                chunk_data = None
                
                for part in parts:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        if key == 'chunk_id':
                            chunk_id = value
                        elif key == 'data':
                            chunk_data = value
                
                if not chunk_id:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({"error": "Missing chunk_id"}).encode())
                    return
                
                chunk_path = os.path.join(DATA_DIR, 'text', chunk_id)
                with open(chunk_path, 'w') as f:
                    f.write(chunk_data or "")
                
                print(f"[{SERVER_ID}] Stored chunk: {chunk_id}")
            
            self._set_headers()
            self.wfile.write(json.dumps({
                "success": True,
                "chunk_id": chunk_id,
                "server_id": SERVER_ID,
                "category": category if 'filename' in locals() else 'text'
            }).encode())
        
        except Exception as e:
            print(f"[{SERVER_ID}] Upload error: {e}")
            self._set_headers(500)
            self.wfile.write(json.dumps({"error": str(e)}).encode())
    
    def _handle_download(self):
        chunk_id = self.path.split('/')[-1]
        
        # Search in all categories
        chunk_path = None
        for category in ['text', 'images', 'documents', 'other']:
            test_path = os.path.join(DATA_DIR, category, chunk_id)
            if os.path.exists(test_path):
                chunk_path = test_path
                break
        
        if not chunk_path:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Chunk not found"}).encode())
            return
        
        try:
            with open(chunk_path, 'r') as f:
                data = f.read()
            is_binary = False
        except:
            with open(chunk_path, 'rb') as f:
                data = base64.b64encode(f.read()).decode()
            is_binary = True
        
        self._set_headers()
        self.wfile.write(json.dumps({
            "chunk_id": chunk_id,
            "data": data,
            "is_binary": is_binary
        }).encode())
    
    def _handle_health(self):
        """Health check endpoint"""
        chunk_counts = {}
        total_chunks = 0
        
        for category in ['text', 'images', 'documents', 'other']:
            cat_path = os.path.join(DATA_DIR, category)
            count = len(os.listdir(cat_path)) if os.path.exists(cat_path) else 0
            chunk_counts[category] = count
            total_chunks += count
        
        self._set_headers()
        self.wfile.write(json.dumps({
            "server_id": SERVER_ID,
            "status": "active",
            "chunks_stored": total_chunks,
            "chunks_by_category": chunk_counts
        }).encode())
    
    def _handle_storage_info(self):
        """Return detailed storage information"""
        storage_info = {
            "server_id": SERVER_ID,
            "categories": {}
        }
        
        for category in ['text', 'images', 'documents', 'other']:
            cat_path = os.path.join(DATA_DIR, category)
            if os.path.exists(cat_path):
                files = os.listdir(cat_path)
                storage_info["categories"][category] = {
                    "count": len(files),
                    "files": files[:20]  # Limit to 20 for performance
                }
        
        self._set_headers()
        self.wfile.write(json.dumps(storage_info).encode())
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

def main():
    # Start heartbeat thread
    threading.Thread(target=send_heartbeat, daemon=True).start()
    
    # Start HTTP server
    server = HTTPServer(('0.0.0.0', SERVER_PORT), ChunkServerHandler)
    print(f"[{SERVER_ID}] Chunk Server started on port {SERVER_PORT}")
    print(f"[{SERVER_ID}] Storage organized in: text/, images/, documents/, other/")
    server.serve_forever()

if __name__ == "__main__":
    main()