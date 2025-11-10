import json
import time
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MASTER_URL = "http://master:8000"
CHUNK_SIZE = 1024 * 1024  
ENCRYPTION_KEY = None  

def generate_encryption_key(password="default_gfs_key"):
    """Generate encryption key from password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'gfs_salt_2024',  
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

def encrypt_data(data, cipher):
    if isinstance(data, str):
        data = data.encode()
    return cipher.encrypt(data)

def decrypt_data(encrypted_data, cipher):
    return cipher.decrypt(encrypted_data)

def upload_file(filename, content, encrypt=True, uploaded_by="unknown"):
    print(f"[CLIENT] ========== UPLOAD START ==========")
    print(f"[CLIENT] Starting upload: {filename} (Encryption: {encrypt}, User: {uploaded_by})")

    cipher = generate_encryption_key() if encrypt else None
    
    if isinstance(content, str):
        content_bytes = content.encode()
        print(f"[CLIENT] Converted string content to bytes: {len(content_bytes)} bytes")
    else:
        content_bytes = content
        print(f"[CLIENT] Using binary content: {len(content_bytes)} bytes")
    
    if encrypt:
        print(f"[CLIENT] Encrypting file...")
        try:
            content_bytes = encrypt_data(content_bytes, cipher)
            print(f"[CLIENT] Encryption successful, size: {len(content_bytes)} bytes")
        except Exception as e:
            print(f"[CLIENT] Encryption FAILED: {e}")
            return False

    try:
        data = json.dumps({
            "filename": filename,
            "filesize": len(content_bytes)
        }).encode()
        
        print(f"[CLIENT] Requesting chunk allocation from master...")
        print(f"[CLIENT] Master URL: {MASTER_URL}/allocate_chunks")
        
        req = urllib.request.Request(
            f"{MASTER_URL}/allocate_chunks",
            data=data,
            headers={"Content-Type": "application/json"}
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            allocation = json.loads(response.read().decode())
        
        print(f"[CLIENT] ✓ Received allocation for {len(allocation['allocations'])} chunks")
        print(f"[CLIENT] Allocation details: {allocation}")
    
    except Exception as e:
        print(f"[CLIENT] ✗ Failed to get allocation from master: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    successful_chunks = 0
    
    for alloc in allocation["allocations"]:
        chunk_id = alloc["chunk_id"]
        servers = alloc["servers"]
        index = alloc["index"]

        start = index * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, len(content_bytes))
        chunk_data = content_bytes[start:end]

        is_binary = not isinstance(content, str) or encrypt
        
        print(f"[CLIENT] Processing chunk {index}: {chunk_id} ({len(chunk_data)} bytes)")
        print(f"[CLIENT] Target servers: {servers}")
        
        success = False
        for server_id in servers:
            try:
                port_map = {
                    "chunk_server_1": 9001,
                    "chunk_server_2": 9002,
                    "chunk_server_3": 9003
                }
                port = port_map.get(server_id, 9001)
                
                upload_payload = {
                    "chunk_id": chunk_id,
                    "data": base64.b64encode(chunk_data).decode(),
                    "is_binary": is_binary,
                    "filename": filename
                }
                
                server_url = f"http://{server_id}:{port}/upload"
                print(f"[CLIENT] Uploading to {server_url}...")
                
                req = urllib.request.Request(
                    server_url,
                    data=json.dumps(upload_payload).encode(),
                    headers={"Content-Type": "application/json"}
                )
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    result = json.loads(response.read().decode())
                    print(f"[CLIENT] ✓ Uploaded {chunk_id} to {server_id}: {result}")
                    success = True
            
            except Exception as e:
                print(f"[CLIENT] ✗ Failed to upload {chunk_id} to {server_id}: {e}")
                import traceback
                traceback.print_exc()
        
        if success:
            successful_chunks += 1
            try:
                register_data = {
                    "filename": filename,
                    "chunk_id": chunk_id,
                    "servers": servers,
                    "uploaded_by": uploaded_by
                }
                
                print(f"[CLIENT] Registering chunk with master: {register_data}")
                
                data = json.dumps(register_data).encode()
                
                req = urllib.request.Request(
                    f"{MASTER_URL}/register_chunk",
                    data=data,
                    headers={"Content-Type": "application/json"}
                )
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    result = json.loads(response.read().decode())
                    print(f"[CLIENT] ✓ Registered {chunk_id} with Master - Response: {result}")
            
            except Exception as e:
                print(f"[CLIENT] ✗ Failed to register {chunk_id}: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"[CLIENT] ✗ Chunk {chunk_id} failed to upload to any server!")
        
        time.sleep(0.5)
    
    print(f"[CLIENT] ========== UPLOAD COMPLETE ==========")
    print(f"[CLIENT] File: {filename}, User: {uploaded_by}")
    print(f"[CLIENT] Success: {successful_chunks}/{len(allocation['allocations'])} chunks")
    
    return successful_chunks > 0

class ClientHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_OPTIONS(self):
        self._set_headers()
    
    def do_POST(self):
        if self.path == "/upload":
            self._handle_upload_request()
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
    
    def _handle_upload_request(self):
        """Handle upload request from web UI"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode()
        
        print(f"[CLIENT] Received upload request, content length: {content_length}")
        
        try:
            data = json.loads(body)
            filename = data.get("filename", "test_file.txt")
            content = data.get("content", "")
            content_b64 = data.get("content_base64", None)
            encrypt = data.get("encrypt", True)
            uploaded_by = data.get("uploaded_by", "unknown")
            
            print(f"[CLIENT] Upload request details:")
            print(f"  - Filename: {filename}")
            print(f"  - Uploaded by: {uploaded_by}")
            print(f"  - Encrypt: {encrypt}")
            print(f"  - Has content: {len(content) > 0}")
            print(f"  - Has base64 content: {content_b64 is not None}")
            
            if content_b64:
                content = base64.b64decode(content_b64)
                print(f"[CLIENT] Decoded base64 content, size: {len(content)} bytes")
            
            if not content:
                print(f"[CLIENT] ERROR: No content provided!")
                self._set_headers(400)
                self.wfile.write(json.dumps({
                    "success": False,
                    "error": "No content provided"
                }).encode())
                return
            
            print(f"[CLIENT] Starting file upload process...")
            success = upload_file(filename, content, encrypt, uploaded_by)
            print(f"[CLIENT] Upload process result: {success}")
            
            response_data = {
                "success": success,
                "filename": filename,
                "size": len(content) if isinstance(content, (bytes, str)) else 0,
                "encrypted": encrypt,
                "uploaded_by": uploaded_by
            }
            
            print(f"[CLIENT] Sending response: {response_data}")
            
            self._set_headers()
            self.wfile.write(json.dumps(response_data).encode())
        
        except Exception as e:
            print(f"[CLIENT] EXCEPTION in upload handler: {e}")
            import traceback
            traceback.print_exc()
            self._set_headers(500)
            self.wfile.write(json.dumps({
                "success": False,
                "error": str(e)
            }).encode())
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

def main():
    server = HTTPServer(('0.0.0.0', 8001), ClientHandler)
    print("[CLIENT] Client service started on port 8001")
    print("[CLIENT] Encryption enabled for all uploads")
    server.serve_forever()

if __name__ == "__main__":
    main()