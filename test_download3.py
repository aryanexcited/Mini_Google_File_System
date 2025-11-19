import http.client
import json
import urllib.parse

filename = "Screenshot 2025-09-18 220426.png"
encoded_filename = urllib.parse.quote(filename)

print(f"Testing download: {filename}")

conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=30)
conn.request("GET", f"/download/{encoded_filename}")
response = conn.getresponse()

print(f"Status: {response.status}")

if response.status == 200:
    data = json.loads(response.read())
    print(f"Success: {data.get('success')}")
    print(f"Data length: {len(data.get('data', ''))}")
    print("DOWNLOAD WORKS!")
else:
    print(f"Body: {response.read().decode()}")

conn.close()
