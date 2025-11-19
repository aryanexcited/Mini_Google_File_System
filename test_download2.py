import http.client
import json
import urllib.parse

filename = "Screenshot 2025-05-06 204054.png"
encoded_filename = urllib.parse.quote(filename)

print(f"Testing download: {filename}")
print(f"Encoded: {encoded_filename}")

conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=30)
conn.request("GET", f"/download/{encoded_filename}")
response = conn.getresponse()

print(f"Status: {response.status}")
print(f"Reason: {response.reason}")

if response.status == 200:
    data = json.loads(response.read())
    print(f"Success: {data.get('success')}")
    print(f"Has data: {'data' in data}")
else:
    print(f"Body: {response.read().decode()}")

conn.close()
