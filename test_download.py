import urllib.request
import urllib.parse
import json

filename = "Screenshot 2025-05-06 204054.png"
url = f"http://localhost:8000/download/{urllib.parse.quote(filename)}"

print(f"Testing download: {filename}")
print(f"URL: {url}")

try:
    resp = urllib.request.urlopen(url, timeout=30)
    data = json.loads(resp.read())
    print(f"Success: {data.get('success')}")
    print(f"Has data: {'data' in data}")
    if 'data' in data:
        print(f"Data length: {len(data['data'])}")
    if 'error' in data:
        print(f"Error: {data['error']}")
except Exception as e:
    print(f"Error: {e}")
