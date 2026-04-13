import requests
import os
from dotenv import load_dotenv

load_dotenv()

VIGITRA_API_KEY = os.getenv("VIGITRA_API_KEY", "vigitra_dev_key_x9f2")
headers = {"X-Vigitra-Key": VIGITRA_API_KEY}

try:
    r = requests.get("http://127.0.0.1:5000/api/health", headers=headers)
    print(f"Health check: {r.status_code}")
    print(r.json())
    
    r = requests.get("http://127.0.0.1:5000/api/stats", headers=headers)
    print(f"Stats check: {r.status_code}")
    print(r.json())
except Exception as e:
    print(f"Error: {e}")
