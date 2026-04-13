import requests
import json

r = requests.post('http://127.0.0.1:5000/api/analyze_domain', json={'domain': 'https://mail.yahoo.com/?lang=en-IN'})
d = r.json()
print(f"Score: {d.get('score')}  Type: {d.get('threat_type')}  Blocked: {d.get('blocked')}")
