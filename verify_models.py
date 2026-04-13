"""Quick verification of retrained models."""
import requests

tests = [
    ("google.com", "Should be safe"),
    ("xkj234kjdfsh2md.net", "DGA domain"),
    ("paypa1-secure-login.xyz", "Phishing - PayPal"),
    ("amaz0n-verify-account.top", "Phishing - Amazon"),
    ("cD93ZXJzaGVsbCBoYWNrZXI.evil.com", "DNS Tunneling"),
    ("sbi-netbanking-verify.tk", "Phishing - SBI Bank"),
    ("github.com", "Should be safe"),
    ("bcvnwk83jd2lp.org", "DGA domain"),
    ("micros0ft-login.club", "Phishing - Microsoft"),
    ("stackoverflow.com", "Should be safe"),
]

header = f"{'DOMAIN':<45} {'SCORE':>6} {'TYPE':<15} {'BLOCKED':<8} EXPECTED"
print(header)
print("=" * 110)

for domain, expected in tests:
    r = requests.post("http://127.0.0.1:5000/api/analyze_domain", json={"domain": domain})
    d = r.json()
    score = d.get("score", 0)
    threat_type = d.get("threat_type", "")
    blocked = "BLOCK" if score >= 50 else "PASS"
    icon = "X" if score >= 50 else "OK"
    print(f"{domain:<45} {score:>6.1f} {threat_type:<15} [{icon}] {blocked:<6} ({expected})")
