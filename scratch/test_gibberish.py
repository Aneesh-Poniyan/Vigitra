"""Quick test to verify Gibberish DGA detection is working."""
import sys
sys.path.insert(0, r"c:\Anti\DNS PROJECT")
from threat_engine import ThreatEngine

engine = ThreatEngine()

test_domains = [
    # DGA / Gibberish domains (should be BLOCKED)
    "xeogrhxquuubt.com",
    "qwrtzxcvbn.tk",
    "bxkjmthwrng.xyz",
    "dfghnjklqwrt.cc",
    # Legitimate domains (should be SAFE)
    "google.com",
    "youtube.com",
    "github.com",
    "gla.ac.in",
    "stackoverflow.com",
]

print("=" * 80)
print("  INTRUSIONX GIBBERISH DETECTION VERIFICATION")
print("=" * 80)

for domain in test_domains:
    r = engine.analyze(domain)
    status = "BLOCKED" if r['blocked'] else "SAFE"
    marker = "[X]" if r['blocked'] else "[OK]"
    print(f"  {marker} {domain:<35} Score: {r['score']:>6} | {status:<8} | {r['threat_type']}")
    if r.get('reason') and r['reason'] != 'N/A':
        print(f"       Reason: {r['reason']}")

print("=" * 80)
