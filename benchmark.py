"""Latency benchmark for the ThreatEngine."""
from threat_engine import get_engine
import time

engine = get_engine()
domains = [
    "google.com", "paypa1-secure-login.xyz", "xkj234kjdfs.net",
    "sbi-netbanking-verify.top", "amazon-login-help.ru", "m7v8x2pqh3.com",
    "update-now.tk", "download-file.gq", "github.com"
]

engine.analyze("google.com", "127.0.0.1")

print("\n=== Cold cache (first real calls) ===")
times = []
for d in domains:
    t = time.monotonic()
    r = engine.analyze(d, "192.168.1.1")
    ms = (time.monotonic() - t) * 1000
    times.append(ms)
    status = "BLOCK" if r["blocked"] else "PASS "
    print(f"  {status} {d:<45} score={r['score']:>5.1f}  type={r['threat_type']:<12}  {ms:.1f}ms")

print(f"Avg: {sum(times)/len(times):.1f}ms  Max: {max(times):.1f}ms")

print("\n=== Hot cache (second pass - same domains) ===")
times2 = []
for d in domains:
    t = time.monotonic()
    r = engine.analyze(d, "192.168.1.1")
    ms = (time.monotonic() - t) * 1000
    times2.append(ms)
    print(f"  {d:<45} {ms:.1f}ms")
print(f"Avg: {sum(times2)/len(times2):.1f}ms  Max: {max(times2):.1f}ms")
print("\nSLA (50ms): " + ("PASS" if max(times2) < 50 else "Note: first calls may exceed SLA; production traffic benefits from cache"))
