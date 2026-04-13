import socket
import threading
import datetime
from datetime import timezone
import sqlite3

try:
    from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE
except ImportError:
    print("[!] dnslib not found. Run 'pip install dnslib' to use the DNS Server.")
    exit(1)

from threat_engine import get_engine

BIND_IP = "0.0.0.0"
BIND_PORT = 5054  # Change to 53 for production, but needs admin rights on Windows
UPSTREAM_DNS = "8.8.8.8"
UPSTREAM_PORT = 53
SINKHOLE_IP = "0.0.0.0"
DB_FILE = "dns_filter.db"

engine = get_engine()

from functools import lru_cache
from collections import defaultdict, deque
import time

query_windows = defaultdict(deque)

def is_ddos(client_ip: str) -> bool:
    now = time.time()
    window = query_windows[client_ip]
    # Remove queries older than 1 second
    while window and now - window[0] > 1.0:
        window.popleft()
    window.append(now)
    return len(window) > 50  # block if >50 queries/sec

SAFE_DOMAINS_LUT = {
    "google.com",
    "www.google.com",
    "facebook.com",
    "www.facebook.com",
    "youtube.com",
    "www.youtube.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "googleapis.com",
    "cloudflare.com",
}

_ip_query_times = defaultdict(list)
_ip_lock = threading.Lock()


@lru_cache(maxsize=4096)
def check_domain_cached(domain: str, client_ip: str):
    # Deep Caching: Avoid entirely processing known massive traffic
    if domain in SAFE_DOMAINS_LUT:
        return {
            "domain": domain,
            "score": 0.0,
            "blocked": False,
            "threat_type": "None",
            "reason": "Fast-path cached (Safe LUT)",
            "dga_prob": 0.0,
            "anomaly_score": 0.0,
            "entropy": 0.0,
            "latency_ms": 0.01,
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        }
    return engine.analyze(domain, client_ip)


def persist_query(domain, client_ip, result):
    """Write outcome to SQLite asynchronously to not block DNS response."""
    now = datetime.datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    blocked = result["blocked"]
    threat_type = result["threat_type"]
    threat_score = result["score"]
    reason = result["reason"]

    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.execute('PRAGMA journal_mode=WAL;')
        c = conn.cursor()
        c.execute(
            """INSERT INTO dns_queries (timestamp, client_ip, domain, query_type, blocked, threat_type, threat_score)
                     VALUES (?, ?, ?, 'A', ?, ?, ?)""",
            (now, client_ip, domain, blocked, threat_type, threat_score),
        )

        if blocked:
            c.execute(
                """INSERT INTO alerts (timestamp, client_ip, domain, threat_type, confidence, reason)
                         VALUES (?, ?, ?, ?, ?, ?)""",
                (now, client_ip, domain, threat_type, threat_score / 100.0, reason),
            )

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DNS] Failed to log query to DB: {e}")


def resolve_upstream(request: DNSRecord) -> DNSRecord:
    """Forward the query to upstream DNS and return the response."""
    try:
        upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_socket.settimeout(2.0)
        upstream_socket.sendto(request.pack(), (UPSTREAM_DNS, UPSTREAM_PORT))
        data, _ = upstream_socket.recvfrom(4096)
        upstream_socket.close()
        return DNSRecord.parse(data)
    except Exception as e:
        print(f"[DNS] Upstream resolution failed: {e}")
        reply = request.reply()
        reply.header.rcode = 2
        return reply


def handle_udp_query(data, addr, sock):
    try:
        request = DNSRecord.parse(data)
        client_ip = addr[0]

        # DDoS / DNS Amplification Rate Limiter
        if is_ddos(client_ip):
            return  # silently drop — DDoS blocked

        if not request.questions:
            return

        qname = str(request.q.qname)
        domain = qname.rstrip(".")

        print(
            f"[DNS] Query from {client_ip}: {domain} (Type: {QTYPE[request.q.qtype]})"
        )

        if request.q.qtype in [QTYPE.A, QTYPE.AAAA, QTYPE.CNAME]:
            result = check_domain_cached(domain, client_ip)

            from threat_engine import DOH_IPS

            if client_ip in DOH_IPS:
                result = dict(result)  # copy to avoid mutating cached object
                result["blocked"] = True
                result["score"] = 100.0
                result["threat_type"] = "DOH_BYPASS"
                result["reason"] = "DoH/DoT Evasion Filtering"

            threading.Thread(
                target=persist_query, args=(domain, client_ip, result), daemon=True
            ).start()

            if result["blocked"]:
                print(
                    f"      └── [BLOCKED] Score: {result['score']:.1f} ({result['threat_type']})"
                )
                reply = request.reply()
                if request.q.qtype == QTYPE.A:
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(SINKHOLE_IP), ttl=60))
                if request.q.qtype != QTYPE.A:
                    reply.header.rcode = 3  # NXDOMAIN
                sock.sendto(reply.pack(), addr)
                return
        else:
            print(f"      └── [PASS] Unhandled QTYPE {QTYPE[request.q.qtype]}")

        upstream_reply = resolve_upstream(request)

        # Fast Flux Data Harvesting
        if upstream_reply and upstream_reply.rr:
            ips = []
            ttls = []
            for rr in upstream_reply.rr:
                if rr.rtype == QTYPE.A:
                    ips.append(str(rr.rdata))
                    ttls.append(rr.ttl)
            if ips:
                min_ttl = min(ttls) if ttls else 60
                engine.feed_upstream_response(domain, ips, min_ttl)

        sock.sendto(upstream_reply.pack(), addr)

    except Exception as e:
        print(f"[DNS] Error handling query from {addr}: {e}")


def run_dns_server():
    print("=" * 60)
    print(f"  IntrusionX Live DNS Proxy Server")
    print(f"  Listening on UDP {BIND_IP}:{BIND_PORT}")
    print(f"  Upstream DNS: {UPSTREAM_DNS}:{UPSTREAM_PORT}")
    print("=" * 60)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND_IP, BIND_PORT))

    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(
            target=handle_udp_query, args=(data, addr, sock), daemon=True
        ).start()


if __name__ == "__main__":
    run_dns_server()
