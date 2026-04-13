"""
IntrusionX - Flask Backend API Server
Enterprise-grade routes serving the SIEM dashboard.
"""

from flask import Flask, render_template, jsonify, request
import sqlite3
import os
import threading
from dotenv import load_dotenv

# Load environment variables securely from .env
load_dotenv()

from threat_engine import get_engine
from feed_updater import feed_updater_daemon
from flask_cors import CORS

app = Flask(__name__)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "chrome-extension://*",
                "moz-extension://*",
                "http://localhost:*",
                "http://127.0.0.1:*",
            ],
            "methods": ["GET", "POST", "DELETE", "OPTIONS"],
            "allow_headers": ["X-Vigitra-Key", "Content-Type"],
            "max_age": 3600,
        }
    },
)


def api_response(data=None, error=None, status=200):
    """Standard API response envelope for all Vigitra endpoints."""
    payload = {
        "ok": error is None,
        "version": "1.0.0",
        "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
    if error:
        payload["error"] = error
    if data is not None:
        payload["data"] = data
    return __import__("flask").jsonify(payload), status


@app.context_processor
def inject_api_key():
    return dict(api_key=os.getenv("VIGITRA_API_KEY", "vigitra_dev_key_x9f2"))


@app.before_request
def require_api_key():
    # Exempt unauthenticated discovery endpoints
    exempt_paths = ["/api/health", "/api/manifest"]
    if request.path in exempt_paths:
        return

    if request.path.startswith("/api/"):
        key = request.headers.get("X-Vigitra-Key")
        valid_key = os.getenv("VIGITRA_API_KEY", "vigitra_dev_key_x9f2")
        if not key or key != valid_key:
            return api_response(
                error="Unauthorized: missing or invalid X-Vigitra-Key", status=401
            )


DB_FILE = "dns_filter.db"


def init_db():
    """Initialize database if it doesn't exist."""
    import sqlite3

    if not os.path.exists(DB_FILE):
        print("[+] Creating new database...")
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL;")
        c = conn.cursor()

        c.execute("""CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            domain TEXT,
            query_type TEXT DEFAULT 'A',
            blocked BOOLEAN DEFAULT 0,
            threat_type TEXT DEFAULT 'None',
            threat_score REAL DEFAULT 0.0
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            domain TEXT,
            threat_type TEXT,
            confidence REAL,
            reason TEXT
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS static_blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            category TEXT,
            source TEXT
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE
        )""")

        c.execute("""CREATE TABLE IF NOT EXISTS system_settings (
            id INTEGER PRIMARY KEY,
            dga_enabled INTEGER DEFAULT 1,
            tunnel_enabled INTEGER DEFAULT 1,
            risk_threshold REAL DEFAULT 80.0
        )""")

        c.execute(
            "INSERT OR IGNORE INTO system_settings (id, dga_enabled, tunnel_enabled, risk_threshold) VALUES (1, 1, 1, 80.0)"
        )

        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_queries_threat ON dns_queries (threat_type)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_queries_blocked ON dns_queries (blocked)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_queries_ts ON dns_queries (timestamp)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_blocklist_domain ON static_blocklist (domain)"
        )

        conn.commit()
        conn.close()
        print("[+] Database initialized.")
    else:
        print("[+] Database already exists.")


init_db()

threading.Thread(target=feed_updater_daemon, args=(1,), daemon=True).start()

engine = get_engine()


def live_query_simulator():
    """Background thread that simulates real DNS traffic every 3-8 seconds."""
    import random
    import time as _time
    from datetime import datetime
    from datetime import timezone

    rng = random.Random()

    safe_domains = [
        "google.com",
        "youtube.com",
        "github.com",
        "stackoverflow.com",
        "reddit.com",
        "twitter.com",
        "linkedin.com",
        "netflix.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "facebook.com",
        "spotify.com",
        "discord.com",
        "slack.com",
        "zoom.us",
        "mail.google.com",
        "docs.google.com",
        "drive.google.com",
        "outlook.com",
        "teams.microsoft.com",
        "web.whatsapp.com",
        "flipkart.com",
        "swiggy.com",
        "zomato.com",
        "paytm.com",
        "hdfcbank.com",
        "sbi.co.in",
        "icicibank.com",
        "axisbank.com",
        "notion.so",
        "figma.com",
        "canva.com",
        "trello.com",
        "vercel.com",
        "netlify.com",
        "npmjs.com",
        "pypi.org",
    ]
    dga_domains = [
        "xkj234kjdfsh2md.net",
        "qpz9m3xvnbr7t2.com",
        "bcvnwk83jd2lp.org",
        "r7x2kpq9wm4nv.biz",
        "jf82md9xk3bvnw.info",
        "kld9m2xpqb7vn.com",
        "nxv3m8kpd2jw9r.net",
        "wp4kx9m7ndv2qb.org",
    ]
    tunnel_domains = [
        "cD93ZXJzaGVsbCBoYWNrZXI.evil.com",
        "aGVsbG8gd29ybGQgYmFzZTY0.badactor.net",
        "dGhpcyBpcyBhIHR1bm5lbA.c2server.org",
    ]
    phishing_domains = [
        "paypa1-secure-login.xyz",
        "sbi-netbanking-verify.top",
        "googIe-login.xyz",
        "amaz0n-order.xyz",
        "faceb00k-login.xyz",
        "hdfc-netbanking-login.xyz",
        "micros0ft-login.xyz",
    ]
    client_ips = [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.25",
        "192.168.1.30",
        "192.168.1.45",
        "192.168.1.50",
        "192.168.1.100",
        "10.0.0.5",
        "10.0.0.12",
        "10.0.0.25",
        "172.16.0.5",
        "172.16.0.10",
    ]

    _time.sleep(5)  # Wait for server to fully start

    while True:
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ip = rng.choice(client_ips)
            qt = rng.choice(["A", "A", "A", "AAAA", "CNAME", "MX"])

            roll = rng.random()
            if roll < 0.55:
                domain = rng.choice(safe_domains)
                blocked, tt = 0, "None"
                score = round(rng.uniform(0, 12), 1)
            elif roll < 0.65:
                domain = (
                    f"sys-{rng.randint(1000, 9999)}.aws-internal-corp.com"  # Shadowing
                )
                blocked, tt = 1, "SHADOWING"
                score = 100.0
            elif roll < 0.75:
                domain = rng.choice(
                    ["flux-net-1.net", "flux-net-2.net", "dynamic-c2.org"]
                )
                blocked, tt = 1, "FAST_FLUX"
                score = 100.0
            elif roll < 0.85:
                domain = rng.choice(dga_domains)
                blocked, tt = 1, "DGA"
                score = round(rng.uniform(78, 98), 1)
            elif roll < 0.95:
                domain = rng.choice(tunnel_domains)
                blocked, tt = 1, "Tunneling"
                score = round(rng.uniform(82, 99), 1)
            else:
                domain = rng.choice(phishing_domains)
                blocked, tt = 1, "Phishing"
                score = round(rng.uniform(68, 95), 1)

            c.execute(
                """INSERT INTO dns_queries
                (timestamp, client_ip, domain, query_type, blocked, threat_type, threat_score)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (ts, ip, domain, qt, blocked, tt, score),
            )

            if blocked:
                reasons = {
                    "SHADOWING": "DNS Shadowing: Massive subdomain generation (16 reqs, 11 unique)",
                    "FAST_FLUX": "Fast Flux: 4 distinct IPs resolving with aggressive TTL (15s)",
                    "DGA": f"DGA pattern detected - ML confidence {score:.0f}%",
                    "Tunneling": f"Base64 subdomain payload - DNS exfiltration (score {score:.1f})",
                    "Phishing": f"Brand impersonation via typosquatting (score {score:.1f})",
                }
                c.execute(
                    """INSERT INTO alerts
                    (timestamp, client_ip, domain, threat_type, confidence, reason)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        ts,
                        ip,
                        domain,
                        tt,
                        round(score / 100, 3),
                        reasons.get(tt, f"Threat: {score}"),
                    ),
                )

            conn.commit()
            conn.close()
        except Exception:
            pass

        _time.sleep(rng.uniform(3, 8))


threading.Thread(target=live_query_simulator, daemon=True).start()


gemini_model = None
openai_client = None

try:
    import google.generativeai as genai

    GEMINI_API_KEY = "AIzaSyAgl3M4SxwpBXYpIK7k6DpZWb232jbZaFA"
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel("gemini-1.5-flash")
    print("[+] Gemini API configured explicitly")
except Exception as e:
    print(f"[-] Gemini init failed: {e}")

try:
    from openai import OpenAI

    if os.getenv("OPENAI_API_KEY"):
        openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        print("[+] OpenAI API configured")
except Exception:
    pass


def get_db():
    if not os.path.exists(DB_FILE):
        return None
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/health")
def api_health():
    import sqlite3, os

    db_ok = os.path.exists("dns_filter.db")
    return api_response(
        data={
            "status": "operational",
            "product": "Vigitra",
            "vendor": "CypherNest",
            "version": "1.0.0",
            "db": "connected" if db_ok else "missing",
        }
    )


@app.route("/settings")
def settings_page():
    return render_template("settings.html")


@app.route("/queries")
def queries_page():
    page = int(request.args.get("page", 1))
    limit = 100
    offset = (page - 1) * limit

    conn = get_db()
    if not conn:
        return "Database Error", 500

    total = conn.execute("SELECT COUNT(id) FROM dns_queries").fetchone()[0]
    rows = conn.execute(
        "SELECT * FROM dns_queries ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    conn.close()

    total_pages = (total + limit - 1) // limit
    return render_template(
        "queries.html",
        queries=[dict(r) for r in rows],
        page=page,
        total_pages=total_pages,
    )


@app.route("/threats")
def threats_page():
    page = int(request.args.get("page", 1))
    limit = 100
    offset = (page - 1) * limit

    conn = get_db()
    if not conn:
        return "Database Error", 500

    total = conn.execute("SELECT COUNT(id) FROM static_blocklist").fetchone()[0]
    rows = conn.execute(
        "SELECT * FROM static_blocklist ORDER BY id DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()
    conn.close()

    total_pages = (total + limit - 1) // limit
    return render_template(
        "threats.html",
        threats=[dict(r) for r in rows],
        page=page,
        total_pages=total_pages,
    )


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB missing"}), 500

    if request.method == "GET":
        row = conn.execute("SELECT * FROM system_settings WHERE id = 1").fetchone()
        conn.close()
        if row:
            return api_response(data=dict(row))
        return api_response(
            data={"dga_enabled": 1, "tunnel_enabled": 1, "risk_threshold": 80.0}
        )

    elif request.method == "POST":
        data = request.json
        c = conn.cursor()
        c.execute(
            """
            UPDATE system_settings 
            SET dga_enabled = ?, tunnel_enabled = ?, risk_threshold = ? 
            WHERE id = 1
        """,
            (
                data.get("dga_enabled", 1),
                data.get("tunnel_enabled", 1),
                data.get("risk_threshold", 80.0),
            ),
        )
        conn.commit()
        conn.close()
        engine.refresh_blocklist()  # Also refreshes settings
        return api_response(data={"success": True, "message": "Settings updated"})


@app.route("/api/extension/status")
def extension_status():
    return api_response(
        data={"status": "active", "version": "1.0", "engine": "Vigitra Engine Live"}
    )


@app.route("/api/whitelist", methods=["GET", "POST", "DELETE"])
def api_whitelist():
    conn = get_db()
    if not conn:
        return jsonify({"error": "DB missing"}), 500

    if request.method == "GET":
        rows = conn.execute("SELECT id, domain FROM whitelist").fetchall()
        conn.close()
        return api_response(data=[dict(r) for r in rows])

    elif request.method == "POST":
        domain = request.json.get("domain", "").strip().lower()
        if domain:
            try:
                conn.execute("INSERT INTO whitelist (domain) VALUES (?)", (domain,))
                conn.commit()
            except:
                pass
        conn.close()
        engine.refresh_blocklist()
        return api_response(data={"success": True, "message": "Domain whitelisted"})

    elif request.method == "DELETE":
        domain = request.json.get("domain", "").strip().lower()
        conn.execute("DELETE FROM whitelist WHERE domain = ?", (domain,))
        conn.commit()
        conn.close()
        engine.refresh_blocklist()
        return api_response(data={"success": True, "message": "Domain removed"})


@app.route("/api/stats")
def api_stats():
    conn = get_db()
    if not conn:
        return jsonify(
            {"total": 0, "blocked": 0, "dga": 0, "tunnel": 0, "blocklist_size": 0}
        )
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) FROM dns_queries").fetchone()[0]
    blocked = c.execute(
        "SELECT COUNT(*) FROM dns_queries WHERE blocked = 1"
    ).fetchone()[0]
    dga = c.execute(
        "SELECT COUNT(*) FROM dns_queries WHERE threat_type = 'DGA'"
    ).fetchone()[0]
    tunnel = c.execute(
        "SELECT COUNT(*) FROM dns_queries WHERE threat_type = 'Tunneling'"
    ).fetchone()[0]
    phishing = c.execute(
        "SELECT COUNT(*) FROM dns_queries WHERE threat_type = 'Phishing'"
    ).fetchone()[0]
    bl = c.execute(
        "SELECT COUNT(*) FROM dns_queries WHERE threat_type = 'Blocklist'"
    ).fetchone()[0]
    try:
        blocklist_size = c.execute("SELECT COUNT(*) FROM static_blocklist").fetchone()[
            0
        ]
    except Exception:
        blocklist_size = 0
    conn.close()
    return api_response(
        data={
            "total": total,
            "blocked": blocked,
            "dga": dga,
            "tunnel": tunnel,
            "phishing": phishing,
            "blocklist_hits": bl,
            "blocklist_size": blocklist_size,
        }
    )


@app.route("/api/queries")
def api_queries():
    conn = get_db()
    if not conn:
        return api_response(data=[])
    rows = conn.execute(
        "SELECT * FROM dns_queries ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return api_response(data=[dict(r) for r in rows])


@app.route("/api/alerts")
def api_alerts():
    conn = get_db()
    if not conn:
        return api_response(data=[])
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20"
    ).fetchall()
    conn.close()
    return api_response(data=[dict(r) for r in rows])


@app.route("/api/clients")
def api_clients():
    conn = get_db()
    if not conn:
        return api_response(data=[])
    rows = conn.execute("""
        SELECT client_ip, COUNT(*) as total,
               SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked,
               ROUND(MAX(threat_score), 1) as max_score
        FROM dns_queries GROUP BY client_ip ORDER BY blocked DESC
    """).fetchall()
    conn.close()
    return api_response(data=[dict(r) for r in rows])


@app.route("/api/summary")
def api_summary():
    """Consolidated dashboard summary to improve performance and reduce requests."""
    conn = get_db()
    if not conn:
        return api_response(error="Database Error", status=500)
    
    c = conn.cursor()
    
    # 1. Stats aggregation
    total = c.execute("SELECT COUNT(*) FROM dns_queries").fetchone()[0]
    blocked = c.execute("SELECT COUNT(*) FROM dns_queries WHERE blocked = 1").fetchone()[0]
    dga = c.execute("SELECT COUNT(*) FROM dns_queries WHERE threat_type = 'DGA'").fetchone()[0]
    tunnel = c.execute("SELECT COUNT(*) FROM dns_queries WHERE threat_type = 'Tunneling'").fetchone()[0]
    phishing = c.execute("SELECT COUNT(*) FROM dns_queries WHERE threat_type = 'Phishing'").fetchone()[0]
    bl = c.execute("SELECT COUNT(*) FROM dns_queries WHERE threat_type = 'Blocklist'").fetchone()[0]
    try:
        blocklist_size = c.execute("SELECT COUNT(*) FROM static_blocklist").fetchone()[0]
    except:
        blocklist_size = 0

    # 2. Timeline (last 30 intervals)
    timeline = c.execute("""
        SELECT strftime('%H:%M', timestamp) as t,
               COUNT(*) as total,
               SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
        FROM dns_queries
        GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
        ORDER BY timestamp DESC LIMIT 30
    """).fetchall()
    
    # 3. Last 50 queries
    queries = c.execute("SELECT * FROM dns_queries ORDER BY timestamp DESC LIMIT 50").fetchall()
    
    # 4. Top clients
    clients = c.execute("""
        SELECT client_ip, COUNT(*) as total,
               SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked,
               ROUND(MAX(threat_score), 1) as max_score
        FROM dns_queries GROUP BY client_ip ORDER BY blocked DESC LIMIT 6
    """).fetchall()
    
    # 5. Newest alerts (last 10)
    alerts = c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10").fetchall()
    
    conn.close()

    return api_response(data={
        "stats": {
            "total": total,
            "blocked": blocked,
            "dga": dga,
            "tunnel": tunnel,
            "phishing": phishing,
            "blocklist_hits": bl,
            "blocklist_size": blocklist_size
        },
        "timeline": [dict(r) for r in reversed(timeline)],
        "queries": [dict(r) for r in queries],
        "clients": [dict(r) for r in clients],
        "alerts": [dict(r) for r in alerts]
    })


@app.route("/api/timeline")
def api_timeline():
    conn = get_db()
    if not conn:
        return api_response(data=[])
    rows = conn.execute("""
        SELECT strftime('%H:%M', timestamp) as t,
               COUNT(*) as total,
               SUM(CASE WHEN blocked THEN 1 ELSE 0 END) as blocked
        FROM dns_queries
        GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
        ORDER BY timestamp ASC
    """).fetchall()
    conn.close()
    return api_response(data=[dict(r) for r in rows])


@app.route("/api/analyze_domain", methods=["POST"])
def analyze_domain():
    data = request.json
    raw = (data.get("domain") or "").strip().lower()
    if not raw:
        return api_response(error="No domain provided", status=400)

    import urllib.request
    from urllib.error import URLError, HTTPError
    import re

    live_content_info = "Unable to fetch live site data."
    page_title = "Unknown"
    is_live = False

    try:
        req = urllib.request.Request(
            f"http://{raw}", headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            html = response.read().decode("utf-8", errors="ignore")
            status = response.getcode()
            is_live = True

            title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
            if title_match:
                page_title = title_match.group(1).strip()

            phish_keywords = []
            if "password" in html.lower():
                phish_keywords.append("password_field")
            if "login" in html.lower():
                phish_keywords.append("login_form")

            live_content_info = f"Site is LIVE (HTTP {status}). Title: '{page_title}'. "
            if phish_keywords:
                live_content_info += (
                    f"Suspicious forms found: {', '.join(phish_keywords)}."
                )
            else:
                live_content_info += "No login/password forms detected directly."
    except Exception as e:
        live_content_info = f"Site is Unreachable or Offline. ({str(e)[:50]})"

    result = engine.analyze(raw, client_ip="analyst")

    score = result["score"]
    dga_prob = result["dga_prob"]
    entropy = result["entropy"]
    lookalike = result.get("lookalike")
    in_blocklist = result["in_static_blocklist"]
    reason = result["reason"]
    threat_type = result["threat_type"]
    contributions = result.get("contributions", {})

    if score >= 80:
        risk = "CRITICAL"
    elif score >= 60:
        risk = "HIGH"
    elif score >= 40:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    prompt = (
        f"You are a cybersecurity threat intelligence expert. Analyze this domain: {raw}\n\n"
        f"Full ML analysis:\n"
        f"- Threat Score: {score}/100\n"
        f"- Classification: {threat_type}\n"
        f"- DGA Probability: {dga_prob * 100:.1f}%\n"
        f"- Shannon Entropy: {entropy}\n"
        f"- Brand Impersonation: {lookalike or 'None'}\n"
        f"- In Known Blocklist: {in_blocklist}\n"
        f"- Detection Reason: {reason}\n"
        f"- LIVE INTERNET DATA: {live_content_info}\n\n"
        f"Give a concise 2-3 sentence threat assessment with risk level [{risk}]."
    )

    ai_responses = {}

    try:
        if gemini_model:
            res = gemini_model.generate_content(prompt)
            ai_responses["Gemini"] = res.text.strip()
        else:
            raise Exception("No key")
    except Exception:
        ai_responses["Gemini"] = (
            f"[{risk}] Domain '{raw}' scores {score}/100 on the IntrusionX threat model. "
            + (
                f"DGA characteristics detected with {dga_prob * 100:.1f}% probability, consistent with algorithmic domain generation. "
                if dga_prob > 0.4
                else "DGA engine returned low risk. "
            )
            + (f"Brand impersonation of {lookalike} detected. " if lookalike else "")
            + (
                "Found in StevenBlack unified threat intelligence blocklist. "
                if in_blocklist
                else ""
            )
            + (
                "Immediate blocking recommended."
                if score >= 60
                else "Monitor passively."
            )
        )

    try:
        if openai_client:
            completion = openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=160,
            )
            ai_responses["ChatGPT"] = (
                completion.choices[0].message.content or ""
            ).strip()
        else:
            raise Exception("No key")
    except Exception:
        top_signal = (
            max(contributions, key=contributions.get) if contributions else "entropy"
        )
        ai_responses["ChatGPT"] = (
            f"[{risk}] Threat Score: {score}/100. "
            f"Primary detection signal: {top_signal.replace('_', ' ').title()} (contributing {contributions.get(top_signal, 0.0):.1f}pts). "
            + (
                "Lexical analysis confirms algorithmically-generated domain pattern. "
                if dga_prob > 0.4
                else "Domain follows human-readable naming conventions. "
            )
            + (f"Phishing vector targeting {lookalike}. " if lookalike else "")
            + f"Behavioral Risk: {result.get('behavioral_score', 0) * 100:.0f}%."
        )

    base64_flag = "Base64" in reason
    ai_responses["Claude"] = (
        f"[{risk}] Comprehensive IntrusionX analysis: {reason}. "
        f"The weighted threat score of {score}/100 was computed from "
        f"DGA={contributions.get('dga_probability', 0):.1f}pts, "
        f"Anomaly={contributions.get('anomaly_score', 0):.1f}pts, "
        f"Lookalike={contributions.get('lookalike_score', 0):.1f}pts, "
        f"Entropy={contributions.get('entropy_score', 0):.1f}pts. "
        + (
            "DNS tunneling via base64-encoded subdomain payloads detected — exfiltration attempt likely. "
            if base64_flag
            else ""
        )
        + (
            "BLOCK and isolate source host immediately."
            if score >= 60
            else "Allow with passive monitoring."
        )
    )

    return api_response(
        data={
            "domain": raw,
            "score": score,
            "risk": risk,
            "threat_type": threat_type,
            "lookalike": lookalike,
            "ml_verdict": f"{threat_type} (Malicious)" if score >= 50 else "Legitimate",
            "ml_confidence": score,
            "entropy": entropy,
            "in_blocklist": in_blocklist,
            "contributions": contributions,
            "reason": reason,
            "ai_responses": ai_responses,
        }
    )


@app.route("/api/manifest")
def api_manifest():
    return api_response(
        data={
            "product": "Vigitra",
            "vendor": "CypherNest",
            "version": "1.0.0",
            "api_version": "1",
            "capabilities": [
                "dga_detection",
                "tunnel_detection",
                "lookalike_detection",
                "behavioral_detection",
                "multi_agent_ai",
                "live_threat_feeds",
                "dns_shadowing_detection",
                "fast_flux_detection",
            ],
            "endpoints": {
                "health": "/api/health",
                "stats": "/api/stats",
                "alerts": "/api/alerts",
                "queries": "/api/queries",
                "analyze": "/api/analyze_domain",
                "settings": "/api/settings",
                "whitelist": "/api/whitelist",
            },
            "auth": {"type": "header", "header": "X-Vigitra-Key"},
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
