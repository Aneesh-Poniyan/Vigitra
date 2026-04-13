"""
IntrusionX - Enterprise Dataset Ingestion Pipeline
Downloads real-world domain intelligence from multiple sources:
  1. Tranco Top 1M (legitimate domains baseline)
  2. StevenBlack unified hosts (malware/ads blocklist)
  3. DGA domain families from chrmor/DGA_domains_dataset
"""

import urllib.request
import sqlite3
import zipfile
import csv
import io
import os
import time

DB_FILE = 'dns_filter.db'

def setup_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS dns_queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        client_ip TEXT,
        domain TEXT,
        query_type TEXT DEFAULT 'A',
        blocked BOOLEAN DEFAULT 0,
        threat_type TEXT DEFAULT 'None',
        threat_score REAL DEFAULT 0.0
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        client_ip TEXT,
        domain TEXT,
        threat_type TEXT,
        confidence REAL,
        reason TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS static_blocklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE,
        category TEXT,
        source TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS training_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        label INTEGER,
        source TEXT,
        family TEXT DEFAULT 'unknown'
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS system_settings (
        id INTEGER PRIMARY KEY,
        dga_enabled INTEGER DEFAULT 1,
        tunnel_enabled INTEGER DEFAULT 1,
        risk_threshold REAL DEFAULT 80.0
    )''')
    
    c.execute('INSERT OR IGNORE INTO system_settings (id, dga_enabled, tunnel_enabled, risk_threshold) VALUES (1, 1, 1, 80.0)')
    
    c.execute('CREATE INDEX IF NOT EXISTS idx_queries_threat ON dns_queries (threat_type)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_queries_blocked ON dns_queries (blocked)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_queries_ts ON dns_queries (timestamp)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_blocklist_domain ON static_blocklist (domain)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_training_label ON training_domains (label)')
    
    conn.commit()
    return conn

def download_tranco(conn, limit=5000):
    """Download Tranco Top 1M legitimate domains as our benign baseline."""
    print("[1/3] Downloading Tranco Top 1M legitimate domains...")
    url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        response = urllib.request.urlopen(url, timeout=30)
        zip_data = io.BytesIO(response.read())
        with zipfile.ZipFile(zip_data) as z:
            with z.open(z.namelist()[0]) as f:
                reader = csv.reader(io.TextIOWrapper(f, encoding='utf-8'))
                c = conn.cursor()
                count = 0
                for row in reader:
                    if len(row) >= 2:
                        domain = row[1].strip()
                        c.execute('INSERT OR IGNORE INTO training_domains (domain, label, source) VALUES (?, 0, ?)',
                                  (domain, 'tranco'))
                        count += 1
                        if count >= limit:
                            break
                conn.commit()
                print(f"    ✓ Ingested {count} legitimate domains from Tranco")
    except Exception as e:
        print(f"    ✗ Tranco download failed: {e}")
        print("    → Falling back to hardcoded top domains...")
        fallback_legit = [
            "google.com","youtube.com","facebook.com","amazon.com","wikipedia.org",
            "twitter.com","instagram.com","linkedin.com","reddit.com","netflix.com",
            "microsoft.com","apple.com","github.com","stackoverflow.com","whatsapp.com",
            "zoom.us","office.com","live.com","yahoo.com","bing.com",
            "adobe.com","spotify.com","twitch.tv","pinterest.com","tumblr.com",
            "paypal.com","ebay.com","cnn.com","bbc.com","nytimes.com",
            "bloomberg.com","reuters.com","medium.com","quora.com","slack.com",
            "dropbox.com","salesforce.com","oracle.com","ibm.com","intel.com",
            "nvidia.com","amd.com","samsung.com","huawei.com","xiaomi.com",
            "flipkart.com","paytm.com","sbi.co.in","hdfcbank.com","icicibank.com",
        ]
        c = conn.cursor()
        for d in fallback_legit:
            c.execute('INSERT OR IGNORE INTO training_domains (domain, label, source) VALUES (?, 0, ?)', (d, 'fallback'))
        conn.commit()
        print(f"    ✓ Ingested {len(fallback_legit)} fallback legitimate domains")

def download_dga_dataset(conn, limit=5000):
    """Download real DGA domain families from chrmor's dataset on GitHub."""
    print("[2/3] Downloading real DGA domain families...")
    families_url = "https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/master/legit_dga_combined.csv"
    try:
        response = urllib.request.urlopen(families_url, timeout=30)
        data = response.read().decode('utf-8', errors='ignore')
        reader = csv.reader(io.StringIO(data))
        c = conn.cursor()
        count = 0
        for row in reader:
            if len(row) >= 2:
                domain = row[0].strip()
                label_str = row[1].strip().lower()
                label = 1 if label_str == 'dga' else 0
                family = row[2].strip() if len(row) > 2 else 'unknown'
                if label == 1:  # We only need DGA from here (legit comes from Tranco)
                    c.execute('INSERT OR IGNORE INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)',
                              (domain, 'chrmor_dga', family))
                    count += 1
                    if count >= limit:
                        break
        conn.commit()
        print(f"    ✓ Ingested {count} real DGA domains with family labels")
    except Exception as e:
        print(f"    ✗ DGA dataset download failed: {e}")
        print("    → Generating synthetic DGA domains as fallback...")
        import random, string
        c = conn.cursor()
        count = 0
        dga_families = ['cryptolocker', 'conficker', 'necurs', 'bamital', 'murofet',
                        'pykspa', 'ranbyus', 'tinba', 'matsnu', 'suppobox']
        for _ in range(limit):
            length = random.randint(10, 35)
            domain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)) + '.' + random.choice(['com','net','org','info','biz'])
            family = random.choice(dga_families)
            c.execute('INSERT OR IGNORE INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)',
                      (domain, 'synthetic_dga', family))
            count += 1
        conn.commit()
        print(f"    ✓ Generated {count} synthetic DGA domains across {len(dga_families)} families")

def download_stevenblack(conn, limit=10000):
    """Download StevenBlack unified hosts blocklist."""
    print("[3/3] Downloading StevenBlack malware/ad blocklist...")
    url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    try:
        response = urllib.request.urlopen(url, timeout=30)
        data = response.read().decode('utf-8')
        c = conn.cursor()
        count = 0
        for line in data.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ['0.0.0.0', '127.0.0.1']:
                domain = parts[1]
                if domain in ['localhost', 'localhost.localdomain', 'broadcasthost', 'local', '0.0.0.0']:
                    continue
                c.execute('INSERT OR IGNORE INTO static_blocklist (domain, category, source) VALUES (?, ?, ?)',
                          (domain, 'Malware/Ads', 'StevenBlack'))
                count += 1
                if count >= limit:
                    break
        conn.commit()
        print(f"    ✓ Ingested {count} malware/ad domains into blocklist")
    except Exception as e:
        print(f"    ✗ StevenBlack download failed: {e}")

def print_summary(conn):
    c = conn.cursor()
    legit = c.execute('SELECT COUNT(*) FROM training_domains WHERE label=0').fetchone()[0]
    dga = c.execute('SELECT COUNT(*) FROM training_domains WHERE label=1').fetchone()[0]
    blocklist = c.execute('SELECT COUNT(*) FROM static_blocklist').fetchone()[0]
    print(f"\n{'='*50}")
    print(f"  Dataset Ingestion Complete")
    print(f"{'='*50}")
    print(f"  Legitimate domains (label=0): {legit:,}")
    print(f"  DGA domains (label=1):        {dga:,}")
    print(f"  Static blocklist entries:      {blocklist:,}")
    print(f"  Total training corpus:         {legit + dga:,}")
    print(f"{'='*50}")

if __name__ == "__main__":
    start = time.time()
    conn = setup_database()
    download_tranco(conn, limit=5000)
    download_dga_dataset(conn, limit=5000)
    download_stevenblack(conn, limit=10000)
    print_summary(conn)
    conn.close()
    print(f"\nCompleted in {time.time() - start:.1f}s")
