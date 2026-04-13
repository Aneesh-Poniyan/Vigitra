import urllib.request
import sqlite3
import time
import threading

DB_FILE = 'dns_filter.db'

def update_openphish(conn):
    print("[ThreatFeeds] Fetching OpenPhish feed...")
    try:
        url = "https://openphish.com/feed.txt"
        response = urllib.request.urlopen(url, timeout=30)
        data = response.read().decode('utf-8')
        
        c = conn.cursor()
        count = 0
        for line in data.split('\n'):
            line = line.strip()
            if not line: continue
            
            domain = line.split('/')[2] if '://' in line else line.split('/')[0]
            domain = domain.split(':')[0].lower()
            
            if domain:
                try:
                    c.execute('INSERT OR IGNORE INTO static_blocklist (domain, category, source) VALUES (?, ?, ?)',
                              (domain, 'Phishing', 'OpenPhish'))
                    count += 1
                except sqlite3.IntegrityError:
                    pass
        conn.commit()
        print(f"[ThreatFeeds] Added {count} new domains from OpenPhish")
    except Exception as e:
        print(f"[ThreatFeeds] OpenPhish update failed: {e}")

def update_urlhaus(conn):
    print("[ThreatFeeds] Fetching Abuse.ch URLhaus feed...")
    try:
        url = "https://urlhaus.abuse.ch/downloads/csv/"
        response = urllib.request.urlopen(url, timeout=30)
        data = response.read().decode('utf-8', errors='ignore')
        
        c = conn.cursor()
        count = 0
        for line in data.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'): continue
            
            parts = line.split('","')
            if len(parts) >= 3:
                url_str = parts[2]
                domain = url_str.split('/')[2] if '://' in url_str else url_str.split('/')[0]
                domain = domain.split(':')[0].lower().replace('"', '')
                
                if domain:
                    try:
                        c.execute('INSERT OR IGNORE INTO static_blocklist (domain, category, source) VALUES (?, ?, ?)',
                                  (domain, 'Malware', 'Abuse.ch URLhaus'))
                        count += 1
                    except sqlite3.IntegrityError:
                        pass
                        pass
        conn.commit()
        print(f"[ThreatFeeds] Added {count} new domains from URLhaus")
    except Exception as e:
        print(f"[ThreatFeeds] URLhaus update failed: {e}")

def update_stevenblack(conn):
    print("[ThreatFeeds] Fetching StevenBlack blocklist...")
    try:
        url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
        response = urllib.request.urlopen(url, timeout=30)
        data = response.read().decode('utf-8')
        
        c = conn.cursor()
        count = 0
        domains = []
        for line in data.split('\n'):
            line = line.strip()
            if line.startswith('0.0.0.0 '):
                domain = line.replace('0.0.0.0 ', '').strip()
                if domain and domain != '0.0.0.0':
                    domains.append((domain, 'Malware/Ads', 'StevenBlack'))
                    count += 1
        
        # Batch insert for speed
        c.executemany('INSERT OR IGNORE INTO static_blocklist (domain, category, source) VALUES (?, ?, ?)', domains)
        conn.commit()
        print(f"[ThreatFeeds] Added {count} new domains from StevenBlack hosts")
    except Exception as e:
        print(f"[ThreatFeeds] StevenBlack update failed: {e}")

def run_update_job():
    print("[ThreatFeeds] Starting threat feed update cycle...")
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('''CREATE TABLE IF NOT EXISTS static_blocklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE,
        category TEXT,
        source TEXT
    )''')
    
    update_openphish(conn)
    update_urlhaus(conn)
    update_stevenblack(conn)
    
    conn.close()
    
    from threat_engine import get_engine
    get_engine().refresh_blocklist()
    
    print("[ThreatFeeds] Update cycle complete.")

def feed_updater_daemon(interval_hours=1):
    """Runs continuously in the background."""
    while True:
        try:
            run_update_job()
        except Exception as e:
            print(f"[ThreatFeeds] Fatal error in updater: {e}")
        
        time.sleep(interval_hours * 3600)

if __name__ == "__main__":
    run_update_job()
