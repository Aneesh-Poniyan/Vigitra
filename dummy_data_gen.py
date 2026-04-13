import sqlite3
import random
import time
from datetime import datetime, timedelta

DB_FILE = 'dns_filter.db'

def create_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            client_ip TEXT,
            domain TEXT,
            query_type TEXT,
            blocked BOOLEAN,
            threat_type TEXT,
            threat_score FLOAT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            client_ip TEXT,
            domain TEXT,
            threat_type TEXT,
            confidence FLOAT,
            reason TEXT
        )
    ''')

    conn.commit()
    conn.close()

def generate_dummy_data():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('DELETE FROM dns_queries')
    cursor.execute('DELETE FROM alerts')

    client_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.25", "10.0.0.5"]
    good_domains = ["google.com", "github.com", "slack.com", "windows.com", "apple.com"]
    dga_domains = ["xkj234kjdfs.com", "poqwe098zx.net", "vncxm9823k.org"]
    tunnel_domains = ["cD93ZXJzaGVsbCBoYWNrZXI.malicious.com", "aGVsbG8gd29ybGQgYmFzZTY0.badactor.net"]

    now = datetime.now()

    for i in range(100):
        timestamp = now - timedelta(seconds=random.randint(1, 3600)) # Last 1 hour
        client_ip = random.choice(client_ips)
        query_type = "A"

        rand_val = random.random()
        if rand_val < 0.8:
            domain = random.choice(good_domains)
            blocked = False
            threat_type = "None"
            threat_score = random.uniform(0, 10)
        elif rand_val < 0.9:
            domain = random.choice(dga_domains)
            blocked = True
            threat_type = "DGA"
            threat_score = random.uniform(80, 99)
            
            cursor.execute('''
                INSERT INTO alerts (timestamp, client_ip, domain, threat_type, confidence, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, client_ip, domain, threat_type, threat_score / 100, f"High entropy and model score {threat_score:.1f}"))
        else:
            domain = random.choice(tunnel_domains)
            blocked = True
            threat_type = "Tunneling"
            threat_score = random.uniform(85, 99)
            
            cursor.execute('''
                INSERT INTO alerts (timestamp, client_ip, domain, threat_type, confidence, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, client_ip, domain, threat_type, threat_score / 100, "Unusual subdomain length mapping anomaly"))

        cursor.execute('''
            INSERT INTO dns_queries (timestamp, client_ip, domain, query_type, blocked, threat_type, threat_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, client_ip, domain, query_type, blocked, threat_type, threat_score))

    conn.commit()
    conn.close()
    print("Database created and populated with dummy data successfully.")

if __name__ == "__main__":
    create_db()
    generate_dummy_data()
