"""
IntrusionX - Live Attack Simulator
Generates realistic DNS traffic in real-time, processes each query
through the ML models, and writes results to SQLite.
Run this in the background during hackathon demo.
"""

import sqlite3
import random
import time
import math
import joblib
import numpy as np
from datetime import datetime
from collections import Counter
import string

DB_FILE = 'dns_filter.db'

from threat_engine import get_engine
detection_engine = get_engine()
print(f"[+] ThreatEngine loaded")


LEGIT_DOMAINS = []
try:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT domain FROM training_domains WHERE label = 0 LIMIT 2000")
    LEGIT_DOMAINS = [row[0] for row in c.fetchall()]
    conn.close()
    print(f"[+] Loaded {len(LEGIT_DOMAINS)} legit domains for simulation")
except Exception as e:
    print(f"[!] Could not load legit domains from db: {e}")
    LEGIT_DOMAINS = ["google.com", "microsoft.com", "apple.com"]

import random
random.shuffle(LEGIT_DOMAINS)
legit_index = 0

BLOCKLIST = []
try:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT domain FROM static_blocklist")
    BLOCKLIST = [row[0] for row in c.fetchall()]
    conn.close()
    random.shuffle(BLOCKLIST)
    print(f"[+] Loaded {len(BLOCKLIST)} blocklist domains")
except:
    BLOCKLIST = []
blocklist_index = 0

def gen_dga():
    length = random.randint(12, 30)
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)) + '.' + random.choice(['com','net','org','info','biz','xyz'])

def gen_tunnel():
    payload = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(40, 120)))
    return payload + '.tunnel.' + random.choice(['evil.com','c2server.net','exfil.org'])

def gen_phishing(base_domain):
    """Synthetic dataset generation as per Executive Summary: typos, homoglyphs, affix"""
    name = base_domain.split('.')[0]
    tld = base_domain.split('.')[-1]
    strategies = [
        lambda n: n.replace('o', '0').replace('l', '1').replace('i', 'l'), # Homoglyph
        lambda n: n + '-auth', # Suffix
        lambda n: 'secure-' + n, # Prefix
        lambda n: n + '-verifyaccount'
    ]
    phish_name = random.choice(strategies)(name)
    return phish_name + '.' + random.choice([tld, 'xyz', 'top', 'tk'])

CLIENT_IPS = ["192.168.1.10","192.168.1.11","192.168.1.25","192.168.1.42","10.0.0.5","10.0.0.12","172.16.0.8"]


def process_query(domain, client_ip):
    """Run domain through ThreatEngine and persist to SQLite."""
    result = detection_engine.analyze(domain, client_ip)
    
    now = result['timestamp'].replace('T', ' ')[:19]
    blocked = result['blocked']
    threat_type = result['threat_type']
    threat_score = result['score']
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''INSERT INTO dns_queries (timestamp, client_ip, domain, query_type, blocked, threat_type, threat_score)
                 VALUES (?, ?, ?, 'A', ?, ?, ?)''',
              (now, client_ip, domain, blocked, threat_type, threat_score))
    
    if blocked:
        c.execute('''INSERT INTO alerts (timestamp, client_ip, domain, threat_type, confidence, reason)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (now, client_ip, domain, threat_type, threat_score / 100, result['reason']))
    
    conn.commit()
    conn.close()
    
    return blocked, threat_type, threat_score


def run_simulator():
    """Main simulation loop. Generates mixed traffic continuously."""
    print("\n" + "="*60)
    print("  IntrusionX Attack Simulator - LIVE")
    print("  Press Ctrl+C to stop")
    print("="*60 + "\n")
    
    query_count = 0
    blocked_count = 0
    
    global legit_index, blocklist_index
    
    while True:
        roll = random.random()
        client_ip = random.choice(CLIENT_IPS)
        
        if roll < 0.70:
            domain = LEGIT_DOMAINS[legit_index % len(LEGIT_DOMAINS)]
            legit_index += 1
        elif roll < 0.80:
            domain = gen_dga()
        elif roll < 0.88:
            domain = gen_tunnel()
        elif roll < 0.95:
            base = LEGIT_DOMAINS[random.randint(0, len(LEGIT_DOMAINS)-1)]
            domain = gen_phishing(base)
        else:
            if BLOCKLIST:
                domain = BLOCKLIST[blocklist_index % len(BLOCKLIST)]
                blocklist_index += 1
            else:
                domain = gen_dga()
        
        blocked, threat, score = process_query(domain, client_ip)
        query_count += 1
        if blocked: blocked_count += 1
        
        status = "BLOCKED" if blocked else "ALLOWED"
        color = "\033[91m" if blocked else "\033[92m"
        reset = "\033[0m"
        
        print(f"  [{query_count:04d}] {client_ip:15s} -> {domain[:50]:50s} {color}{status:8s}{reset} {threat}")
        
        time.sleep(random.uniform(0.3, 1.5))


if __name__ == "__main__":
    run_simulator()
