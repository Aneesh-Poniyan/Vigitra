import sqlite3
import random
import base64
import string

DB_FILE = 'dns_filter.db'

WORDS = [
    "secure", "login", "update", "verify", "account", "support", "service", 
    "billing", "payment", "customer", "portal", "auth", "web", "mail", "app",
    "cloud", "storage", "drive", "docs", "bank", "finance", "alert", "notice",
    "system", "admin", "corporate", "internal", "api", "oauth", "sso"
]

BRANDS = [
    "google", "amazon", "microsoft", "apple", "facebook", "netflix", 
    "paypal", "chase", "bankofamerica", "wellsfargo", "twitter", "linkedin",
    "github", "slack", "discord", "dropbox", "salesforce"
]

TLDS = [".com", ".net", ".org", ".info", ".biz", ".co", ".xyz", ".top"]

def generate_tunneling_domain():
    # Simulate high-entropy base64 or hex strings
    length = random.randint(30, 60)
    raw_bytes = bytes(random.getrandbits(8) for _ in range(length))
    if random.choice([True, False]):
        subdomain = base64.urlsafe_b64encode(raw_bytes).decode('utf-8').rstrip('=')
    else:
        subdomain = raw_bytes.hex()
    return f"{subdomain}.{random.choice(['c2-server', 'evil-domain', 'update-sys'])}{random.choice(TLDS)}"

def generate_dictionary_dga():
    # APT style: 3-5 hyphenated words
    word_count = random.randint(3, 5)
    selected = random.sample(WORDS, word_count)
    return "-".join(selected) + random.choice(TLDS)

def generate_typosquat():
    brand = random.choice(BRANDS)
    # Character substitutions
    swaps = {'o': '0', 'i': '1', 'l': 'I', 'e': '3', 'a': '4'}
    new_brand = ""
    for char in brand:
        if char in swaps and random.random() < 0.4:
            new_brand += swaps[char]
        else:
            new_brand += char
    
    # Prefix or Suffix
    if random.random() < 0.5:
        return f"{random.choice(['login-', 'secure-', 'my-'])}{new_brand}{random.choice(TLDS)}"
    else:
        return f"{new_brand}-{random.choice(['verify', 'update', 'support'])}{random.choice(TLDS)}"


def inject_threats():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    count = 0
    domains_to_insert = []
    
    # 1. Inject Tunneling Domains (1000)
    for _ in range(1000):
        domains_to_insert.append((generate_tunneling_domain(), 1, 'synthetic_tunneling', 'tunnel'))
        
    # 2. Inject Dictionary DGAs (1000)
    for _ in range(1000):
        domains_to_insert.append((generate_dictionary_dga(), 1, 'synthetic_dictionary', 'dictionary'))
        
    # 3. Inject Typosquats (1000)
    for _ in range(1000):
        domains_to_insert.append((generate_typosquat(), 1, 'synthetic_typosquat', 'phishing'))
        
    # Insert ignore to prevent dupes (though highly unlikely)
    c.executemany('''
        INSERT OR IGNORE INTO training_domains (domain, label, source, family)
        VALUES (?, ?, ?, ?)
    ''', domains_to_insert)
    
    conn.commit()
    print(f"Successfully injected {len(domains_to_insert)} advanced threat domains into training_domains.")
    conn.close()

if __name__ == '__main__':
    inject_threats()
