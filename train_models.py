import requests, zipfile, io, random, os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from features import extract_features

def fetch(url, timeout=30):
    try:
        r = requests.get(url, timeout=timeout)
        return r.text.splitlines()
    except Exception as e:
        print(f"    Failed: {url} — {e}")
        return []

def url_to_domain(line):
    line = line.strip()
    if not line or line.startswith('#'): return None
    try:
        if '://' in line:
            d = line.split('://')[1].split('/')[0]
        else:
            d = line.split('/')[0]
        if '.' in d and len(d) > 3:
            return d.lower()
    except: pass
    return None

malicious, legit = [], []

# ── DNS ATTACK SOURCES ─────────────────────────────────────

print("[1] DGA botnet domains...")
for line in fetch("https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/master/dga_domains.txt"):
    if line.strip(): malicious.append(line.strip())
print(f"    {len(malicious)} DGA domains")

print("[2] URLhaus active malware...")
prev = len(malicious)
for line in fetch("https://urlhaus.abuse.ch/downloads/text_recent/"):
    d = url_to_domain(line)
    if d: malicious.append(d)
print(f"    {len(malicious)-prev} malware domains")

print("[3] OpenPhish live phishing...")
prev = len(malicious)
for line in fetch("https://openphish.com/feed.txt"):
    d = url_to_domain(line)
    if d: malicious.append(d)
print(f"    {len(malicious)-prev} phishing domains")

print("[4] Botnet C2 domains...")
prev = len(malicious)
for line in fetch("https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"):
    if line.strip() and not line.startswith('#'):
        malicious.append(line.strip())
print(f"    {len(malicious)-prev} C2 domains")

print("[5] Ransomware domains...")
prev = len(malicious)
for line in fetch("https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/ransomware.txt"):
    if line.strip() and not line.startswith('#'):
        malicious.append(line.strip())
print(f"    {len(malicious)-prev} ransomware domains")

# ── URL / PHISHING SOURCES ─────────────────────────────────

print("[6] StealthPhisher database...")
prev = len(malicious)
stealthphisher_sources = [
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://raw.githubusercontent.com/Phishing-Database/phishing-links/main/phishing-links-NEW-today.txt",
    "https://raw.githubusercontent.com/elliotwutingfeng/Inversion-DNSBL-Blocklists/main/Google_hostnames_light.txt",
]
for source in stealthphisher_sources:
    for line in fetch(source):
        d = url_to_domain(line)
        if d: malicious.append(d)
        elif line.strip() and '.' in line and not line.startswith('#'):
            malicious.append(line.strip())
print(f"    {len(malicious)-prev} phishing URLs/domains")

print("[7] PhishTank verified phishing...")
prev = len(malicious)
for line in fetch("https://data.phishtank.com/data/online-valid.csv"):
    if line.startswith('#') or 'url' in line.lower()[:5]: continue
    parts = line.split(',')
    if len(parts) > 1:
        d = url_to_domain(parts[1].replace('"',''))
        if d: malicious.append(d)
print(f"    {len(malicious)-prev} PhishTank domains")

print("[8] Malware domain list...")
prev = len(malicious)
for line in fetch("https://www.malwaredomainlist.com/hostslist/hosts.txt"):
    if line.startswith('#') or not line.strip(): continue
    parts = line.split()
    if len(parts) >= 2 and '.' in parts[-1]:
        malicious.append(parts[-1].lower())
print(f"    {len(malicious)-prev} malware domains")

# ── SYNTHETIC ATTACK PATTERNS ──────────────────────────────

print("[9] Generating synthetic attack patterns...")
import base64, string
rnd = random

brands = [
    'google','paypal','amazon','apple','microsoft',
    'hdfc','sbi','icici','paytm','flipkart','facebook',
    'instagram','netflix','whatsapp','youtube'
]
bad_tlds = ['xyz','tk','ml','cf','ga','top','click','loan','work','online']
keywords = ['login','secure','verify','account','update','alert','confirm','reset','suspended','auth']

# Typosquatting
for brand in brands:
    for kw in keywords:
        for tld in bad_tlds[:4]:
            malicious.append(f"{brand}-{kw}.{tld}")
            malicious.append(f"{brand[:-1]}1-{kw}.{tld}")
            malicious.append(f"secure-{brand}-{kw}.{tld}")

# DNS tunneling (base64 subdomains)
for _ in range(3000):
    payload = base64.b64encode(
        ''.join(rnd.choices(string.ascii_letters+string.digits, k=20)).encode()
    ).decode().replace('=','').lower()[:20]
    malicious.append(f"{payload}.c2-server.{rnd.choice(bad_tlds)}")

# DGA simulation
for _ in range(3000):
    length = rnd.randint(10, 20)
    consonants = 'bcdfghjklmnpqrstvwxyz'
    domain = ''.join(rnd.choices(consonants + string.digits, k=length))
    malicious.append(f"{domain}.{rnd.choice(bad_tlds)}")

# Fast flux
for _ in range(2000):
    d = ''.join(rnd.choices(string.ascii_lowercase, k=rnd.randint(8,15)))
    malicious.append(f"{d}.{rnd.choice(bad_tlds)}")

print(f"    Synthetic patterns added")

# ── LEGITIMATE SOURCES ─────────────────────────────────────

print("[10] Tranco top 1M legitimate domains...")
try:
    r = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=60)
    z = zipfile.ZipFile(io.BytesIO(r.content))
    data = z.read(z.namelist()[0]).decode()
    legit = [
        l.split(',')[1].strip()
        for l in data.splitlines()[:60000]
        if ',' in l
    ]
    print(f"    {len(legit)} legitimate domains")
except Exception as e:
    print(f"    Tranco failed: {e}")

# Manually add known safe domains
safe_manual = [
    'google.com','youtube.com','facebook.com','twitter.com','instagram.com',
    'linkedin.com','github.com','stackoverflow.com','reddit.com','wikipedia.org',
    'amazon.com','flipkart.com','paytm.com','sbi.co.in','hdfcbank.com',
    'icicibank.com','infosec.ink','microsoft.com','apple.com','netflix.com',
    'cloudflare.com','stripe.com','shopify.com','notion.so','figma.com',
    'canva.com','zoom.us','slack.com','discord.com','telegram.org'
]
legit.extend(safe_manual)

# ── BUILD DATASET ──────────────────────────────────────────

malicious = list(set(malicious))
legit = list(set(legit))
random.shuffle(malicious)
random.shuffle(legit)

limit = min(len(malicious), len(legit), 45000)
all_data = (
    [(d, 1) for d in malicious[:limit]] +
    [(d, 0) for d in legit[:limit]]
)
random.shuffle(all_data)

print(f"\nDataset: {len(all_data)} total | {limit} malicious | {limit} clean")

# ── EXTRACT FEATURES ───────────────────────────────────────

print("\n[11] Extracting 17 features...")
X, y = [], []
errors = 0
for domain, label in all_data:
    try:
        f = extract_features(domain)
        if len(f) == 17:
            X.append(f)
            y.append(label)
    except:
        errors += 1

X = np.array(X)
y = np.array(y)
print(f"    Features extracted: {len(X)} | Errors skipped: {errors}")

# ── TRAIN DGA MODEL ────────────────────────────────────────

print("\n[12] Training Random Forest (200 trees)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    stratify=y,
    random_state=42
)
rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    class_weight='balanced',
    min_samples_leaf=2,
    n_jobs=-1,
    random_state=42
)
rf.fit(X_train, y_train)
print("\nDGA Model Report:")
print(classification_report(y_test, rf.predict(X_test)))
joblib.dump(rf, 'models/dga_rf_model.pkl')
print("Saved: models/dga_rf_model.pkl")

# ── TRAIN TUNNELING MODEL ──────────────────────────────────

print("\n[13] Training Isolation Forest...")
clean_X = X[y == 0]
iso = IsolationForest(
    n_estimators=200,
    contamination=0.01,
    max_samples='auto',
    random_state=42,
    n_jobs=-1
)
iso.fit(clean_X)
joblib.dump(iso, 'models/tunneling_iso_model.pkl')
print("Saved: models/tunneling_iso_model.pkl")

# ── SANITY CHECK ───────────────────────────────────────────

print("\n[14] Sanity Check:")
print("-" * 65)
tests = [
    ("google.com",                      "CLEAN"),
    ("youtube.com",                     "CLEAN"),
    ("github.com",                      "CLEAN"),
    ("infosec.ink",                     "CLEAN"),
    ("sbi.co.in",                       "CLEAN"),
    ("xkqzr7abmncvpq.com",              "DGA"),
    ("a7f3k9zxvbnm.tk",                 "DGA"),
    ("bcdfghjklm12345.xyz",             "DGA"),
    ("paypa1-secure-login.xyz",         "PHISHING"),
    ("hdfc-account-verify.ml",          "PHISHING"),
    ("amaz0n-update-alert.tk",          "PHISHING"),
    ("secure-google-login.cf",          "PHISHING"),
    ("aGVsbG8KdG9rZW4uZXZpbA.c2.ml",   "TUNNEL"),
    ("dGVzdHBheWxvYWQ.evil-c2.xyz",     "TUNNEL"),
]
for domain, expected in tests:
    try:
        f = np.array([extract_features(domain)])
        dga = rf.predict_proba(f)[0][1]
        tun = iso.decision_function(f)[0]
        threat = dga > 0.55 or tun < -0.1
        flag = "THREAT" if threat else "CLEAN"
        ok = "[PASS]" if (threat and expected != "CLEAN") or (not threat and expected == "CLEAN") else "[FAIL]"
        print(f"{ok} {domain:42} DGA:{dga:.2f} Tunnel:{tun:.3f} | {expected}")
    except Exception as e:
        print(f"? {domain} ERROR: {e}")

print("\n[SUCCESS] Training complete. Both models saved and ready.")
