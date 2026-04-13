"""
IntrusionX - Enhanced Dataset Ingestion & Model Retraining Pipeline
enhance_and_retrain.py

Downloads real-world threat intelligence from multiple sources:
  1. OpenPhish       — Live phishing URLs (stealth phishing domains)
  2. PhishTank       — Community-verified phishing URLs
  3. URLhaus (Abuse.ch) — Malware distribution URLs
  4. Netlab 360 DGA  — Real DGA domain families
  5. Bambenek DGA    — IoC feeds for DGA families
  6. Majestic Million — Additional legitimate domain baseline
  7. Synthetic phishing — Algorithmically generated brand-squatting domains

Then retrains both ML models (Random Forest DGA + Isolation Forest Tunneling)
with all 17 features for maximum accuracy.
"""

import sys
import os
if os.name == 'nt':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

import urllib.request
import sqlite3
import csv
import io
import time
import random
import string
import ssl
import json
import re
import zipfile
import numpy as np
import pandas as pd
import joblib
from urllib.parse import urlparse, unquote
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix
)

DB_FILE = "dns_filter.db"

# Allow unverified SSL for some feeds
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def extract_domain_from_url(url: str) -> str:
    """Extract clean domain from a full URL."""
    url = url.strip()
    url = unquote(url)
    if not url.startswith("http"):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        if ":" in netloc:
            netloc = netloc.split(":")[0]
        return netloc.lower().strip(".")
    except Exception:
        return ""

# ============================================================
# STEP 1: DOWNLOAD AND INGEST NEW THREAT DATA
# ============================================================

def ingest_openphish(conn, limit=3000):
    """Download OpenPhish community feed — live stealth phishing URLs."""
    print("\n  [OpenPhish] Downloading live phishing feed...")
    url = "https://openphish.com/feed.txt"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IntrusionX/2.0"})
        response = urllib.request.urlopen(req, timeout=20, context=ctx)
        data = response.read().decode("utf-8", errors="ignore")
        c = conn.cursor()
        count = 0
        domains_seen = set()
        for line in data.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domain = extract_domain_from_url(line)
            if domain and len(domain) > 3 and domain not in domains_seen:
                domains_seen.add(domain)
                c.execute(
                    "INSERT OR IGNORE INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)",
                    (domain, "openphish", "phishing"),
                )
                count += 1
                if count >= limit:
                    break
        conn.commit()
        print(f"    ✓ Ingested {count} phishing domains from OpenPhish")
        return count
    except Exception as e:
        print(f"    ✗ OpenPhish failed: {e}")
        return 0


def ingest_phishtank_like(conn, limit=2000):
    """Download phishing domains from multiple community sources."""
    print("\n  [PhishStats] Downloading phishing URL feed...")
    # PhishStats API — recent phishing URLs
    url = "https://phishstats.info/phish_score.csv"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IntrusionX/2.0"})
        response = urllib.request.urlopen(req, timeout=30, context=ctx)
        data = response.read().decode("utf-8", errors="ignore")
        c = conn.cursor()
        count = 0
        domains_seen = set()
        for line in data.strip().split("\n"):
            if line.startswith("#") or line.startswith('"date'):
                continue
            # CSV: date, score, url, ip
            parts = line.split(",")
            if len(parts) >= 3:
                raw_url = parts[2].strip().strip('"')
                domain = extract_domain_from_url(raw_url)
                if domain and len(domain) > 3 and domain not in domains_seen:
                    domains_seen.add(domain)
                    c.execute(
                        "INSERT OR IGNORE INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)",
                        (domain, "phishstats", "phishing"),
                    )
                    count += 1
                    if count >= limit:
                        break
        conn.commit()
        print(f"    ✓ Ingested {count} phishing domains from PhishStats")
        return count
    except Exception as e:
        print(f"    ✗ PhishStats failed: {e}")
        return 0


def ingest_urlhaus(conn, limit=3000):
    """Download Abuse.ch URLhaus malware distribution URLs."""
    print("\n  [URLhaus] Downloading malware URL feed...")
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IntrusionX/2.0"})
        response = urllib.request.urlopen(req, timeout=30, context=ctx)
        data = response.read().decode("utf-8", errors="ignore")
        c = conn.cursor()
        count = 0
        domains_seen = set()
        for line in data.strip().split("\n"):
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split('","')
            if len(parts) >= 3:
                raw_url = parts[2].strip().strip('"')
                domain = extract_domain_from_url(raw_url)
                if domain and len(domain) > 3 and domain not in domains_seen and not re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                    domains_seen.add(domain)
                    c.execute(
                        "INSERT OR IGNORE INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)",
                        (domain, "urlhaus", "malware"),
                    )
                    # Also add to blocklist
                    c.execute(
                        "INSERT OR IGNORE INTO static_blocklist (domain, category, source) VALUES (?, ?, ?)",
                        (domain, "Malware", "URLhaus"),
                    )
                    count += 1
                    if count >= limit:
                        break
        conn.commit()
        print(f"    ✓ Ingested {count} malware domains from URLhaus")
        return count
    except Exception as e:
        print(f"    ✗ URLhaus failed: {e}")
        return 0


def ingest_netlab_dga(conn, limit=5000):
    """Download Netlab 360 DGA domain feed."""
    print("\n  [Netlab360] Downloading DGA domain feed...")
    # Use the DGA archive feed
    url = "https://data.netlab.360.com/feeds/dga/dga.txt"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IntrusionX/2.0"})
        response = urllib.request.urlopen(req, timeout=30, context=ctx)
        data = response.read().decode("utf-8", errors="ignore")
        c = conn.cursor()
        count = 0
        for line in data.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Format: family\tdomain or just domain
            parts = line.split("\t")
            if len(parts) >= 2:
                family = parts[0].strip().lower()
                domain = parts[1].strip().lower()
            else:
                family = "unknown_dga"
                domain = parts[0].strip().lower()
            if domain and len(domain) > 3 and "." in domain:
                c.execute(
                    "INSERT OR IGNORE INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)",
                    (domain, "netlab360_dga", family),
                )
                count += 1
                if count >= limit:
                    break
        conn.commit()
        print(f"    ✓ Ingested {count} DGA domains from Netlab 360")
        return count
    except Exception as e:
        print(f"    ✗ Netlab360 DGA failed: {e}")
        return 0


def ingest_bambenek_dga(conn, limit=3000):
    """Download Bambenek Consulting DGA domain feed."""
    print("\n  [Bambenek] Downloading DGA IoC feed...")
    url = "https://osint.bambenekconsulting.com/feeds/dga-feed.txt"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IntrusionX/2.0"})
        response = urllib.request.urlopen(req, timeout=20, context=ctx)
        data = response.read().decode("utf-8", errors="ignore")
        c = conn.cursor()
        count = 0
        for line in data.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Format: domain,description,date,...
            parts = line.split(",")
            if not parts:
                continue
            domain = parts[0].strip().lower()
            family = parts[1].strip().lower() if len(parts) > 1 else "unknown"
            if domain and len(domain) > 3 and "." in domain:
                c.execute(
                    "INSERT OR IGNORE INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)",
                    (domain, "bambenek_dga", family),
                )
                count += 1
                if count >= limit:
                    break
        conn.commit()
        print(f"    ✓ Ingested {count} DGA domains from Bambenek")
        return count
    except Exception as e:
        print(f"    ✗ Bambenek failed: {e}")
        return 0


def ingest_majestic_legit(conn, limit=5000):
    """Download Majestic Million for additional legitimate domain baseline."""
    print("\n  [Majestic] Downloading top legitimate domains...")
    url = "https://downloads.majestic.com/majestic_million.csv"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IntrusionX/2.0"})
        response = urllib.request.urlopen(req, timeout=30, context=ctx)
        data = response.read().decode("utf-8", errors="ignore")
        reader = csv.reader(io.StringIO(data))
        c = conn.cursor()
        count = 0
        header_skipped = False
        for row in reader:
            if not header_skipped:
                header_skipped = True
                continue
            if len(row) >= 3:
                domain = row[2].strip().lower()
                if domain and len(domain) > 3:
                    c.execute(
                        "INSERT OR IGNORE INTO training_domains (domain, label, source, family) VALUES (?, 0, ?, ?)",
                        (domain, "majestic_million", "legitimate"),
                    )
                    count += 1
                    if count >= limit:
                        break
        conn.commit()
        print(f"    ✓ Ingested {count} legitimate domains from Majestic Million")
        return count
    except Exception as e:
        print(f"    ✗ Majestic Million failed: {e}")
        return 0


def generate_stealth_phishing_domains(conn, count=2000):
    """
    Generate highly realistic stealth phishing domains that mimic real-world attack patterns:
    - Homoglyph attacks (l→1, o→0, rn→m)
    - Typosquatting (character swaps, missing chars, extra chars)
    - Combo-squatting (brand + keyword)
    - TLD abuse (.xyz, .top, .tk, .club)
    - Subdomain abuse (e.g., google.com.evil.xyz)
    """
    print("\n  [Synthetic] Generating stealth phishing domain variants...")
    rng = random.Random(2026)

    brands = [
        "google", "paypal", "amazon", "facebook", "microsoft", "apple",
        "netflix", "instagram", "twitter", "linkedin", "dropbox", "adobe",
        "yahoo", "ebay", "spotify", "zoom", "slack", "github",
        "flipkart", "paytm", "sbi", "hdfc", "icici", "razorpay",
        "swiggy", "zomato", "whatsapp", "telegram", "snapchat", "tiktok",
        "chase", "wellsfargo", "bankofamerica", "citibank", "americanexpress",
        "stripe", "shopify", "coinbase", "binance", "metamask",
    ]

    phish_keywords = [
        "login", "verify", "secure", "update", "account", "confirm",
        "signin", "support", "helpdesk", "reset", "password", "recovery",
        "authentication", "billing", "invoice", "payment", "wallet",
        "checkout", "refund", "suspended", "blocked", "unlock", "kyc",
        "otp", "alert", "notification", "service", "portal", "access",
    ]

    risky_tlds = [
        "xyz", "top", "tk", "gq", "cf", "ml", "ga", "club", "online",
        "site", "click", "link", "info", "biz", "pw", "cc", "live",
        "work", "shop", "store", "space", "fun", "website", "tech",
    ]

    homoglyph_map = {
        'a': ['@', '4', 'á', 'à'],
        'e': ['3', 'é', 'è'],
        'i': ['1', 'l', '!', 'í'],
        'o': ['0', 'ó', 'ò'],
        'l': ['1', 'I'],
        's': ['5', '$'],
        't': ['7'],
        'g': ['9', 'q'],
        'b': ['d', '6'],
    }

    c = conn.cursor()
    generated = set()
    inserted = 0

    for _ in range(count):
        brand = rng.choice(brands)
        technique = rng.random()

        if technique < 0.20:
            # Homoglyph substitution
            result = list(brand)
            num_subs = rng.randint(1, 2)
            for _ in range(num_subs):
                for i, ch in enumerate(result):
                    if ch in homoglyph_map and rng.random() < 0.5:
                        result[i] = rng.choice(homoglyph_map[ch])
                        break
            domain = "".join(result)
            tld = rng.choice(risky_tlds)
            full = f"{domain}.{tld}"

        elif technique < 0.40:
            # Combo-squatting: brand + phishing keyword
            kw = rng.choice(phish_keywords)
            sep = rng.choice(["-", "", "."])
            order = rng.random()
            tld = rng.choice(risky_tlds)
            if order < 0.5:
                full = f"{brand}{sep}{kw}.{tld}"
            else:
                full = f"{kw}{sep}{brand}.{tld}"

        elif technique < 0.55:
            # Typosquatting: swap, drop, duplicate, insert adjacent
            result = list(brand)
            typo = rng.random()
            if typo < 0.3 and len(result) > 3:
                # Swap adjacent chars
                idx = rng.randint(0, len(result) - 2)
                result[idx], result[idx + 1] = result[idx + 1], result[idx]
            elif typo < 0.55 and len(result) > 4:
                # Drop a char
                idx = rng.randint(1, len(result) - 2)
                result.pop(idx)
            elif typo < 0.75:
                # Duplicate a char
                idx = rng.randint(0, len(result) - 1)
                result.insert(idx, result[idx])
            else:
                # Insert random adjacent keyboard char
                idx = rng.randint(0, len(result) - 1)
                adj = chr(ord(result[idx]) + rng.choice([-1, 1]))
                result.insert(idx + 1, adj)
            domain = "".join(result)
            tld = rng.choice(risky_tlds)
            full = f"{domain}.{tld}"

        elif technique < 0.70:
            # Subdomain abuse: brand.com.attack.xyz
            tld = rng.choice(risky_tlds)
            evil_word = rng.choice(["security", "verify", "auth", "check", "portal", "srv", "api", "cdn"])
            full = f"{brand}.com.{evil_word}.{tld}"

        elif technique < 0.80:
            # Hyphenated keyword chain: secure-paypal-login-verify.xyz
            kws = rng.sample(phish_keywords, rng.randint(2, 3))
            brand_pos = rng.randint(0, len(kws))
            kws.insert(brand_pos, brand)
            tld = rng.choice(risky_tlds)
            full = "-".join(kws) + f".{tld}"

        elif technique < 0.90:
            # Brand with number injection: paypa1, g00gle, amaz0n
            result = brand
            for old, new in [('l', '1'), ('o', '0'), ('a', '4'), ('e', '3'), ('i', '1'), ('s', '5')]:
                if old in result and rng.random() < 0.6:
                    result = result.replace(old, new, 1)
                    break
            kw = rng.choice(phish_keywords)
            tld = rng.choice(risky_tlds)
            full = f"{result}-{kw}.{tld}"

        else:
            # IDN / punycode-style (ASCII representation)
            xn_label = "xn--" + "".join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(8, 16)))
            tld = rng.choice(risky_tlds)
            full = f"{xn_label}.{tld}"

        full = full.lower()
        if full not in generated and len(full) > 5:
            generated.add(full)
            c.execute(
                "INSERT OR IGNORE INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)",
                (full, "synthetic_stealth", "phishing"),
            )
            inserted += 1

    conn.commit()
    print(f"    ✓ Generated {inserted} stealth phishing domain variants")
    return inserted


def generate_advanced_tunneling_domains(conn, count=1000):
    """
    Generate realistic DNS tunneling domains with various encoding patterns:
    - Base64 subdomains
    - Hex-encoded data
    - High-entropy random subdomains
    - Long chained subdomains simulating data exfiltration
    """
    print("\n  [Synthetic] Generating DNS tunneling domain variants...")
    rng = random.Random(2026)
    c = conn.cursor()
    inserted = 0

    c2_bases = [
        "evil.com", "c2server.org", "badactor.net", "malware.xyz",
        "tunnel.info", "dropper.top", "beacon.club", "exfil.tk",
        "shell.gq", "keylog.cf", "capture.ml", "stealer.pw",
        "botnet.cc", "payload.work", "backdoor.site", "rat.live",
        "implant.online", "stage.click", "loader.link", "crypter.space",
    ]

    for _ in range(count):
        technique = rng.random()
        base = rng.choice(c2_bases)

        if technique < 0.35:
            # Base64-encoded subdomain
            payload_len = rng.randint(10, 45)
            payload = "".join(rng.choices(string.ascii_letters + string.digits, k=payload_len))
            encoded = __import__("base64").b64encode(payload.encode()).decode().rstrip("=")
            domain = f"{encoded}.{base}"

        elif technique < 0.60:
            # Hex-encoded subdomain
            hex_len = rng.randint(16, 48)
            hex_str = "".join(rng.choices("0123456789abcdef", k=hex_len))
            domain = f"{hex_str}.{base}"

        elif technique < 0.80:
            # Multi-level chained subdomains (simulating large data exfiltration)
            num_levels = rng.randint(3, 6)
            parts = []
            for _ in range(num_levels):
                part_len = rng.randint(8, 20)
                part = "".join(rng.choices(string.ascii_lowercase + string.digits, k=part_len))
                parts.append(part)
            domain = ".".join(parts) + f".{base}"

        else:
            # High-entropy random subdomain
            sub_len = rng.randint(20, 55)
            sub = "".join(rng.choices(string.ascii_lowercase + string.digits + "-", k=sub_len))
            sub = sub.strip("-")
            domain = f"{sub}.{base}"

        domain = domain.lower()
        if len(domain) > 10:
            c.execute(
                "INSERT OR IGNORE INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)",
                (domain, "synthetic_tunnel", "tunneling"),
            )
            inserted += 1

    conn.commit()
    print(f"    ✓ Generated {inserted} DNS tunneling domain variants")
    return inserted


# ============================================================
# STEP 2: RETRAIN MODELS WITH FULL 17 FEATURES
# ============================================================

def retrain_models():
    """Load all data, extract 17 features, and retrain both models."""
    from features import extract_features
    FEATURE_NAMES = [
        "length", "num_subdomains", "vowel_ratio", "consonant_ratio", "digit_ratio",
        "special_char_count", "entropy", "ngram_randomness", "repeated_char_score",
        "tld_risk", "suspicious_keyword_score", "lookalike_score", "max_consec_cons",
        "unique_char_ratio", "hex_char_ratio", "jaro_winkler_score", "char_continuity"
    ]

    print("\n" + "═" * 65)
    print("  RETRAINING MODELS WITH ENHANCED DATASET")
    print("═" * 65)

    # Load training data
    print("\n─── Loading Training Data ───")
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT domain, label, source FROM training_domains", conn)
    conn.close()

    print(f"  Raw rows: {len(df):,}")
    df = df.dropna(subset=["domain"])
    df["domain"] = df["domain"].str.strip().str.lower()
    df = df[df["domain"].str.len() > 2]
    df = df[df["domain"].str.contains(r"\.", regex=True)]  # Must have a dot (valid domain)
    df = df.drop_duplicates(subset=["domain"])

    print(f"  After dedup/clean: {len(df):,} unique domains")
    print(f"\n  Class distribution:")
    for label, count in df["label"].value_counts().items():
        name = "Legitimate" if label == 0 else "Malicious"
        print(f"    [{label}] {name}: {count:,}")

    print(f"\n  Source breakdown:")
    for source, count in df["source"].value_counts().head(15).items():
        print(f"    {source:<25} {count:>6,}")

    # Extract features
    print(f"\n─── Extracting {len(FEATURE_NAMES)} Features ───")
    t0 = time.time()
    X_rows = []
    valid_indices = []
    errors = 0
    for i, row in df.iterrows():
        try:
            feats = extract_features(row["domain"])
            X_rows.append(feats)
            valid_indices.append(i)
        except Exception:
            errors += 1

    X = np.array(X_rows, dtype=np.float32)
    y = df.loc[valid_indices, "label"].values

    print(f"  Feature extraction: {time.time()-t0:.2f}s ({errors} errors skipped)")
    print(f"  Feature matrix shape: {X.shape}")
    print(f"  Features: {FEATURE_NAMES}")

    # ======================
    # MODEL 1: Random Forest DGA Classifier (Enhanced)
    # ======================
    print("\n" + "═" * 65)
    print("  MODEL 1: Enhanced Random Forest DGA Classifier")
    print("═" * 65)

    idx_legit = np.where(y == 0)[0]
    idx_mal = np.where(y == 1)[0]
    min_class = min(len(idx_legit), len(idx_mal))

    rng = np.random.RandomState(42)
    idx_legit_s = rng.choice(idx_legit, min_class, replace=False)
    idx_mal_s = rng.choice(idx_mal, min_class, replace=False)
    idx_balanced = np.concatenate([idx_legit_s, idx_mal_s])
    rng.shuffle(idx_balanced)

    X_bal, y_bal = X[idx_balanced], y[idx_balanced]
    print(f"  Balanced dataset: {len(X_bal):,} samples ({min_class:,} per class)")

    X_train, X_test, y_train, y_test = train_test_split(
        X_bal, y_bal, test_size=0.2, random_state=42, stratify=y_bal
    )

    print("  Training Random Forest (300 trees, max_depth=25)...")
    rf_model = RandomForestClassifier(
        n_estimators=300,        # More trees for stability
        max_depth=25,            # Deeper trees for complex patterns
        min_samples_split=3,     # Slightly less restrictive
        min_samples_leaf=2,
        max_features="sqrt",     # sqrt instead of log2 for better feature exploration
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
        oob_score=True,          # Out-of-bag score for free validation
    )
    t0 = time.time()
    rf_model.fit(X_train, y_train)
    train_time = time.time() - t0
    print(f"  Training time: {train_time:.2f}s")
    print(f"  OOB Score: {rf_model.oob_score_*100:.2f}%")

    y_pred = rf_model.predict(X_test)
    y_proba = rf_model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print(f"\n  ── Test Set Results ──")
    print(f"  Accuracy:  {acc*100:.2f}%")
    print(f"  Precision: {prec*100:.2f}%")
    print(f"  Recall:    {rec*100:.2f}%")
    print(f"  F1 Score:  {f1*100:.2f}%")
    print(f"\n{classification_report(y_test, y_pred, target_names=['Legitimate','Malicious'])}")

    cm = confusion_matrix(y_test, y_pred)
    print(f"  Confusion Matrix:")
    print(f"    TN={cm[0,0]:>5}  FP={cm[0,1]:>5}")
    print(f"    FN={cm[1,0]:>5}  TP={cm[1,1]:>5}")

    # Cross-validation
    print(f"\n  Running 5-Fold Stratified Cross-Validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(rf_model, X_bal, y_bal, cv=cv, scoring="f1", n_jobs=-1)
    print(f"  F1 CV Scores: {[f'{s:.4f}' for s in cv_scores]}")
    print(f"  Mean F1: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")

    # Feature importance
    importances = sorted(
        zip(FEATURE_NAMES, rf_model.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print(f"\n  ── Feature Importances ──")
    for name, imp in importances:
        bar = "█" * int(imp * 60)
        print(f"  {name:<32} {imp:.4f}  {bar}")

    # ======================
    # MODEL 2: Isolation Forest Anomaly Detector (Enhanced)
    # ======================
    print("\n" + "═" * 65)
    print("  MODEL 2: Enhanced Isolation Forest Anomaly Detector")
    print("═" * 65)

    X_legit = X[y == 0]
    print(f"  Training on {len(X_legit):,} legitimate domains only")

    iso_model = IsolationForest(
        n_estimators=300,                          # More estimators
        max_samples=min(512, len(X_legit)),         # Larger sample size
        contamination=0.008,                       # Very low contamination for precision
        max_features=1.0,
        random_state=42,
        n_jobs=-1,
    )
    t0 = time.time()
    iso_model.fit(X_legit)
    print(f"  Training time: {time.time()-t0:.2f}s")

    # Sanity check
    legit_sample = X[y == 0][:200]
    mal_sample = X[y == 1][:200]

    legit_preds = iso_model.predict(legit_sample)
    mal_preds = iso_model.predict(mal_sample)

    legit_anomaly_rate = (legit_preds == -1).mean()
    mal_anomaly_rate = (mal_preds == -1).mean()

    legit_scores = iso_model.score_samples(legit_sample)
    mal_scores = iso_model.score_samples(mal_sample)

    print(f"\n  ── Sanity Check ──")
    print(f"  Legit domains flagged as anomaly: {legit_anomaly_rate*100:.1f}% (target: <3%)")
    print(f"  Malicious flagged as anomaly:     {mal_anomaly_rate*100:.1f}% (target: >60%)")
    print(f"  Avg anomaly score (legit): {legit_scores.mean():.4f}")
    print(f"  Avg anomaly score (mal):   {mal_scores.mean():.4f}")

    # ======================
    # SAVE MODELS
    # ======================
    print("\n─── Saving Models ───")
    joblib.dump(rf_model, "models/dga_rf_model.pkl")
    joblib.dump(iso_model, "models/tunneling_iso_model.pkl")
    print("  [SAVED] models/dga_rf_model.pkl")
    print("  [SAVED] models/tunneling_iso_model.pkl")

    return acc, f1, cv_scores.mean()


# ============================================================
# MAIN
# ============================================================

def main():
    total_start = time.time()

    print()
    print("═" * 65)
    print("  IntrusionX — Enhanced Data Ingestion & Retraining Pipeline")
    print("═" * 65)
    print()

    conn = sqlite3.connect(DB_FILE)

    # Ensure training_domains table exists
    conn.execute("""CREATE TABLE IF NOT EXISTS training_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT, label INTEGER, source TEXT, family TEXT DEFAULT 'unknown'
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_training_domain ON training_domains (domain)")
    conn.commit()

    # Get counts before
    before_legit = conn.execute("SELECT COUNT(*) FROM training_domains WHERE label=0").fetchone()[0]
    before_mal = conn.execute("SELECT COUNT(*) FROM training_domains WHERE label=1").fetchone()[0]
    print(f"  Current dataset: {before_legit:,} legit + {before_mal:,} malicious = {before_legit + before_mal:,} total")

    # Download from all sources
    print("\n" + "─" * 65)
    print("  PHASE 1: INGESTING NEW THREAT DATA")
    print("─" * 65)

    total_new = 0
    # Ingestion already complete in previous run
    # total_new += ingest_openphish(conn, limit=3000)
    # total_new += ingest_phishtank_like(conn, limit=2000)
    # total_new += ingest_urlhaus(conn, limit=3000)
    # total_new += ingest_netlab_dga(conn, limit=5000)
    # total_new += ingest_bambenek_dga(conn, limit=3000)
    # total_new += ingest_majestic_legit(conn, limit=5000)
    # total_new += generate_stealth_phishing_domains(conn, count=2500)
    # total_new += generate_advanced_tunneling_domains(conn, count=1500)

    # Get counts after
    after_legit = conn.execute("SELECT COUNT(*) FROM training_domains WHERE label=0").fetchone()[0]
    after_mal = conn.execute("SELECT COUNT(*) FROM training_domains WHERE label=1").fetchone()[0]
    blocklist = conn.execute("SELECT COUNT(*) FROM static_blocklist").fetchone()[0]

    conn.close()

    print(f"\n" + "─" * 65)
    print(f"  INGESTION SUMMARY")
    print(f"─" * 65)
    print(f"  Before: {before_legit + before_mal:,} total ({before_legit:,} legit + {before_mal:,} mal)")
    print(f"  After:  {after_legit + after_mal:,} total ({after_legit:,} legit + {after_mal:,} mal)")
    print(f"  New domains added: {total_new:,}")
    print(f"  Static blocklist: {blocklist:,} entries")

    # Phase 2: Retrain models
    print(f"\n" + "─" * 65)
    print("  PHASE 2: RETRAINING ML MODELS")
    print("─" * 65)

    acc, f1, cv_f1 = retrain_models()

    total_time = time.time() - total_start

    print(f"\n{'═'*65}")
    print(f"  ENHANCEMENT COMPLETE")
    print(f"{'═'*65}")
    print(f"  Total Time:        {total_time:.1f}s")
    print(f"  Final Dataset:     {after_legit + after_mal:,} domains")
    print(f"  Accuracy:          {acc*100:.2f}%")
    print(f"  F1 Score:          {f1*100:.2f}%")
    print(f"  CV Mean F1:        {cv_f1*100:.2f}%")
    print(f"  Blocklist:         {blocklist:,} entries")
    print(f"{'═'*65}\n")


if __name__ == "__main__":
    main()
