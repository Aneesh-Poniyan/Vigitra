import pandas as pd
import numpy as np
import math
import joblib
from collections import Counter
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

HIGH_RISK_TLDS = [
    "xyz",
    "top",
    "club",
    "online",
    "site",
    "live",
    "click",
    "loan",
    "work",
    "gq",
    "ml",
    "cf",
    "ga",
    "tk",
]
SUSPICIOUS_KEYWORDS = [
    "login",
    "secure",
    "account",
    "update",
    "verify",
    "bank",
    "paypal",
    "amazon",
    "apple",
    "microsoft",
]
TRUSTED_BRANDS = [
    "google",
    "paypal",
    "amazon",
    "apple",
    "microsoft",
    "facebook",
    "hdfc",
    "sbi",
    "icici",
    "paytm",
    "flipkart",
]


def levenshtein(a, b):
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def extract_features(domain):
    domain = domain.lower().strip()
    parts = domain.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    sld = parts[0] if parts else domain  # second level domain

    freq = Counter(sld)
    p = [v / len(sld) for v in freq.values()] if sld else [1]
    entropy = -sum(x * math.log2(x) for x in p if x > 0)

    common_bigrams = {"th", "he", "in", "er", "an", "re", "on", "en", "at", "es"}
    bigrams = [sld[i : i + 2] for i in range(len(sld) - 1)]
    ngram_randomness = 1 - (
        sum(1 for b in bigrams if b in common_bigrams) / max(len(bigrams), 1)
    )

    repeated = sum(1 for i in range(1, len(sld)) if sld[i] == sld[i - 1])
    repeated_char_score = repeated / max(len(sld), 1)

    tld_risk = 1.0 if tld in HIGH_RISK_TLDS else 0.0

    suspicious_keyword_score = sum(
        1 for kw in SUSPICIOUS_KEYWORDS if kw in domain
    ) / len(SUSPICIOUS_KEYWORDS)

    min_dist = min((levenshtein(sld, brand) for brand in TRUSTED_BRANDS), default=99)
    lookalike_score = 1.0 if (0 < min_dist <= 2) else 0.0

    vowels = set("aeiou")
    max_cons, curr = 0, 0
    for c in sld:
        if c.isalpha() and c not in vowels:
            curr += 1
            max_cons = max(max_cons, curr)
        else:
            curr = 0

    hex_chars = set("0123456789abcdef")
    hex_ratio = sum(1 for c in sld if c in hex_chars) / max(len(sld), 1)

    return [
        len(domain),  # length
        len(parts) - 1,  # num_subdomains
        sum(c in vowels for c in sld) / max(len(sld), 1),  # vowel_ratio
        sum(c.isalpha() and c not in vowels for c in sld)
        / max(len(sld), 1),  # consonant_ratio
        sum(c.isdigit() for c in sld) / max(len(sld), 1),  # digit_ratio
        sum(not c.isalnum() for c in sld),  # special_char_count
        entropy,  # entropy
        ngram_randomness,  # ngram_randomness
        repeated_char_score,  # repeated_char_score
        tld_risk,  # tld_risk
        suspicious_keyword_score,  # suspicious_keyword_score
        lookalike_score,  # lookalike_score
        max_cons,  # max_consecutive_consonants
        len(set(sld)) / max(len(sld), 1),  # unique_char_ratio
        hex_ratio,  # hex_char_ratio
    ]


if __name__ == "__main__":
    print("Loading dataset natively from SQLite cache...")
    import sqlite3

    conn = sqlite3.connect("dns_filter.db")
    df = pd.read_sql_query("SELECT domain, label as class FROM training_domains", conn)
    conn.close()
    df = df.sample(n=min(200000, len(df)), random_state=42)

    print("Extracting features...")
    X = np.array([extract_features(d) for d in df["domain"]])
    y = df["class"].values

    print("Training Random Forest...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    rf.fit(X_train, y_train)
    print(classification_report(y_test, rf.predict(X_test)))
    joblib.dump(rf, "models/dga_rf_model.pkl")
    print("Saved: models/dga_rf_model.pkl")

    print("Training Isolation Forest...")
    clean_domains = df[y == 0]["domain"].values[:5000]
    X_clean = np.array([extract_features(d) for d in clean_domains])
    iso = IsolationForest(contamination=0.05, random_state=42, n_jobs=-1)
    iso.fit(X_clean)
    joblib.dump(iso, "models/tunneling_iso_model.pkl")
    print("Saved: models/tunneling_iso_model.pkl")

    print("\n--- Sanity Check ---")
    test_cases = [
        ("google.com", "should be CLEAN"),
        ("xkqzr7abmncvpq.com", "should be DGA"),
        ("paypa1.com", "should flag LOOKALIKE"),
        ("aGVsbG8.evilc2.xyz", "should be DGA/TUNNEL"),
    ]
    for domain, expected in test_cases:
        feats = np.array([extract_features(domain)])
        dga_score = rf.predict_proba(feats)[0][1]
        tunnel_score = iso.decision_function(feats)[0]
        print(f"{domain:35} DGA:{dga_score:.2f} Tunnel:{tunnel_score:.2f} | {expected}")
