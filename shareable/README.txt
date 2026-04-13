=====================================================================
  IntrusionX - Shareable Database Package
  DNS Threat Detection & ML Training Database
=====================================================================

REQUIREMENTS:
  - Python 3.8 or higher (no pip installs needed)
  - Internet connection (for downloading real datasets)

HOW TO USE:
  1. Open terminal / command prompt
  2. Navigate to this folder
  3. Run:   python build_database.py
  4. Copy dns_filter.db to the main project folder
  5. Run:   python train_models.py   (trains the ML models)
  6. Run:   python app.py            (launches the dashboard)

NOTE: If internet is unavailable, the script will automatically
fall back to embedded data. No manual intervention needed.

=====================================================================
  DATASET SOURCES & REFERENCES
=====================================================================

Our training database is built from multiple real-world, open-source
threat intelligence feeds:

  1. TRANCO TOP 1M (Legitimate Domains Baseline)
     URL:   https://tranco-list.eu/top-1m.csv.zip
     Repo:  https://tranco-list.eu/
     Paper: Le Pochat et al., "Tranco: A Research-Oriented Top Sites
            Ranking Hardened Against Manipulation", NDSS 2019
     Usage: 10,000 top legitimate domains as benign training baseline

  2. DGA DOMAINS DATASET (Malware Domain Generation)
     URL:   https://github.com/chrmor/DGA_domains_dataset
     Data:  https://raw.githubusercontent.com/chrmor/DGA_domains_dataset/master/legit_dga_combined.csv
     Info:  675,000 domains from 25 DGA malware families
            (Cryptolocker, Conficker, Necurs, Bamital, etc.)
     Source: 360 Netlab DGA feed + Alexa Top Sites

  3. EXTRAHOP DGA DETECTION TRAINING DATASET
     URL:   https://github.com/ExtraHop/DGA-Detection-Training-Dataset
     Info:  16 million+ rows, balanced 50/50 benign vs DGA
     Format: Compressed JSON (.json.gz)

  4. STEVENBLACK UNIFIED HOSTS (Malware/Ad Blocklist)
     URL:   https://github.com/StevenBlack/hosts
     Data:  https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
     Info:  100,000+ known malware, adware, and tracking domains
     License: MIT

  5. PHISHTANK OPEN DATA (Verified Phishing URLs)
     URL:   https://data.phishtank.com/data/online-valid.csv
     Info:  https://phishtank.net/
     Usage: Reference for phishing domain pattern research

  6. 360 NETLAB DGA FEED (Live DGA Intelligence)
     URL:   https://data.netlab.360.com/dga/
     Info:  Updated DGA domain lists from active malware families

  7. BAMBENEK CONSULTING DGA FEEDS
     URL:   https://osint.bambenekconsulting.com/feeds/
     Info:  OSINT feeds for DGA, C2, and malware indicators

=====================================================================
  WHAT THE DATABASE CONTAINS
=====================================================================

  TABLE                RECORDS     DESCRIPTION
  -------              -------     -----------
  training_domains     15,000+     Labeled domains for ML training
                                   - label=0: Legitimate (Tranco + curated)
                                   - label=1: Malicious (Real DGA + phishing)

  static_blocklist     15,000+     Known-bad domains from StevenBlack
                                   + curated malware/phishing/C2 entries

  dns_queries          500         Realistic simulated query logs
                                   for the SIEM dashboard timeline

  alerts               165+        Threat alerts with detailed reasons

  whitelist            12          Default trusted domains

  system_settings      1           Engine config (DGA on, Tunnel on,
                                   risk threshold 80.0)

=====================================================================
  ML TRAINING DATA BREAKDOWN
=====================================================================

  LEGITIMATE (label=0):
    - Tranco Top 1M download       (up to 10,000 domains)
    - Curated Indian/Global sites  (200+ hand-picked)
    - Generated subdomain combos   (2,000 variations)

  MALICIOUS (label=1):
    - Real DGA families from chrmor dataset (up to 10,000)
    - Generated DGA across 15 families:
        Cryptolocker, Conficker, Necurs, Bamital, Murofet,
        Pykspa, Ranbyus, Tinba, Matsnu, Suppobox,
        Ramnit, Qakbot, Emotet, Dyre, Gozi
    - 83 phishing/brand impersonation domains
    - 15 DNS tunneling domains (base64-encoded payloads)

=====================================================================
