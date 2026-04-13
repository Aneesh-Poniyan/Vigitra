# Vigitra — Autonomous DNS Threat Detection & SIEM
### by [CypherNest]

> Self-hosted. Privacy-first. ML-powered.  
> Your DNS traffic analyzed in real time — your data never leaves your machine.

<img width="1919" height="1141" alt="image" src="https://github.com/user-attachments/assets/0219170c-89b3-49d1-a496-a02c1c10a308" />

---

## Overview

**Vigitra** is a production-grade DNS security intelligence system that sits between your network and the internet — intercepting every DNS query, running it through multiple AI and ML detection layers, and blocking threats before they reach your devices.

Most DNS security tools rely on static blocklists. Vigitra goes further: it **predicts** malicious domains using trained machine learning models, detects behavioral attack patterns, and runs multi-agent AI consensus analysis — even for domains that have never been seen before.

Built and deployed exclusively by **CipherNest** for client network security engagements.

---

## Live Detection in Action

```
⚠ SHADOWING DETECTION   08:18:51
sys-3824.aws-internal-corp.com
172.16.0.10 — DNS Shadowing: Massive subdomain generation (16 reqs, 11 unique)

⚠ DGA DETECTION         08:18:52
jf82md9xk3bvnw.info
172.16.0.5 — DGA pattern detected — ML confidence 78%

⚠ FAST_FLUX DETECTION   08:18:55
flux-net-1.net
192.168.1.45 — Fast Flux: 4 distinct IPs resolving with aggressive TTL (15s)

⚠ PHISHING DETECTION
google-login.xyz
192.168.1.100 — Brand impersonation via typosquatting (score 74.9)
```

---

## Detection Capabilities

| Engine | Method | Status |
|--------|--------|--------|
| DGA Detection | Random Forest — 17 entropy features | **96.6% accuracy** |
| DNS Tunneling | Isolation Forest anomaly detection | **97.5% accuracy** |
| Lookalike Domains | Edit distance + homoglyph analysis | ✅ Active |
| DNS Shadowing | Subdomain generation rate analysis | ✅ Active |
| Fast Flux Detection | Multi-IP TTL behavioral analysis | ✅ Active |
| Multi-Agent AI | Gemini + GPT + Claude consensus | ✅ Active |
| Live Threat Feeds | OpenPhish, URLhaus, StevenBlack | **109,000+ domains** |

---

## Architecture

```
Network DNS Query (UDP :5054)
            │
            ▼
  ┌──────────────────┐
  │   dns_server.py  │  ← Proxy + DDoS sliding-window filter
  └────────┬─────────┘
           │
           ▼
  ┌──────────────────┐
  │  threat_engine   │  ← ML inference + O(1) blocklist lookup
  │  .py             │
  └────────┬─────────┘
           │
     ┌─────┴──────┐
     │            │
   BLOCK        ALLOW
     │            │
     ▼            ▼
  Alert →      Forward →
  SIEM DB      8.8.8.8
```

**Core Components:**

- `dns_server.py` — UDP DNS proxy on port 5054 with DDoS protection
- `threat_engine.py` — ML inference engine with in-memory blocklist cache
- `feed_updater.py` — Hourly background threat feed ingestion
- `app.py` — Flask SIEM dashboard + authenticated REST API
- `models/` — Trained `.pkl` model files (Random Forest + Isolation Forest)
- `features.py` — 17-feature entropy extractor for domain analysis

---

## SIEM Dashboard

| Feature | Description |
|---------|-------------|
| KPI Cards | Live query count, threats blocked, DGA hits, tunneling alerts |
| Threat Velocity | Real-time chart — queries vs blocked over time |
| Live Alerts | Toast notifications for Shadowing, DGA, Fast Flux detections |
| Autonomous Threat Discovery | Scan any domain via Gemini + GPT + Claude AI consensus |
| Live Traffic Stream | Every DNS query with verdict, engine, and client IP |
| Threat Intel DB | Browse 109,000+ known malicious domains |
| Query Log | Paginated historical DNS log with full metadata |
| Settings | Toggle ML engines, adjust risk threshold, manage whitelist |

---

## REST API

All endpoints protected by `X-Vigitra-Key` header authentication.

```
GET  /api/health           System status        (no auth required)
GET  /api/manifest         Capability discovery (no auth required)
GET  /api/stats            Query counts & threat aggregations
GET  /api/alerts           Last 20 threat alerts
GET  /api/queries          Last 50 DNS query records
GET  /api/clients          Risk matrix by client IP
GET  /api/timeline         Time-series queries vs blocked
POST /api/analyze_domain   Multi-agent AI + ML domain analysis
GET  /api/settings         Detection toggles & risk threshold
GET  /api/whitelist        Whitelisted domains management
```

Full API reference → [`docs/API.md`](docs/API.md)

---

## Quick Start

**Requirements:** Python 3.10+, Windows / Linux / macOS / Raspberry Pi

```bash
# 1. Clone the repository
git clone https://github.com/Aneesh-Poniyan/Vigitra.git
cd Vigitra

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env — add Gemini/OpenAI keys (optional, for AI analysis)

# 4. Build the database & train models
python build_database.py
python train_models.py

# 5. Start Vigitra
python dns_server.py    # Terminal 1 — DNS proxy on :5054
python app.py           # Terminal 2 — Dashboard on :5000
```

Open `http://localhost:5000` in your browser.  
Point your network DNS to `127.0.0.1:5054` to begin filtering live traffic.

---

## ML Model Training

Vigitra's models are trained on ~30,000 unique domain records:

```bash
python train_models.py          # Train base models
python enhance_and_retrain.py   # Expand dataset and retrain
python verify_models.py         # Verify accuracy
```

Feature extraction uses 17 entropy-based signals including character frequency,
n-gram analysis, domain length, subdomain depth, and TLD risk scoring.

---

## Privacy

- **Zero telemetry.** No DNS data is ever sent to CipherNest servers.
- All ML inference runs **entirely on local hardware.**
- Gemini and OpenAI keys are **optional** — stored only in your local `.env`.
- Designed to run efficiently on consumer hardware including Raspberry Pi.
- SQLite database stays on your machine at all times.

---

## Project Structure

```
Vigitra/
├── app.py                       # Flask SIEM dashboard & REST API
├── dns_server.py                # UDP DNS proxy (port 5054)
├── threat_engine.py             # ML inference + blocklist engine
├── feed_updater.py              # Live threat feed ingestion daemon
├── features.py                  # 17-feature entropy extractor
├── train_models.py              # ML training pipeline
├── enhance_and_retrain.py       # Dataset hardening & retraining
├── verify_models.py             # Model accuracy verification
├── attack_simulator.py          # Threat simulation for testing
├── models/
│   ├── dga_rf_model.pkl         # Random Forest — DGA detection
│   └── tunneling_iso_model.pkl  # Isolation Forest — tunneling
├── templates/                   # Flask HTML templates
├── static/
│   ├── css/styles.css           # Dark glassmorphism design system
│   ├── css/animations.css       # Keyframe animations
│   └── js/dashboard.js          # Chart.js config & UI logic
├── docs/
│   ├── API.md                   # Full REST API reference
│   └── dashboard.png            # Dashboard screenshot
├── .env.example                 # Environment variable template
└── requirements.txt             # Python dependencies
```

---

## Roadmap

- [x] Phase 1 — Foundation & production readiness
- [x] Phase 2 — Live threat intelligence engine (109k+ domains)
- [x] Phase 3 — Premium dark glassmorphism SIEM dashboard
- [x] Phase 4 — REST API decoupling & browser extension readiness
- [ ] Phase 5 — Vigitra Browser Extension
- [ ] Phase 6 — Desktop installer for SMB deployment
- [ ] Phase 7 — Enterprise multi-network deployment

---

## License

**Copyright © 2025 CypherNest. All Rights Reserved.**

This software is proprietary and confidential. Unauthorized copying, modification,
distribution, or commercial use of this software, in whole or in part, is strictly
prohibited. Vigitra is deployed exclusively by CipherNest for client engagements.

---

<div align="center">

**Built by [CypherNest] — Securing India's Business Future**

[LinkedIn](https://linkedin.com/in/aneesh-poniyan) · [GitHub](https://github.com/AnuuPoniyan) · contact@CypherNest

</div>
