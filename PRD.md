# PRD: Vigitra Phase 3 — Premium UI/UX Overhaul
# Vigitra by CypherNest | SIEM Dashboard Redesign

## Overview
Overhaul the Vigitra Flask dashboard from its current hackathon aesthetic into a premium, production-grade dark cybersecurity SaaS product. The final result must look and feel like a paid tool — think Draftly.space meets a real SIEM. The design language is: dark glassmorphism, electric cyan glows, surgical typography, and purposeful motion. Every pixel must feel intentional.

## Reference Files
- `templates/index.html` — current dashboard HTML
- `static/css/styles.css` — current stylesheet
- `app.py` — Flask routes (do not touch backend logic)
- `.gsd/SPEC.md` — project vision

## Key Requirements
1. **Typography & Design System**: Implement a new CSS variable-driven system utilizing "Liquid Glass" aesthetics. Focus on Syne, DM Sans, and JetBrains Mono fonts.
2. **Sidebar Rebrand**: Replace the branding area with the new CypherNest shield logo and Vigitra identity.
3. **KPI Stat Cards**: Upgrade cards with glassmorphism, glowing numeric values, and fade-up animations.
4. **Cyber Animations**: Add a pulsing grid background and live pulse indicators for the system status.
5. **SIEM Tables**: Polished, monochrome log tables with red-bordered "threat" highlighting.
6. **Toast Alerts**: High-fidelity threat notification system with glass backdrop and slide-in motion.
7. **Chart.js Standardization**: Unified dark-themed visualizations across the dashboard.

---

# PRD: Vigitra Phase 4 — API Decoupling & Extension Readiness
# Vigitra by CypherNest | Backend Hardening for Web Extension

## Overview
The existing API is functional but not extension-ready. This phase hardens the existing JSON endpoints, adds a standardized response envelope, improves CORS configuration for browser extension access, adds a health check endpoint, creates a machine-readable API manifest, and writes an API reference doc. No existing backend logic is to be rewritten — only wrap, harden, and document.

## Key Requirements
1. **Standardized Response Envelope**: All API returns follow a consistent JSON structure (`ok`, `version`, `timestamp`, `data`/`error`).
2. **Health Check Endpoint**: `/api/health` for extension detection (unauthenticated).
3. **CORS Hardening**: Explicit allowance for `chrome-extension://*` and `moz-extension://*` origins.
4. **Critical Endpoint Wrap**: Standardized `/api/stats`, `/api/alerts`, and `/api/queries` with the wrapper.
5. **Full API Coverage**: Wrap remaining endpoints (`/api/settings`, `/api/whitelist`, `/api/clients`, `/api/timeline`, `/api/analyze_domain`).
6. **Machine-Readable Manifest**: `/api/manifest` for auto-discovery of version and capabilities.
7. **Developer Documentation**: Complete API reference in `docs/API.md`.

## Output Files
- `app.py`: Standardized helper, hardened CORS, discovery routes.
- `docs/API.md`: Developer reference.
- `static/js/dashboard.js`: API Key meta-tag hook.
