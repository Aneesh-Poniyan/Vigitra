# ROADMAP.md

> **Current Phase**: Not started
> **Milestone**: v1.0 (Production Core & UI Polish)

## Must-Haves (from SPEC)
- [ ] Reproducible environment and safe secret management.
- [ ] Live external threat intel integration.
- [ ] Premium "Draftly" style SIEM dashboard.
- [ ] Extension-ready API.

## Phases

### Phase 1: Foundation & Production Readiness
**Status**: ✅ Completed
**Objective**: Fix the technical debt from the hackathon to make the codebase stable for future feature development.
**Requirements**: 
- Generate `requirements.txt`.
- Implement `python-dotenv` for API keys.
- Move ML models to a dedicated `/models` directory to clean up the root.
- Clean up unused test/scratch files.

### Phase 2: Live Threat Intelligence Engine
**Status**: ✅ Completed
**Objective**: Connect the DNS filter to real-world, constantly updating threat feeds.
**Requirements**: 
- Augment `feed_updater.py` to ingest known free OSINT lists (PhishTank, URLhaus, etc.).
- Ensure local SQLite database handles feed updates efficiently without locking the DNS proxy.

### Phase 3: Premium UI/UX Overhaul (Vigitra Dashboard)
**Status**: ✅ Completed
**Objective**: Redesign the Flask dashboard to look like a premium cybersecurity SaaS app utilizing dark mode, glowing accents, and glassmorphism.
**Requirements**:
- Overhaul `templates/` and `static/css/styles.css`.
- Add proper branding for "Vigitra by CypherNest".
- Refine the live charts for smoother animations.

### Phase 4: API Decoupling (Prep for Extension)
**Status**: ✅ Completed
**Objective**: Ensure all dashboard data is served via clean REST APIs, allowing the future Vigitra Web Extension to connect to the local core seamlessly.
**Requirements**:
- Map out and format JSON endpoints in `app.py`.
- Add basic API authentication (or local-network-only safeguards).
