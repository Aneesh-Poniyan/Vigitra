# SPEC.md — Project Specification

> **Status**: `FINALIZED`

## Vision
**Vigitra** (by CypherNest) is a premium, self-hosted DNS threat detection and SIEM system. It acts as the "watchful eye" of the network, protecting users from DGA, DNS tunneling, phishing, and botnets. It is built privacy-first (data stays on the user's local machine) and is designed to eventually scale into a browser extension, desktop app, and enterprise deployment. 

## Goals
1. **Solidify the Foundation**: Transition from a hackathon demo to a production-safe backend (reproducible environments, secret management, proper config).
2. **Integrate Real-World Intel**: Consume live, free threat intelligence feeds (e.g., URLhaus, OpenPhish) to actively block real-time global threats alongside the ML models.
3. **Draftly-Level UI/UX**: Overhaul the SIEM dashboard to feature a premium, dark glassmorphism aesthetic (inspired by Draftly.space) worthy of a paid cybersecurity product.
4. **Prepare for Ecosystem**: Ensure the API backend is robust enough to eventually support the Vigitra Web Extension.

## Non-Goals (Out of Scope for immediate Next Steps)
- Building the mobile app or native desktop software (focusing on backend + extension API first).
- Paid threat intelligence feeds (sticking to free tier/open-source feeds for initial launch).

## Users
- Solo privacy-conscious individuals and tech-savvy users willing to pay a one-time fee for absolute DNS security where their data never leaves their machine.
- Eventually: Schools, colleges, and SMBs deploying it on local hardware (e.g., Raspberry Pi).

## Constraints
- **Technical**: Must run efficiently on consumer hardware. Must gracefully handle missing API keys for optional integrations (like Gemini).
- **Privacy**: No telemetry or user DNS data is ever sent to CypherNest servers.

## Success Criteria
- [ ] Reproducible build environment (`requirements.txt`).
- [ ] Secrets securely managed via `.env`.
- [ ] At least 2 live threat feeds automatically ingested into the blocklist.
- [ ] Dashboard completely redesigned with glowing, premium visual elements.
- [ ] API is decoupled and ready for a web extension to consume.
