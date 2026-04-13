# DECISIONS.md

> Architecture Decision Record (ADR) Log

## ADR-001: SQLite as storage layer
- **Date:** Pre-existing
- **Decision:** Use SQLite (dns_filter.db) for all query/alert/blocklist storage
- **Rationale:** Lightweight, zero-config, sufficient for single-node DNS proxy
- **Trade-offs:** Not horizontally scalable; fine for hackathon/demo scope

## ADR-002: Dual ML model approach
- **Date:** Pre-existing
- **Decision:** RandomForest for DGA detection, IsolationForest for tunneling
- **Rationale:** RF excels at supervised classification (labelled DGA data); IF excels at unsupervised anomaly detection (tunneling has no clean labels)
- **Trade-offs:** 107 MB RF model is large; IF may have higher false-positive rate

## ADR-003: Port 5054 for DNS
- **Date:** Pre-existing
- **Decision:** Run DNS proxy on port 5054, not 53
- **Rationale:** Port 53 requires admin/root on Windows
- **Trade-offs:** Requires manual DNS redirect; not transparent to clients
