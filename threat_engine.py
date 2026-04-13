import numpy as np
import joblib
import os
import socket
import time
from collections import defaultdict
from functools import lru_cache
from features import extract_features, BRANDS, PHISH_KEYWORDS, HIGH_RISK_TLDS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# DNS Shadowing detector
subdomain_tracker = defaultdict(set)


def check_dns_shadowing(domain: str) -> bool:
    parts = domain.split(".")
    if len(parts) < 3:
        return False
    base = ".".join(parts[-2:])
    subdomain = parts[0]
    subdomain_tracker[base].add(subdomain)
    # If one base domain generates 50+ unique subdomains = shadowing
    return len(subdomain_tracker[base]) > 50


# Fast Flux detector
ip_tracker = defaultdict(set)


def check_fast_flux(domain: str) -> bool:
    try:
        results = socket.getaddrinfo(domain, None)
        ips = set(r[4][0] for r in results)
        ip_tracker[domain].update(ips)
        # Multiple IPs = fast flux botnet infrastructure
        return len(ip_tracker[domain]) > 3
    except:
        return False


class ThreatEngine:
    def __init__(self):
        self.dga_model = joblib.load(
            os.path.join(BASE_DIR, "models", "dga_rf_model.pkl")
        )
        self.tunnel_model = joblib.load(
            os.path.join(BASE_DIR, "models", "tunneling_iso_model.pkl")
        )
        self.upstream_cache = {}  # For future threat intelligence
        self.static_blocklist = set()
        self.refresh_blocklist()
        print("[ThreatEngine] Models loaded successfully")

    def refresh_blocklist(self):
        """Loads static blocklisted domains into an O(1) in-memory lookup set."""
        try:
            import sqlite3

            conn = sqlite3.connect("dns_filter.db", timeout=10)
            conn.execute("PRAGMA journal_mode=WAL;")
            c = conn.cursor()
            try:
                c.execute("SELECT domain FROM static_blocklist")
                self.static_blocklist = {row[0].lower() for row in c.fetchall()}
                print(
                    f"[ThreatEngine] Loaded {len(self.static_blocklist)} domains into fast blocklist."
                )
            except sqlite3.OperationalError:
                pass  # Table might not exist yet
            conn.close()
        except Exception as e:
            print(f"[ThreatEngine] Failed to load static blocklist: {e}")

    def feed_upstream_response(self, domain: str, ips: list, ttl: int):
        """Store upstream DNS response data for threat intelligence."""
        self.upstream_cache[domain] = {"ips": ips, "ttl": ttl, "time": time.time()}

    @lru_cache(maxsize=8192)
    def analyze(
        self, domain: str, client_ip: str = "0.0.0.0", is_https: bool = True
    ) -> dict:
        try:
            domain_lower = domain.lower()
            if domain_lower in self.static_blocklist:
                return {
                    "original_input": domain,
                    "analyzed_domain": domain,
                    "score": 100,
                    "threat_type": "THREAT_INTEL",
                    "reason": "Matched known malicious OSINT blocklist",
                    "blocked": True,
                    "dga_prob": 1.0,
                    "tunnel_score": 1.0,
                    "entropy": 0,
                    "in_static_blocklist": True,
                    "lookalike": None,
                    "lookalike_similarity": 0,
                    "tld_risk": 1.0,
                }

            features = extract_features(domain)
            f = np.array([features])

            dga_prob = float(self.dga_model.predict_proba(f)[0][1])
            tunnel_raw = float(self.tunnel_model.decision_function(f)[0])
            tunnel_prob = max(0, min(1, (-tunnel_raw + 0.5)))

            # weighted threat score
            score = (
                dga_prob * 40
                + tunnel_prob * 20
                + features[6] * 15  # entropy
                + features[11] * 10  # lookalike
                + features[9] * 10  # tld_risk
                + features[15] * 5  # jaro_winkler
            )

            # keyword boost
            domain_lower = domain.lower()
            kw_hits = sum(1 for kw in PHISH_KEYWORDS if kw in domain_lower)
            if kw_hits > 0:
                score += min(kw_hits * 8, 20)

            # brand in domain boost
            from features import levenshtein

            parts = domain_lower.split(".")
            sld = parts[0] if parts else domain_lower
            min_lev = min((levenshtein(sld, b) for b in BRANDS), default=99)
            if 0 < min_lev <= 2:
                score += 15

            threat_override = None
            if check_dns_shadowing(domain):
                score += 30
                threat_override = "DNS_SHADOWING"

            if check_fast_flux(domain):
                score += 25
                threat_override = "FAST_FLUX"

            score = min(int(score), 100)

            # determine threat type
            if threat_override:
                threat_type = threat_override
            elif score < 30:
                threat_type = "CLEAN"
            elif dga_prob > 0.55:
                threat_type = "DGA"
            elif tunnel_prob > 0.6:
                threat_type = "TUNNELING"
            elif min_lev <= 2 or features[11] > 0.5:
                threat_type = "PHISHING"
            else:
                threat_type = "SUSPICIOUS"

            # build reason string
            reasons = []
            if threat_override == "DNS_SHADOWING":
                reasons.append("DNS Shadowing detected")
            if threat_override == "FAST_FLUX":
                reasons.append("Fast Flux botnet infrastructure detected")
            if dga_prob > 0.55:
                reasons.append(f"DGA probability {dga_prob:.0%}")
            if features[6] > 0.75:
                reasons.append(f"High entropy ({features[6] * 4:.1f})")
            if features[11] > 0.5:
                reasons.append(f"Brand lookalike detected")
            if kw_hits > 0:
                reasons.append(f"Phishing keywords found")
            if features[9] > 0.7:
                reasons.append(f"High-risk TLD")
            if not reasons:
                reasons.append("No threats detected")

            return {
                "original_input": domain,
                "analyzed_domain": domain,
                "score": score,
                "threat_type": threat_type,
                "dga_prob": round(dga_prob, 3),
                "tunnel_score": round(tunnel_prob, 3),
                "reason": " | ".join(reasons),
                "blocked": score >= 60,
                "entropy": features[6] * 4,
                "in_static_blocklist": False,
                "lookalike": "Yes" if features[11] > 0.5 else None,
                "lookalike_similarity": features[11],
                "tld_risk": features[9],
            }

        except Exception as e:
            return {
                "original_input": domain,
                "analyzed_domain": domain,
                "score": 0,
                "threat_type": "ERROR",
                "reason": str(e),
                "blocked": False,
                "dga_prob": 0,
                "entropy": 0,
                "in_static_blocklist": False,
                "lookalike": None,
                "lookalike_similarity": 0,
                "tld_risk": 0,
            }


# DoH/DoT server IPs that should be blocked (DNS evasion attempts)
DOH_IPS = {
    "8.8.8.8",
    "8.8.4.4",  # Google DoH
    "1.1.1.1",
    "1.0.0.1",  # Cloudflare DoH
    "9.9.9.9",
    "149.112.112.112",  # Quad9
}


def get_engine():
    global _engine
    if "_engine" not in globals():
        _engine = ThreatEngine()
    return _engine


def feed_upstream_response(domain: str, ips: list, ttl: int):
    """Store upstream DNS response data (for future threat intelligence)."""
    # Placeholder for logging/enrichment - can be expanded later
    pass


engine = get_engine()
