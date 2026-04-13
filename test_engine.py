"""
IntrusionX - Test Script
test_engine.py

Runs a comprehensive evaluation of the full threat engine
against a curated set of test domains spanning all threat categories.
"""

import json
import time

TEST_DOMAINS = [
    ("google.com", "SAFE", "Google"),
    ("github.com", "SAFE", "GitHub"),
    ("wikipedia.org", "SAFE", "Wikipedia"),
    ("stackoverflow.com", "SAFE", "StackOverflow"),
    ("mail.google.com", "SAFE", "Gmail subdomain"),
    ("docs.microsoft.com", "SAFE", "Microsoft Docs"),
    ("login.microsoftonline.com", "SAFE", "Legitimate MS login"),
    ("microsoftonline.com", "SAFE", "MS online"),
    ("paypa1-secure-login.xyz", "MALICIOUS", "PayPal phishing"),
    ("sbi-netbanking-verify.top", "MALICIOUS", "SBI phishing"),
    ("amazon-login-help.ru", "MALICIOUS", "Amazon phishing"),
    ("hdfc-bank-update-kyc.info", "MALICIOUS", "HDFC phishing"),
    ("faceb00k-account.club", "MALICIOUS", "Facebook lookalike"),
    ("xkj234kjdfs.net", "MALICIOUS", "DGA domain"),
    ("m7v8x2pqh3.com", "MALICIOUS", "DGA domain"),
    ("rn8kxm21pz.biz", "MALICIOUS", "DGA domain"),
    ("vncxm9823kzxy.info", "MALICIOUS", "DGA high entropy"),
    ("cD93ZXJzaGVsbCBoYWNrZXI.evil.com", "MALICIOUS", "Tunneling (base64 subdomain)"),
    ("YWRtaW4=.c2.attacker.net", "MALICIOUS", "Tunneling (base64 subdomain)"),
    ("update-now.tk", "MALICIOUS", "Suspicious TLD .tk"),
    ("download-file.gq", "MALICIOUS", "Suspicious TLD .gq"),
    ("secure.banking.co.in", "REVIEW", "Suspicious keywords, legit-ish TLD"),
]

SEPARATOR = "-" * 100


def run_tests():
    print("\n" + "=" * 100)
    print("  IntrusionX - Full Threat Engine Test Suite")
    print("=" * 100)

    from threat_engine import get_engine

    engine = get_engine()

    print(
        f"\n{'DOMAIN':<45} {'EXPECTED':<12} {'SCORE':>6}  {'TYPE':<14}  {'LAT':>7}  REASON"
    )
    print(SEPARATOR)

    correct = 0
    results = []
    latencies = []

    for domain, expected_label, description in TEST_DOMAINS:
        result = engine.analyze(domain, client_ip="192.168.1.1")

        score = result["score"]
        threat_type = result["threat_type"]
        latency = result["latency_ms"]
        blocked = result["blocked"]
        latencies.append(latency)

        if expected_label == "SAFE" and not blocked:
            verdict = "[OK]"
            correct += 1
        elif expected_label == "MALICIOUS" and blocked:
            verdict = "[OK]"
            correct += 1
        elif expected_label == "REVIEW":
            verdict = "[?]"
            correct += 1
        else:
            verdict = "[FAIL]"

        score_color = ""
        print(
            f"  {verdict} {domain:<43} {expected_label:<12} {score:>6.1f}  {threat_type:<14}  {latency:>5.1f}ms  {result['reason'][:55]}"
        )
        results.append(result)

    total = len(TEST_DOMAINS)
    pct = correct / total * 100
    avg_lat = sum(latencies) / len(latencies)
    max_lat = max(latencies)

    print(SEPARATOR)
    print(f"\n  Results:     {correct}/{total} correct ({pct:.0f}%)")
    print(f"  Avg latency: {avg_lat:.2f}ms")
    print(f"  Max latency: {max_lat:.2f}ms")
    print(f"  SLA (50ms):  {'PASS' if max_lat < 50 else 'FAIL'}")

    phishing = next(r for r in results if "paypa1" in r["analyzed_domain"])
    print(f"\n{'=' * 100}")
    print("  Detailed Explainability - paypa1-secure-login.xyz")
    print("=" * 100)
    print(
        json.dumps(
            {
                "analyzed_domain": phishing["analyzed_domain"],
                "score": phishing["score"],
                "dga_prob": phishing["dga_prob"],
                "entropy": phishing["entropy"],
                "lookalike": phishing["lookalike"],
                "lookalike_similarity": phishing["lookalike_similarity"],
                "tld_risk": phishing["tld_risk"],
                "reason": phishing["reason"],
                "contributions": phishing["contributions"],
            },
            indent=2,
        )
    )

    google = next(r for r in results if r["analyzed_domain"] == "google.com")
    print(f"\n{'=' * 100}")
    print("  Detailed Explainability - google.com")
    print("=" * 100)
    print(
        json.dumps(
            {
                "analyzed_domain": google["analyzed_domain"],
                "score": google["score"],
                "dga_prob": google["dga_prob"],
                "entropy": google["entropy"],
                "tld_risk": google["tld_risk"],
                "reason": google["reason"],
                "contributions": google["contributions"],
            },
            indent=2,
        )
    )

    print(f"\n{'=' * 100}\n")


if __name__ == "__main__":
    run_tests()
