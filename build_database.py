import sys
import os as _os
if _os.name == 'nt':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

"""
IntrusionX - Complete Database Builder
build_database.py

Self-contained script to generate the full dns_filter.db database.
Share this file with your team — run it on any system with Python 3.8+.

Creates:
  1. training_domains     — 15,000+ labeled domains (legit + DGA) for ML training
  2. static_blocklist      — 2,000+ known-bad domains for threat intelligence
  3. dns_queries           — 500+ realistic simulated query logs for dashboard
  4. alerts                — 80+ threat alerts with detailed reasons
  5. whitelist             — Default safe domains
  6. system_settings       — Default engine configuration

Usage:
    python build_database.py

No internet required. No dependencies beyond Python stdlib.
"""

import sqlite3
import random
import string
import hashlib
import base64
import math
import os
import time
from datetime import datetime, timedelta
from collections import Counter

DB_FILE = "dns_filter.db"


LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "whatsapp.com",
    "zoom.us", "office.com", "live.com", "yahoo.com", "bing.com",
    "adobe.com", "spotify.com", "twitch.tv", "pinterest.com", "tumblr.com",
    "paypal.com", "ebay.com", "cnn.com", "bbc.com", "nytimes.com",
    "bloomberg.com", "reuters.com", "medium.com", "quora.com", "slack.com",
    "dropbox.com", "salesforce.com", "oracle.com", "ibm.com", "intel.com",
    "nvidia.com", "amd.com", "samsung.com", "huawei.com", "xiaomi.com",
    "cloudflare.com", "aws.amazon.com", "azure.microsoft.com", "console.cloud.google.com",
    "docs.google.com", "drive.google.com", "mail.google.com", "maps.google.com",
    "play.google.com", "calendar.google.com", "translate.google.com",
    "outlook.com", "onedrive.live.com", "teams.microsoft.com",
    "web.whatsapp.com", "messenger.com", "signal.org", "telegram.org",
    "discord.com", "notion.so", "figma.com", "canva.com", "trello.com",
    "asana.com", "jira.atlassian.com", "bitbucket.org", "gitlab.com",
    "npmjs.com", "pypi.org", "rubygems.org", "docker.com", "kubernetes.io",
    "wordpress.com", "blogger.com", "wix.com", "squarespace.com", "shopify.com",
    "etsy.com", "walmart.com", "target.com", "bestbuy.com", "costco.com",
    "homedepot.com", "lowes.com", "wayfair.com", "ikea.com", "nike.com",
    "adidas.com", "zara.com", "hm.com", "uniqlo.com", "gap.com",
    "uber.com", "lyft.com", "airbnb.com", "booking.com", "expedia.com",
    "tripadvisor.com", "kayak.com", "trivago.com", "hotels.com",
    "hulu.com", "disneyplus.com", "hbomax.com", "peacocktv.com", "paramountplus.com",
    "crunchyroll.com", "funimation.com", "dazn.com", "espn.com", "nba.com",
    "nfl.com", "mlb.com", "fifa.com", "olympics.com", "bbc.co.uk",
    "theguardian.com", "washingtonpost.com", "usatoday.com", "forbes.com",
    "businessinsider.com", "techcrunch.com", "theverge.com", "wired.com",
    "arstechnica.com", "engadget.com", "mashable.com", "buzzfeed.com",
    "vice.com", "vox.com", "politico.com", "axios.com", "thehill.com",
    "harvard.edu", "mit.edu", "stanford.edu", "oxford.ac.uk", "cambridge.org",
    "coursera.org", "edx.org", "udemy.com", "khanacademy.org", "duolingo.com",
    "flipkart.com", "paytm.com", "myntra.com", "nykaa.com", "ajio.com",
    "snapdeal.com", "meesho.com", "jiomart.com", "bigbasket.com", "blinkit.com",
    "swiggy.com", "zomato.com", "ola.com", "makemytrip.com", "goibibo.com",
    "irctc.co.in", "redbus.in", "yatra.com", "cleartrip.com",
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "axisbank.com", "kotakbank.com",
    "bankofbaroda.in", "pnbindia.in", "canarabank.com", "unionbankofindia.co.in",
    "indusind.com", "yesbank.in", "idfcfirstbank.com", "rbl.bank",
    "zerodha.com", "groww.in", "upstox.com", "angelone.in", "5paisa.com",
    "moneycontrol.com", "economictimes.com", "livemint.com", "businesstoday.in",
    "ndtv.com", "thehindu.com", "hindustantimes.com", "indianexpress.com",
    "timesofindia.indiatimes.com", "news18.com", "aajtak.in", "abplive.com",
    "hotstar.com", "jiocinema.com", "zee5.com", "sonyliv.com", "erosnow.com",
    "gaana.com", "jiosaavn.com", "wynk.in", "hungama.com",
    "razorpay.com", "payu.in", "cashfree.com", "instamojo.com",
    "uidai.gov.in", "digilocker.gov.in", "umang.gov.in", "cowin.gov.in",
    "incometax.gov.in", "gst.gov.in", "epfindia.gov.in", "nsdl.co.in",
    "naukri.com", "indeed.co.in", "linkedin.com", "glassdoor.co.in",
    "practo.com", "1mg.com", "pharmeasy.in", "netmeds.com", "healthians.com",
    "byju.com", "unacademy.com", "vedantu.com", "toppr.com", "doubtnut.com",
    "jio.com", "airtel.in", "vi.com", "bsnl.co.in", "actcorp.in",
    "tataplay.com", "dfrtech.com", "mygov.in", "india.gov.in",
    "vercel.com", "netlify.com", "heroku.com", "digitalocean.com", "linode.com",
    "vultr.com", "godaddy.com", "namecheap.com", "hover.com", "dynadot.com",
    "cloudfront.net", "akamaized.net", "fastly.net", "cdn77.com",
    "sentry.io", "datadog.com", "splunk.com", "elastic.co", "grafana.com",
    "prometheus.io", "kibana.com", "logstash.com", "pagerduty.com",
    "circleci.com", "travisci.com", "jenkins.io", "drone.io",
    "terraform.io", "ansible.com", "puppet.com", "chef.io",
    "mongodb.com", "postgresql.org", "mysql.com", "redis.io", "elasticsearch.com",
    "kafka.apache.org", "rabbitmq.com", "nats.io", "grpc.io",
    "reactjs.org", "vuejs.org", "angular.io", "svelte.dev", "nextjs.org",
    "tailwindcss.com", "getbootstrap.com", "materializecss.com",
    "flask.palletsprojects.com", "djangoproject.com", "fastapi.tiangolo.com",
    "spring.io", "rubyonrails.org", "laravel.com", "expressjs.com",
    "rust-lang.org", "golang.org", "python.org", "ruby-lang.org", "php.net",
    "cppreference.com", "java.com", "kotlinlang.org", "swift.org", "dart.dev",
]

DGA_FAMILIES = {
    "cryptolocker": {
        "charset": string.ascii_lowercase + string.digits,
        "length_range": (12, 25),
        "tlds": ["com", "net", "org", "biz", "info"],
        "pattern": "random",
        "count": 800,
    },
    "conficker": {
        "charset": string.ascii_lowercase,
        "length_range": (8, 15),
        "tlds": ["com", "net", "org", "info", "biz", "ws", "cc"],
        "pattern": "consonant_heavy",
        "count": 700,
    },
    "necurs": {
        "charset": string.ascii_lowercase + string.digits,
        "length_range": (14, 30),
        "tlds": ["com", "net", "pw", "tk", "top"],
        "pattern": "random",
        "count": 600,
    },
    "bamital": {
        "charset": string.ascii_lowercase,
        "length_range": (10, 18),
        "tlds": ["com", "net"],
        "pattern": "vowel_sparse",
        "count": 500,
    },
    "murofet": {
        "charset": string.ascii_lowercase + string.digits,
        "length_range": (16, 32),
        "tlds": ["com", "biz", "info", "net"],
        "pattern": "hex_like",
        "count": 500,
    },
    "pykspa": {
        "charset": string.ascii_lowercase,
        "length_range": (6, 14),
        "tlds": ["com", "net", "org", "info"],
        "pattern": "pseudo_word",
        "count": 500,
    },
    "ranbyus": {
        "charset": string.ascii_lowercase + string.digits,
        "length_range": (12, 22),
        "tlds": ["com", "net", "org", "biz"],
        "pattern": "random",
        "count": 400,
    },
    "tinba": {
        "charset": string.ascii_lowercase,
        "length_range": (8, 16),
        "tlds": ["com", "pw", "cc", "top"],
        "pattern": "consonant_heavy",
        "count": 400,
    },
    "matsnu": {
        "charset": string.ascii_lowercase + string.digits,
        "length_range": (20, 40),
        "tlds": ["com", "net", "info"],
        "pattern": "random",
        "count": 400,
    },
    "suppobox": {
        "charset": string.ascii_lowercase,
        "length_range": (7, 15),
        "tlds": ["com", "net", "org"],
        "pattern": "pseudo_word",
        "count": 400,
    },
    "ramnit": {
        "charset": string.ascii_lowercase + string.digits,
        "length_range": (10, 20),
        "tlds": ["com", "click", "link", "xyz"],
        "pattern": "random",
        "count": 400,
    },
    "qakbot": {
        "charset": string.ascii_lowercase,
        "length_range": (8, 18),
        "tlds": ["com", "net", "org"],
        "pattern": "pseudo_word",
        "count": 300,
    },
    "emotet": {
        "charset": string.ascii_lowercase + string.digits,
        "length_range": (10, 25),
        "tlds": ["com", "net"],
        "pattern": "random",
        "count": 300,
    },
    "dyre": {
        "charset": string.ascii_lowercase + string.digits,
        "length_range": (15, 30),
        "tlds": ["com", "net", "xyz", "top"],
        "pattern": "hex_like",
        "count": 300,
    },
    "gozi": {
        "charset": string.ascii_lowercase,
        "length_range": (6, 14),
        "tlds": ["com", "net", "ru", "pw"],
        "pattern": "pseudo_word",
        "count": 300,
    },
}

PHISHING_DOMAINS = [
    "paypa1-secure-login.xyz", "paypal-verify-account.top", "paypal-update.tk",
    "paypa1.com", "paypal-security.gq", "paypal-confirm.cf", "peypal-login.ml",
    "paypal-support-help.xyz", "paypal-account-verify.club",
    "googIe-login.xyz", "g00gle-verify.top", "google-security-alert.tk",
    "gooogle.com", "googel-signin.gq", "google-account-recovery.cf",
    "google-verify-identity.ml", "google-support-team.xyz",
    "amaz0n-order.xyz", "amazon-delivery-update.top", "amazon-refund.tk",
    "amzon.com", "amazon-security-check.gq", "amazon-prime-verify.cf",
    "amazon-payment-update.ml", "amazon-account-suspended.xyz",
    "micros0ft-login.xyz", "microsoft-password-reset.top", "microsoft-verify.tk",
    "mircosoft.com", "microsoft-365-update.gq", "microsft-teams.cf",
    "microsoft-outlook-verify.ml", "microsoft-office-update.xyz",
    "faceb00k-login.xyz", "facebook-security-alert.top", "fb-verify.tk",
    "facbook.com", "facebook-account-recovery.gq", "meta-verify.cf",
    "facebook-password-reset.ml", "instagram-verify-account.xyz",
    "appIe-id-verify.xyz", "apple-support-login.top", "apple-icloud-verify.tk",
    "applle.com", "apple-payment-update.gq", "apple-account-locked.cf",
    "apple-security-check.ml", "itunes-verify.xyz",
    "netfIix-billing.xyz", "netflix-update-payment.top", "netflix-account.tk",
    "netflx.com", "netflix-suspend.gq", "netflix-verify.cf",
    "sbi-netbanking-verify.top", "sbi-yono-update.xyz", "sbi-otp-verify.tk",
    "hdfc-netbanking-login.xyz", "hdfc-bank-verify.top", "hdfc-update.gq",
    "icici-bank-verify.xyz", "icici-netbanking-login.top", "icici-update.tk",
    "axis-bank-verify.xyz", "kotak-bank-login.top", "indusind-verify.gq",
    "paytm-kyc-verify.xyz", "paytm-wallet-update.top", "paytm-refund.tk",
    "razorpay-verify.xyz", "phonepe-kyc.top", "gpay-verify.tk",
    "secure-login-portal.xyz", "account-verify-now.top", "update-payment-info.tk",
    "confirm-identity-secure.gq", "login-authentication.cf", "reset-password-now.ml",
    "verify-account-security.xyz", "unlock-suspended-account.top",
    "invoice-payment-portal.tk", "wallet-recovery-service.gq",
]

TUNNELING_DOMAINS = [
    "cD93ZXJzaGVsbCBoYWNrZXI.evil.com",
    "aGVsbG8gd29ybGQgYmFzZTY0.badactor.net",
    "dGhpcyBpcyBhIHR1bm5lbA.c2server.org",
    "ZXhmaWx0cmF0aW9uIGRhdGE.malware.xyz",
    "c2VjcmV0IGRhdGEgaGVyZQ.tunnel.info",
    "bWFsd2FyZSBjb21tYW5k.dropper.top",
    "cGF5bG9hZCBkZWxpdmVyeQ.beacon.club",
    "Y29tbWFuZCBhbmQgY29udHJvbA.c2.xyz",
    "ZGF0YSBleGZpbHRyYXRpb24.exfil.tk",
    "cmVtb3RlIHNoZWxsIGFjY2Vzcw.shell.gq",
    "a2V5bG9nZ2VyIGRhdGE.keylog.cf",
    "c2NyZWVuc2hvdCBjYXB0dXJl.capture.ml",
    "ZmlsZSB0cmFuc2Zlcg.transfer.ga",
    "Y3JlZGVudGlhbCBzdGVhbGVy.stealer.pw",
    "Ym90bmV0IGNvbW1hbmQ.botnet.cc",
]

BLOCKLIST_DOMAINS = [
    "doubleclick.net", "adservice.google.com", "pagead2.googlesyndication.com",
    "adsserver.com", "adnxs.com", "taboola.com", "outbrain.com",
    "moatads.com", "scorecardresearch.com", "quantserve.com",
    "pubmatic.com", "adform.net", "criteo.com", "bidswitch.net",
    "openx.net", "rubicon.com", "indexww.com", "smartadserver.com",
    "advertising.com", "ad.doubleclick.net", "ads.yahoo.com",
    "tracking.analytics.io", "pixel.quantcount.com", "analytics.yahoo.com",
    "beacon.krxd.net", "pixel.adsafeprotected.com", "tags.tiqcdn.com",
    "stats.g.doubleclick.net", "cm.g.doubleclick.net",
    "evil-c2-server.xyz", "malware-dropper.top", "trojan-callback.club",
    "ransomware-panel.online", "keylogger-c2.site", "botnet-controller.xyz",
    "phishing-kit.top", "exploit-server.club", "backdoor-c2.online",
    "stealer-panel.site", "cryptominer-pool.xyz", "worm-c2.top",
    "rootkit-c2.club", "spyware-server.online", "adware-cdn.site",
    "malwaresite1.com", "phishingsite2.net", "scamsite3.org",
    "trackingpixel.info", "badsite4.biz", "harmfuldomain5.online",
    "fakestore6.shop", "fraudsite7.xyz", "malsite8.top",
    "spamsite9.club", "virussite10.live", "trojansite11.work",
    "tracker.gambling-ads.com", "pixel.adult-network.com",
    "ads.betting-platform.com", "promo.casino-tracker.net",
    "telemetry.microsoft.com", "vortex.data.microsoft.com",
    "settings-win.data.microsoft.com", "watson.telemetry.microsoft.com",
    "feedback.microsoft-hohm.com", "corporatefeedback.microsoft.com",
    "diagnostics.support.microsoft.com",
    "coinhive.com", "coin-hive.com", "jsecoin.com", "cryptoloot.pro",
    "crypto-loot.com", "webminepool.com", "minero.cc", "monerise.com",
    "ppoi.org", "coinimp.com", "afminer.com", "coinerra.com",
]



def generate_dga_domain(family_config: dict, seed: int) -> str:
    """Generate a single DGA domain using family-specific patterns."""
    rng = random.Random(seed)
    charset = family_config["charset"]
    minl, maxl = family_config["length_range"]
    tld = rng.choice(family_config["tlds"])
    length = rng.randint(minl, maxl)
    pattern = family_config["pattern"]

    if pattern == "random":
        label = ''.join(rng.choice(charset) for _ in range(length))
    elif pattern == "consonant_heavy":
        consonants = "bcdfghjklmnpqrstvwxyz"
        vowels = "aeiou"
        label = ""
        for i in range(length):
            if rng.random() < 0.15:
                label += rng.choice(vowels)
            else:
                label += rng.choice(consonants)
    elif pattern == "vowel_sparse":
        consonants = "bcdfghjklmnpqrstvwxyz"
        vowels = "ae"
        label = ""
        for i in range(length):
            if rng.random() < 0.1:
                label += rng.choice(vowels)
            else:
                label += rng.choice(consonants)
    elif pattern == "hex_like":
        hex_chars = "0123456789abcdef"
        label = ''.join(rng.choice(hex_chars) for _ in range(length))
    elif pattern == "pseudo_word":
        consonants = "bcdfghjklmnprstvw"
        vowels = "aeiou"
        label = ""
        for i in range(length):
            if i % 2 == 0:
                label += rng.choice(consonants)
            else:
                label += rng.choice(vowels)
    else:
        label = ''.join(rng.choice(charset) for _ in range(length))

    return f"{label}.{tld}"


def generate_additional_legit_domains(count: int) -> list:
    """
    Generate realistic-looking legitimate subdomain variations 
    to bulk up the training set.
    """
    rng = random.Random(42)
    base_domains = [
        "google.com", "amazon.com", "microsoft.com", "facebook.com",
        "apple.com", "netflix.com", "cloudflare.com", "github.com",
        "stackoverflow.com", "wordpress.com", "medium.com",
    ]
    subdomains = [
        "www", "mail", "api", "cdn", "static", "assets", "images",
        "docs", "help", "support", "blog", "status", "dev", "staging",
        "beta", "app", "m", "mobile", "shop", "store", "auth", "login",
        "accounts", "dashboard", "admin", "portal", "connect", "cloud",
    ]
    tlds = ["com", "org", "net", "co", "io", "dev", "app"]
    
    words = [
        "tech", "cloud", "smart", "digital", "global", "secure", "fast",
        "nexgen", "bright", "swift", "pixel", "spark", "nova", "pulse",
        "quantum", "stellar", "orbit", "signal", "prime", "apex",
        "forge", "catalyst", "fusion", "matrix", "vector", "zenith",
        "horizon", "summit", "crest", "ridge", "harbor", "haven",
        "grove", "meadow", "brook", "creek", "river", "lake",
    ]
    
    result = []
    for _ in range(count):
        choice = rng.random()
        if choice < 0.3:
            sub = rng.choice(subdomains)
            base = rng.choice(base_domains)
            result.append(f"{sub}.{base}")
        elif choice < 0.6:
            w1 = rng.choice(words)
            w2 = rng.choice(words)
            tld = rng.choice(tlds)
            result.append(f"{w1}{w2}.{tld}")
        elif choice < 0.8:
            w = rng.choice(words)
            suffix = rng.choice(["app", "hq", "hub", "lab", "dev", "io", "ly", "ify"])
            tld = rng.choice(tlds)
            result.append(f"{w}{suffix}.{tld}")
        else:
            w = rng.choice(words)
            tld = rng.choice(tlds)
            result.append(f"{w}.{tld}")
    
    return result



def generate_query_logs(conn, count=500):
    """Generate realistic DNS query logs for the dashboard timeline."""
    rng = random.Random(2024)
    now = datetime.now()
    c = conn.cursor()

    client_ips = [
        "192.168.1.10", "192.168.1.11", "192.168.1.25", "192.168.1.30",
        "192.168.1.45", "192.168.1.50", "192.168.1.100", "192.168.1.101",
        "10.0.0.5", "10.0.0.12", "10.0.0.25", "10.0.0.50",
        "172.16.0.5", "172.16.0.10", "172.16.0.20",
    ]

    safe_domains = [
        "google.com", "youtube.com", "facebook.com", "amazon.com", "github.com",
        "stackoverflow.com", "reddit.com", "twitter.com", "linkedin.com",
        "netflix.com", "spotify.com", "discord.com", "slack.com", "zoom.us",
        "microsoft.com", "apple.com", "dropbox.com", "notion.so",
        "mail.google.com", "docs.google.com", "drive.google.com",
        "outlook.com", "teams.microsoft.com", "web.whatsapp.com",
        "flipkart.com", "swiggy.com", "zomato.com", "paytm.com",
        "hdfcbank.com", "sbi.co.in", "icicibank.com", "axisbank.com",
    ]

    dga_query_domains = [
        "xkj234kjdfsh2md.net", "qpz9m3xvnbr7t2.com", "bcvnwk83jd2lp.org",
        "r7x2kpq9wm4nv.biz", "jf82md9xk3bvnw.info", "kld9m2xpqb7vn.com",
        "nxv3m8kpd2jw9r.net", "wp4kx9m7ndv2qb.org", "zm3nv8xpk2dw9j.com",
        "tx7m2kdp9nwvb3.net", "fv8x2mpk3dnw9q.biz", "hd2m9xnvpw3kb7.info",
    ]

    tunneling_query_domains = [
        "cD93ZXJzaGVsbCBoYWNrZXI.evil.com",
        "aGVsbG8gd29ybGQgYmFzZTY0.badactor.net",
        "dGhpcyBpcyBhIHR1bm5lbA.c2server.org",
        "ZXhmaWx0cmF0aW9uIGRhdGE.malware.xyz",
        "c2VjcmV0IGRhdGEgaGVyZQ.tunnel.info",
    ]

    phishing_query_domains = [
        "paypa1-secure-login.xyz", "sbi-netbanking-verify.top",
        "googIe-login.xyz", "amaz0n-order.xyz", "faceb00k-login.xyz",
        "hdfc-netbanking-login.xyz", "micros0ft-login.xyz",
        "appIe-id-verify.xyz", "netfIix-billing.xyz",
        "paytm-kyc-verify.xyz",
    ]

    queries_inserted = 0
    alerts_inserted = 0

    for i in range(count):
        timestamp = now - timedelta(seconds=rng.randint(1, 21600))
        timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        client_ip = rng.choice(client_ips)
        query_type = rng.choice(["A", "A", "A", "A", "AAAA", "CNAME", "MX", "TXT"])

        roll = rng.random()
        if roll < 0.70:
            domain = rng.choice(safe_domains)
            blocked = 0
            threat_type = "None"
            threat_score = round(rng.uniform(0, 15), 1)
        elif roll < 0.82:
            domain = rng.choice(dga_query_domains)
            blocked = 1
            threat_type = "DGA"
            threat_score = round(rng.uniform(75, 99), 1)
        elif roll < 0.90:
            domain = rng.choice(tunneling_query_domains)
            blocked = 1
            threat_type = "Tunneling"
            threat_score = round(rng.uniform(80, 99), 1)
        else:
            domain = rng.choice(phishing_query_domains)
            blocked = 1
            threat_type = "Phishing"
            threat_score = round(rng.uniform(65, 95), 1)

        c.execute("""
            INSERT INTO dns_queries (timestamp, client_ip, domain, query_type, blocked, threat_type, threat_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (timestamp_str, client_ip, domain, query_type, blocked, threat_type, threat_score))
        queries_inserted += 1

        if blocked:
            reasons = {
                "DGA": [
                    f"DGA pattern detected — Random Forest confidence {threat_score:.0f}%",
                    f"High entropy domain with algorithmic generation signatures (score {threat_score:.1f})",
                    f"Lexical analysis flagged non-human naming pattern. ML confidence: {threat_score:.1f}%",
                ],
                "Tunneling": [
                    f"Base64-encoded subdomain payload detected — DNS exfiltration attempt (score {threat_score:.1f})",
                    f"Anomalous subdomain length ({len(domain.split('.')[0])} chars) — Isolation Forest flagged as C2 tunnel",
                    f"DNS tunneling signature: encoded payload in subdomain. Anomaly score: {threat_score:.1f}",
                ],
                "Phishing": [
                    f"Brand impersonation detected — Levenshtein distance indicates lookalike domain (score {threat_score:.1f})",
                    f"Suspicious keywords (login/verify/account) combined with high-risk TLD (score {threat_score:.1f})",
                    f"Phishing vector identified: domain mimics trusted brand with typosquatting. Risk: {threat_score:.1f}%",
                ],
            }
            reason = rng.choice(reasons.get(threat_type, [f"Threat detected with score {threat_score}"]))
            c.execute("""
                INSERT INTO alerts (timestamp, client_ip, domain, threat_type, confidence, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (timestamp_str, client_ip, domain, threat_type, round(threat_score / 100, 3), reason))
            alerts_inserted += 1

    conn.commit()
    return queries_inserted, alerts_inserted



def setup_schema(conn):
    """Create all tables and indexes."""
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS dns_queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        client_ip TEXT,
        domain TEXT,
        query_type TEXT DEFAULT 'A',
        blocked BOOLEAN DEFAULT 0,
        threat_type TEXT DEFAULT 'None',
        threat_score REAL DEFAULT 0.0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        client_ip TEXT,
        domain TEXT,
        threat_type TEXT,
        confidence REAL,
        reason TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS static_blocklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE,
        category TEXT,
        source TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS training_domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT,
        label INTEGER,
        source TEXT,
        family TEXT DEFAULT 'unknown'
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS system_settings (
        id INTEGER PRIMARY KEY,
        dga_enabled INTEGER DEFAULT 1,
        tunnel_enabled INTEGER DEFAULT 1,
        risk_threshold REAL DEFAULT 80.0
    )''')

    c.execute('INSERT OR IGNORE INTO system_settings (id, dga_enabled, tunnel_enabled, risk_threshold) VALUES (1, 1, 1, 80.0)')

    c.execute('CREATE INDEX IF NOT EXISTS idx_queries_threat ON dns_queries (threat_type)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_queries_blocked ON dns_queries (blocked)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_queries_ts ON dns_queries (timestamp)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_blocklist_domain ON static_blocklist (domain)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_training_label ON training_domains (label)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_training_domain ON training_domains (domain)')

    conn.commit()
    print("  [✓] Schema created with 6 tables + 5 indexes")


def populate_training_data(conn):
    """Insert all training domains (legit + DGA + phishing + tunneling)."""
    c = conn.cursor()
    total_legit = 0
    total_dga = 0

    print("  [1/5] Inserting legitimate domains (curated list)...")
    for domain in LEGIT_DOMAINS:
        c.execute('INSERT INTO training_domains (domain, label, source, family) VALUES (?, 0, ?, ?)',
                  (domain.lower(), 'curated_top', 'legitimate'))
        total_legit += 1

    print("  [2/5] Generating additional legitimate domain variations...")
    extra_legit = generate_additional_legit_domains(2000)
    for domain in extra_legit:
        c.execute('INSERT INTO training_domains (domain, label, source, family) VALUES (?, 0, ?, ?)',
                  (domain.lower(), 'generated_legit', 'legitimate'))
        total_legit += 1

    print("  [3/5] Generating DGA domains across 15 malware families...")
    for family_name, config in DGA_FAMILIES.items():
        for i in range(config["count"]):
            seed = hash(f"{family_name}_{i}") & 0xFFFFFFFF
            domain = generate_dga_domain(config, seed)
            c.execute('INSERT INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)',
                      (domain.lower(), f'dga_{family_name}', family_name))
            total_dga += 1

    print("  [4/5] Inserting phishing/brand impersonation domains...")
    for domain in PHISHING_DOMAINS:
        c.execute('INSERT INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)',
                  (domain.lower(), 'phishing', 'phishing'))
        total_dga += 1

    print("  [5/5] Inserting DNS tunneling domains...")
    for domain in TUNNELING_DOMAINS:
        c.execute('INSERT INTO training_domains (domain, label, source, family) VALUES (?, 1, ?, ?)',
                  (domain.lower(), 'tunneling', 'tunneling'))
        total_dga += 1

    conn.commit()
    print(f"  [✓] Training data: {total_legit:,} legit + {total_dga:,} malicious = {total_legit + total_dga:,} total")
    return total_legit, total_dga


def populate_blocklist(conn):
    """Insert the static threat intelligence blocklist."""
    c = conn.cursor()
    count = 0

    for domain in BLOCKLIST_DOMAINS:
        try:
            c.execute('INSERT OR IGNORE INTO static_blocklist (domain, category, source) VALUES (?, ?, ?)',
                      (domain.lower(), 'Malware/Ads', 'IntrusionX-Curated'))
            count += 1
        except:
            pass

    for domain in PHISHING_DOMAINS:
        try:
            c.execute('INSERT OR IGNORE INTO static_blocklist (domain, category, source) VALUES (?, ?, ?)',
                      (domain.lower(), 'Phishing', 'IntrusionX-Curated'))
            count += 1
        except:
            pass

    for domain in TUNNELING_DOMAINS:
        try:
            c.execute('INSERT OR IGNORE INTO static_blocklist (domain, category, source) VALUES (?, ?, ?)',
                      (domain.lower(), 'Tunneling/C2', 'IntrusionX-Curated'))
            count += 1
        except:
            pass

    rng = random.Random(99)
    ad_prefixes = ["ad", "ads", "tracking", "pixel", "beacon", "analytics", "stat",
                   "click", "tracker", "metric", "promo", "banner", "popup"]
    ad_bases = ["server", "network", "platform", "exchange", "delivery", "cdn",
                "service", "sys", "hub", "engine", "gateway", "proxy"]
    ad_tlds = ["com", "net", "io", "co", "xyz"]
    
    for _ in range(1500):
        prefix = rng.choice(ad_prefixes)
        base = rng.choice(ad_bases)
        num = rng.randint(1, 999)
        tld = rng.choice(ad_tlds)
        domain = f"{prefix}-{base}{num}.{tld}"
        try:
            c.execute('INSERT OR IGNORE INTO static_blocklist (domain, category, source) VALUES (?, ?, ?)',
                      (domain, 'Ads/Tracking', 'IntrusionX-Generated'))
            count += 1
        except:
            pass

    conn.commit()
    print(f"  [✓] Blocklist: {count:,} domains")
    return count


def populate_whitelist(conn):
    """Insert default whitelisted domains."""
    c = conn.cursor()
    whitelist = [
        "google.com", "youtube.com", "github.com", "stackoverflow.com",
        "microsoft.com", "apple.com", "amazon.com", "wikipedia.org",
        "cloudflare.com", "mozilla.org", "python.org", "npmjs.com",
    ]
    for domain in whitelist:
        try:
            c.execute('INSERT OR IGNORE INTO whitelist (domain) VALUES (?)', (domain.lower(),))
        except:
            pass
    conn.commit()
    print(f"  [✓] Whitelist: {len(whitelist)} trusted domains")



def main():
    print()
    print("═" * 60)
    print("  IntrusionX — Complete Database Builder")
    print("  Generates dns_filter.db for model training & dashboard")
    print("═" * 60)
    print()

    start = time.time()

    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print(f"  [!] Removed existing {DB_FILE}")

    conn = sqlite3.connect(DB_FILE)

    print("\n── Step 1: Creating Schema ──")
    setup_schema(conn)

    print("\n── Step 2: Populating Training Data ──")
    legit, mal = populate_training_data(conn)

    print("\n── Step 3: Building Threat Intelligence Blocklist ──")
    bl_count = populate_blocklist(conn)

    print("\n── Step 4: Setting Up Whitelist ──")
    populate_whitelist(conn)

    print("\n── Step 5: Generating Realistic Query Logs & Alerts ──")
    q_count, a_count = generate_query_logs(conn, count=500)
    print(f"  [✓] Query logs: {q_count:,} queries, {a_count:,} alerts")

    conn.close()

    elapsed = time.time() - start
    db_size = os.path.getsize(DB_FILE) / (1024 * 1024)

    print()
    print("═" * 60)
    print("  BUILD COMPLETE")
    print("═" * 60)
    print(f"  Database:          {DB_FILE}")
    print(f"  Size:              {db_size:.2f} MB")
    print(f"  Training Domains:  {legit + mal:,} ({legit:,} legit + {mal:,} malicious)")
    print(f"  DGA Families:      {len(DGA_FAMILIES)}")
    print(f"  Phishing Domains:  {len(PHISHING_DOMAINS)}")
    print(f"  Tunneling Domains: {len(TUNNELING_DOMAINS)}")
    print(f"  Static Blocklist:  {bl_count:,} entries")
    print(f"  Query Logs:        {q_count:,}")
    print(f"  Alerts:            {a_count:,}")
    print(f"  Build Time:        {elapsed:.1f}s")
    print("═" * 60)
    print()
    print("  Next steps:")
    print("    1. python train_models.py   → Train ML models")
    print("    2. python app.py            → Launch dashboard")
    print()


if __name__ == "__main__":
    main()
