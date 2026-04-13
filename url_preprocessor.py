"""
IntrusionX - URL Preprocessor Module
url_preprocessor.py

Handles URL unmasking, redirect detection, and URL masking techniques
such as credential-based URL obfuscation (user@host) and encoded characters.
"""

import re
from urllib.parse import urlparse, unquote


def unmask_url(raw_url: str) -> dict:
    """
    Unmask a potentially obfuscated URL.
    Handles:
      - Credential-based masking (e.g., http://google.com@evil.com)
      - Percent-encoded characters
      - Nested redirects via query parameters
    
    Returns:
        dict with keys:
            - final_domain (str): The true destination domain
            - redirect_chain_length (int): Number of redirect hops detected
    """
    url = raw_url.strip()
    redirect_chain_length = 0

    # Decode any percent-encoding
    url = unquote(url)

    # Ensure scheme for proper parsing
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    # Track redirect chains embedded in query parameters
    redirect_params = ["url", "redirect", "next", "target", "dest", "destination", "goto", "return", "returnto", "rurl"]
    visited = set()
    current_url = url

    while True:
        if current_url in visited:
            break
        visited.add(current_url)

        parsed = urlparse(current_url)
        # Check for credential-based masking: http://legit.com@evil.com
        netloc = parsed.netloc
        if "@" in netloc:
            # The real host is after the @
            netloc = netloc.split("@")[-1]

        # Strip port
        host = netloc.split(":")[0] if ":" in netloc else netloc
        domain = host.lower()

        # Check query string for embedded redirect URLs
        query = parsed.query
        found_redirect = False
        for param in redirect_params:
            pattern = re.compile(rf"(?:^|&){re.escape(param)}=(https?%3A%2F%2F[^&]+|https?://[^&]+)", re.IGNORECASE)
            match = pattern.search(query)
            if match:
                next_url = unquote(match.group(1))
                if not next_url.startswith("http"):
                    next_url = "http://" + next_url
                current_url = next_url
                redirect_chain_length += 1
                found_redirect = True
                break

        if not found_redirect:
            break

    return {
        "final_domain": domain,
        "redirect_chain_length": redirect_chain_length,
    }


def detect_url_masking(domain: str) -> str:
    """
    Detect and strip URL masking techniques from a domain string.
    Handles:
      - Credential-based obfuscation (user@realhost)
      - Trailing dots
      - Homoglyph-style zero-width characters
    
    Returns:
        The cleaned, true domain string.
    """
    cleaned = domain.strip().lower()

    # Remove zero-width characters often used in homoglyph attacks
    zero_width = ["\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\ufeff"]
    for zw in zero_width:
        cleaned = cleaned.replace(zw, "")

    # Handle credential-based masking
    if "@" in cleaned:
        cleaned = cleaned.split("@")[-1]

    # Strip trailing dots
    cleaned = cleaned.rstrip(".")

    # Remove any scheme if accidentally included
    if cleaned.startswith("http://"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("https://"):
        cleaned = cleaned[8:]

    # Remove path
    if "/" in cleaned:
        cleaned = cleaned.split("/")[0]

    # Remove port
    if ":" in cleaned:
        cleaned = cleaned.split(":")[0]

    return cleaned
