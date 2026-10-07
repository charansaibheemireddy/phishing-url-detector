from urllib.parse import urlparse
import re


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "bank",
    "password",
    "confirm",
    "signin",
    "wallet",
    "payment"
]


def analyze_url(url):

    original_url = url

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    score = 0
    reasons = []

    # 1. HTTPS check
    if parsed.scheme != "https":
        score += 15
        reasons.append("Website does not use HTTPS")

    # 2. URL length
    if len(original_url) > 75:
        score += 15
        reasons.append("URL is unusually long")

    # 3. IP address instead of domain
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, hostname):
        score += 25
        reasons.append("URL uses an IP address instead of a domain name")

    # 4. @ symbol
    if "@" in original_url:
        score += 20
        reasons.append("URL contains @ symbol")

    # 5. Too many subdomains
    if hostname.count(".") >= 3:
        score += 15
        reasons.append("URL contains many subdomains")

    # 6. Suspicious words
    lower_url = original_url.lower()

    found_words = []

    for word in SUSPICIOUS_WORDS:
        if word in lower_url:
            found_words.append(word)

    if found_words:
        score += min(len(found_words) * 5, 20)
        reasons.append(
            "Suspicious keywords found: " +
            ", ".join(found_words)
        )

    # 7. Hyphen-heavy domain
    if hostname.count("-") >= 2:
        score += 10
        reasons.append("Domain contains multiple hyphens")

    # Limit score
    score = min(score, 100)

    # Classification
    if score >= 60:
        status = "High Risk"
        recommendation = "Do not open or enter personal information."
    elif score >= 30:
        status = "Suspicious"
        recommendation = "Proceed carefully and verify the website."
    else:
        status = "Likely Safe"
        recommendation = "No major suspicious patterns were detected."

    return {
        "url": original_url,
        "score": score,
        "status": status,
        "reasons": reasons,
        "recommendation": recommendation
    }
