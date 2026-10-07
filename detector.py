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
    "payment",
    "recover"
]


def analyze_url(url):

    original_url = url.strip()

    if not original_url:
        return {
            "error": "URL cannot be empty"
        }

    if not original_url.startswith(
        ("http://", "https://")
    ):
        url = "http://" + original_url
    else:
        url = original_url


    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    score = 0

    reasons = []


    # HTTPS

    if parsed.scheme != "https":

        score += 15

        reasons.append(
            "Website does not use HTTPS"
        )


    # URL length

    if len(original_url) > 75:

        score += 15

        reasons.append(
            "URL is unusually long"
        )


    # IP address

    ip_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    if re.match(
        ip_pattern,
        hostname
    ):

        score += 25

        reasons.append(
            "URL uses an IP address instead of a domain name"
        )


    # @ symbol

    if "@" in original_url:

        score += 20

        reasons.append(
            "URL contains an @ symbol"
        )


    # Subdomains

    if hostname.count(".") >= 3:

        score += 15

        reasons.append(
            "URL contains multiple subdomains"
        )


    # Suspicious keywords

    lower_url =
        original_url.lower()

    found_words = []

    for word in SUSPICIOUS_WORDS:

        if word in lower_url:

            found_words.append(word)


    if found_words:

        score += min(
            len(found_words) * 5,
            20
        )

        reasons.append(
            "Suspicious keywords: "
            + ", ".join(found_words)
        )


    # Hyphens

    if hostname.count("-") >= 2:

        score += 10

        reasons.append(
            "Domain contains multiple hyphens"
        )


    score = min(score, 100)


    if score >= 60:

        status = "High Risk"

        recommendation = (
            "Do not open this website or "
            "enter personal information."
        )

    elif score >= 30:

        status = "Suspicious"

        recommendation = (
            "Verify the domain carefully "
            "before interacting with it."
        )

    else:

        status = "Likely Safe"

        recommendation = (
            "No major suspicious patterns "
            "were detected."
        )


    return {

        "url": original_url,

        "score": score,

        "status": status,

        "reasons": reasons,

        "recommendation": recommendation

    }
