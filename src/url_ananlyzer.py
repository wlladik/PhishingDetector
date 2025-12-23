import re
from urllib.parse import urlparse

import tldextract


# --- Known legitimate domains (for typosquatting detection)
LEGITIMATE_DOMAINS = {
    "paypal",
    "google",
    "facebook",
    "microsoft",
    "apple",
    "amazon",
    "bank",
    "github"
}

# --- Suspicious TLDs
SUSPICIOUS_TLDS = {
    "xyz", "top", "pl", "cn", "tk", "ml", "ga", "cf"
}

# --- URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"
}


def levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    matrix = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]

    for i in range(len(a) + 1):
        matrix[i][0] = i
    for j in range(len(b) + 1):
        matrix[0][j] = j

    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            matrix[i][j] = min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            )

    return matrix[-1][-1]


def analyze_url(url: str) -> dict:
    score = 0
    reasons = []

    parsed = urlparse(url)

    # 1. IP address instead of domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.netloc):
        score += 3
        reasons.append("URL uses IP address instead of domain")

    # 2. URL length
    if len(url) > 75:
        score += 1
        reasons.append("URL is unusually long")

    # 3. Suspicious characters
    if "@" in url or url.count("//") > 1:
        score += 2
        reasons.append("Suspicious characters in URL")

    # 4. Domain analysis
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    if extracted.suffix in SUSPICIOUS_TLDS:
        score += 2
        reasons.append(f"Suspicious TLD: .{extracted.suffix}")

    if domain in URL_SHORTENERS:
        score += 3
        reasons.append("URL shortener detected")

    # 5. Typosquatting detection (Levenshtein distance)
    for legit in LEGITIMATE_DOMAINS:
        distance = levenshtein_distance(extracted.domain, legit)
        if 0 < distance <= 2:
            score += 3
            reasons.append(
                f"Possible typosquatting: {extracted.domain} similar to {legit}"
            )
            break

    return {
        "score": score,
        "reasons": reasons
    }
