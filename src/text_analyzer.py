import re


SUSPICIOUS_KEYWORDS = {
    "urgent", "verify", "account", "password",
    "login", "security", "confirm", "update",
    "click", "immediately", "wining", "prize", "win", "won",
    "download", "bank account", "contact", "refund", "help",
    "subscription", "renew", "transaction"
}


def analyze_text(text: str) -> dict:
    score = 0
    reasons = []

    text_lower = text.lower()

    # 1. Suspicious keywords
    keyword_hits = [k for k in SUSPICIOUS_KEYWORDS if k in text_lower]
    if keyword_hits:
        score += len(keyword_hits)
        reasons.append(f"Suspicious keywords found: {', '.join(keyword_hits)}")

    # 2. Excessive capitalization
    if sum(1 for c in text if c.isupper()) > len(text) * 0.3:
        score += 2
        reasons.append("Excessive use of capital letters")

    # 3. Excessive exclamation marks
    if text.count("!") >= 3:
        score += 1
        reasons.append("Too many exclamation marks")

    # 4. Links inside text
    if re.search(r"http[s]?://", text):
        score += 1
        reasons.append("Link found inside message")

    return {
        "score": score,
        "reasons": reasons
    }
