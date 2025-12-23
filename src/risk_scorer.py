def classify_risk(score: int) -> str:
    if score >= 6:
        return "PHISHING"
    elif score >= 3:
        return "SUSPICIOUS"
    else:
        return "SAFE"


def classify_risk_url(score: int) -> str:
    if score >= 3:
        return "PHISHING"
    elif score >= 2:
        return "SUSPICIOUS"
    else:
        return "SAFE"