from src.url_ananlyzer import analyze_url
from src.text_analyzer import analyze_text
from src.risk_scorer import classify_risk, classify_risk_url


def detect_phishing(url: str = None, text: str = None) -> dict:
    total_score = 0
    reasons = []

    if url:
        url_result = analyze_url(url)
        total_score += url_result["score"]
        reasons.extend(url_result["reasons"])
        verdict = classify_risk_url(total_score)

    if text:
        text_result = analyze_text(text)
        total_score += text_result["score"]
        reasons.extend(text_result["reasons"])
        verdict = classify_risk(total_score)

    return {
        "score": total_score,
        "verdict": verdict,
        "reasons": reasons
    }
