def calculate_risk(alert):

    severity_scores = {
        "LOW": 30,
        "MEDIUM": 60,
        "HIGH": 80
    }

    score = severity_scores.get(alert["severity"], 0)

    if alert["attempts"] >= 10:
        score += 20

    elif alert["attempts"] >= 5:
        score += 10

    score = min(score, 100)

    if score >= 80:
        risk_level = "CRITICAL"

    elif score >= 60:
        risk_level = "HIGH"

    elif score >= 30:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level
    }
