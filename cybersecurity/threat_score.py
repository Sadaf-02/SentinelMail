def calculate_threat_score(url_result, keyword_result, header_result, sender_result):

    url_score = url_result.get("risk_score", 0)
    keyword_score = keyword_result.get("risk_score", 0)
    header_score = header_result.get("risk_score", 0)
    sender_score = sender_result.get("risk_score", 0)

    # Normalize each module to a 0-100 contribution
    url_component = min(url_score / 8, 1) * 30
    keyword_component = min(keyword_score / 7, 1) * 30
    header_component = min(header_score / 6, 1) * 20
    sender_component = min(sender_score / 6, 1) * 20

    threat_score = (
        url_component
        + keyword_component
        + header_component
        + sender_component
    )

    # Threat level
    if threat_score >= 75:
        threat_level = "CRITICAL"
    elif threat_score >= 50:
        threat_level = "HIGH"
    elif threat_score >= 25:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    indicators = []

    for result in [
        url_result,
        keyword_result,
        header_result,
        sender_result
    ]:
        indicators.extend(result.get("indicators", []))

    return {
        "threat_score": round(threat_score, 2),
        "threat_level": threat_level,
        "module_scores": {
            "url": url_score,
            "keyword": keyword_score,
            "header": header_score,
            "sender": sender_score
        },
        "indicators": indicators
    }

if __name__ == "__main__":

    # --------------------------------------------------
    # TEST 1 - Completely safe email
    # --------------------------------------------------

    safe_url = {
        "risk_score": 0,
        "indicators": []
    }

    safe_keyword = {
        "risk_score": 0,
        "indicators": []
    }

    safe_header = {
        "risk_score": 0,
        "indicators": []
    }

    safe_sender = {
        "risk_score": 0,
        "indicators": []
    }

    result = calculate_threat_score(
        safe_url,
        safe_keyword,
        safe_header,
        safe_sender
    )

    print("\n==============================")
    print("TEST 1 - SAFE EMAIL")
    print("==============================")

    print("Threat score:", result["threat_score"])
    print("Threat level:", result["threat_level"])
    print("Module scores:", result["module_scores"])
    print("Indicators:", result["indicators"])


    # --------------------------------------------------
    # TEST 2 - Suspicious email
    # --------------------------------------------------

    suspicious_url = {
        "risk_score": 3,
        "indicators": [
            "URL contains suspicious keywords: login, verify"
        ]
    }

    suspicious_keyword = {
        "risk_score": 4,
        "indicators": [
            "Credential Request detected",
            "Urgency detected"
        ]
    }

    suspicious_header = {
        "risk_score": 2,
        "indicators": [
            "Reply-To domain differs from the From domain"
        ]
    }

    suspicious_sender = {
        "risk_score": 2,
        "indicators": [
            "Sender domain resembles paypal (paypal.com)"
        ]
    }

    result = calculate_threat_score(
        suspicious_url,
        suspicious_keyword,
        suspicious_header,
        suspicious_sender
    )

    print("\n==============================")
    print("TEST 2 - SUSPICIOUS EMAIL")
    print("==============================")

    print("Threat score:", result["threat_score"])
    print("Threat level:", result["threat_level"])
    print("Module scores:", result["module_scores"])

    print("Indicators:")

    for indicator in result["indicators"]:
        print("-", indicator)


    # --------------------------------------------------
    # TEST 3 - Highly suspicious email
    # --------------------------------------------------

    high_url = {
        "risk_score": 8,
        "indicators": [
            "URL uses an IP address instead of a domain name",
            "URL contains suspicious keywords"
        ]
    }

    high_keyword = {
        "risk_score": 8,
        "indicators": [
            "Credential Request detected",
            "Threat detected",
            "Urgency detected"
        ]
    }

    high_header = {
        "risk_score": 6,
        "indicators": [
            "SPF authentication failed",
            "DKIM authentication failed",
            "DMARC authentication failed"
        ]
    }

    high_sender = {
        "risk_score": 6,
        "indicators": [
            "Sender domain resembles paypal (paypal.com)"
        ]
    }

    result = calculate_threat_score(
        high_url,
        high_keyword,
        high_header,
        high_sender
    )

    print("\n==============================")
    print("TEST 3 - HIGHLY SUSPICIOUS EMAIL")
    print("==============================")

    print("Threat score:", result["threat_score"])
    print("Threat level:", result["threat_level"])
    print("Module scores:", result["module_scores"])

    print("Indicators:")

    for indicator in result["indicators"]:
        print("-", indicator)