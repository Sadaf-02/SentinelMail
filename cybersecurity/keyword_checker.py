import re

KEYWORD_RULES = {

    "urgency": [
        "act immediately",
        "immediately",
        "within 24 hours",
        "urgent",
        "act now",
        "respond immediately",
        "immediate action"
    ],

    "credential_request": [
        "enter your password",
        "verify your account",
        "enter your username",
        "enter your login",
        "sign in",
        "reset your password",
        "confirm your password"
    ],

    "financial_request": [
        "bank details",
        "credit card",
        "bank account",
        "account number",
        "payment details",
        "wire transfer",
        "transfer money",
        "temporary loan",
        "emergency loan"
    ],

    "sensitive_information": [
        "otp",
        "verification code",
        "security code",
        "one time password",
        "ssn",
        "social security number"
    ],

    "threat": [
        "account will be suspended",
        "legal action",
        "failure to respond",
        "security violation",
        "account has been suspended",
        "account will be closed",
        "malware detected"
    ],

    "reward_scam": [
        "you are the winner",
        "congratulations",
        "claim your prize",
        "you have won",
        "winner",
        "prize"
    ],

    "generic_phishing": [
        "click here",
        "new notification",
        "new update",
        "link and attachment",
        "do not reply",
        "auto-generated message",
        "confidential"
    ],

    "tech_support": [
        "it department",
        "technical support",
        "tech support",
        "malware infection",
        "security patch",
        "system administrator",
        "firewall",
        "help desk",
        "support team",
        "technical issue",
        "repair",
        "spyware"
    ],

    "romance_scam": [
        "temporary loan",
        "emergency loan",
        "wallet was stolen",
        "wallet stolen",
        "payment verification",
        "replacement cards",
        "stranded traveler",
        "business trip",
        "transfer back next week"
    ],

    "social_engineering": [
        "financial request",
        "trust building",
        "unusual situation",
        "emergency request",
        "stranded",
        "payment verification",
        "temporary loan"
    ]
}

CATEGORY_SCORES = {
    "urgency": 1,
    "credential_request": 2,
    "financial_request": 2,
    "sensitive_information": 2,
    "threat": 2,
    "reward_scam": 2,
    "generic_phishing": 2,
    "tech_support": 2,
    "romance_scam": 2,
    "social_engineering": 2
}


def normalize_text(text):
    """
    Convert email text into a consistent format.
    """
    if not text:
        return ""

    text = text.lower()
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def analyze_keywords(email_text):
    """
    Analyze an email for phishing-related keywords and phrases.
    """

    text = normalize_text(email_text)

    result = {
        "risk_score": 0,
        "categories": [],
        "indicators": [],
        "matched_keywords": []
    }

    if not text:
        return result

    for category, keywords in KEYWORD_RULES.items():

        found_keywords = []

        for keyword in keywords:
            if keyword in text:
                found_keywords.append(keyword)

        if found_keywords:

            result["categories"].append(category)

            result["matched_keywords"].extend(found_keywords)

            result["indicators"].append(
                f"{category.replace('_', ' ').title()} detected: "
                + ", ".join(found_keywords)
            )

            result["risk_score"] += CATEGORY_SCORES[category]

    # Prevent keyword rules from producing an excessively large score
    result["risk_score"] = min(result["risk_score"], 10)

    return result


if __name__ == "__main__":

    test_emails = [

        # Test 1 - legitimate
        """Hello,

        The project meeting has been moved to tomorrow.

        Thanks,
        Avery
        """,

        # Test 2 - urgency
        """Your account requires attention.
        Please act immediately and respond within 24 hours.
        """,

        # Test 3 - credential phishing
        """Your account has been restricted.
        Please verify your account and enter your password.
        """,

        # Test 4 - financial phishing
        """Your payment could not be processed.
        Please provide your credit card and bank details.
        """,

        # Test 5 - OTP phishing
        """Your verification code is required.
        Please provide your OTP to continue.
        """,

        # Test 6 - threat
        """Security violation detected.
        Failure to respond will result in legal action
        and your account will be suspended.
        """,

        # Test 7 - reward scam
        """Congratulations!
        You are the winner.
        Claim your prize today.
        """
    ]

    for i, email in enumerate(test_emails, start=1):

        result = analyze_keywords(email)

        print("\n==============================")
        print(f"TEST {i}")
        print("==============================")

        print("Risk score:", result["risk_score"])

        print("Categories:", result["categories"])

        print("Matched keywords:", result["matched_keywords"])

        if result["indicators"]:

            print("Indicators:")

            for indicator in result["indicators"]:
                print("-", indicator)

        else:
            print("Indicators: None")