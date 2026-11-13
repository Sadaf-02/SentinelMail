import re
from difflib import SequenceMatcher
from email.utils import parseaddr


# Common brands that attackers may try to imitate.
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "linkedin": "linkedin.com",
}


# Common free email providers.
FREE_EMAIL_PROVIDERS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "protonmail.com",
    "icloud.com",
}


def extract_sender_domain(sender):
    """
    Extract the domain from an email address.

    Example:
        security@example.com -> example.com
    """

    _, address = parseaddr(sender)

    if "@" not in address:
        return ""

    return address.split("@")[-1].lower().strip()


def is_valid_email(sender):
    """
    Perform a basic email-address format check.
    """

    _, address = parseaddr(sender)

    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return bool(re.match(pattern, address))


def similarity_score(domain, known_domain):
    """
    Return similarity between two domains as a value from 0 to 1.
    """

    return SequenceMatcher(
        None,
        domain.lower(),
        known_domain.lower()
    ).ratio()


def analyze_sender(sender):
    """
    Analyze a sender email address for suspicious characteristics.
    """

    result = {
        "sender": sender,
        "domain": "",
        "risk_score": 0,
        "indicators": [],
        "checks": {}
    }

    # --------------------------------------------------
    # 1. Validate email address
    # --------------------------------------------------

    if not is_valid_email(sender):

        result["risk_score"] += 2

        result["indicators"].append(
            "Sender email address has an invalid format"
        )

        return result

    domain = extract_sender_domain(sender)

    result["domain"] = domain

    # --------------------------------------------------
    # 2. Check free email provider
    # --------------------------------------------------

    if domain in FREE_EMAIL_PROVIDERS:

        result["checks"]["free_email_provider"] = True

        result["indicators"].append(
            "Sender uses a free email provider"
        )

        result["risk_score"] += 1

    else:

        result["checks"]["free_email_provider"] = False

    # --------------------------------------------------
    # 3. Check for suspiciously complex domain
    # --------------------------------------------------

    subdomain_count = domain.count(".")

    if subdomain_count >= 3:

        result["risk_score"] += 1

        result["indicators"].append(
            "Sender domain contains multiple subdomains"
        )

    # --------------------------------------------------
    # 4. Check for lookalike domains
    # --------------------------------------------------

    for brand, official_domain in KNOWN_BRANDS.items():

        if domain == official_domain:
            continue

        domain_name = domain.split(".")[0]
        official_name = official_domain.split(".")[0]

        similarity = similarity_score(domain_name, official_name)

        if similarity >= 0.80:

            result["risk_score"] += 2

            result["indicators"].append(
                f"Sender domain resembles {brand} "
                f"({official_domain})"
            )

            break

    # --------------------------------------------------
    # 5. Check for brand name inside a different domain
    # --------------------------------------------------

    domain_without_tld = domain.split(".")[0]

    for brand in KNOWN_BRANDS:

        if brand in domain_without_tld:

            official_domain = KNOWN_BRANDS[brand]

            if domain != official_domain:

                result["risk_score"] += 2

                result["indicators"].append(
                    f"Sender domain contains the brand name "
                    f"'{brand}' but is not the official domain"
                )

                break

    # --------------------------------------------------
    # 6. Detect suspicious characters
    # --------------------------------------------------

    suspicious_chars = [
        "-",
        "_"
    ]

    found_chars = [
        char for char in suspicious_chars
        if char in domain
    ]

    if len(found_chars) >= 2:

        result["risk_score"] += 1

        result["indicators"].append(
            "Sender domain contains multiple suspicious separators"
        )

    # --------------------------------------------------
    # Limit score
    # --------------------------------------------------

    result["risk_score"] = min(result["risk_score"], 10)

    return result


if __name__ == "__main__":

    test_senders = [

        # TEST 1 - Legitimate
        "support@example.com",

        # TEST 2 - Free email provider
        "securityteam@gmail.com",

        # TEST 3 - Lookalike domain
        "support@paypa1.com",

        # TEST 4 - Brand name in fake domain
        "security@microsoft-support-login.com",

        # TEST 5 - Multiple subdomains
        "admin@mail.security.example.com",

        # TEST 6 - Invalid email
        "invalid-email",

        # TEST 7 - Suspicious separators
        "support@secure-paypal-login.com"
    ]

    for i, sender in enumerate(test_senders, start=1):

        result = analyze_sender(sender)

        print("\n==============================")
        print(f"TEST {i}")
        print("==============================")

        print("Sender:", result["sender"])
        print("Domain:", result["domain"])
        print("Risk score:", result["risk_score"])

        print("Checks:", result["checks"])

        if result["indicators"]:

            print("Indicators:")

            for indicator in result["indicators"]:
                print("-", indicator)

        else:

            print("Indicators: None")