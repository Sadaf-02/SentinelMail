from email.utils import parseaddr
from urllib.parse import urlparse


def extract_domain(email_address):
    """
    Extract the domain from an email address.
    Example:
        security@example.com -> example.com
    """

    _, address = parseaddr(email_address)

    if "@" not in address:
        return ""

    return address.split("@")[-1].lower().strip()


def analyze_headers(headers):
    """
    Analyze email headers for suspicious sender and
    authentication patterns.

    Expected input:

    {
        "from": "security@example.com",
        "reply_to": "support@example.com",
        "return_path": "bounce@example.com",
        "spf": "pass",
        "dkim": "pass",
        "dmarc": "pass"
    }
    """

    result = {
        "risk_score": 0,
        "indicators": [],
        "checks": {}
    }

    from_address = headers.get("from", "").strip()
    reply_to = headers.get("reply_to", "").strip()
    return_path = headers.get("return_path", "").strip()

    spf = headers.get("spf", "").lower().strip()
    dkim = headers.get("dkim", "").lower().strip()
    dmarc = headers.get("dmarc", "").lower().strip()

    # --------------------------------------------------
    # 1. Check From address
    # --------------------------------------------------

    from_domain = extract_domain(from_address)

    if not from_domain:
        result["risk_score"] += 1

        result["indicators"].append(
            "Could not determine the sender domain"
        )

    result["checks"]["from_domain"] = from_domain

    # --------------------------------------------------
    # 2. Check Reply-To mismatch
    # --------------------------------------------------

    if reply_to and from_domain:

        reply_domain = extract_domain(reply_to)

        result["checks"]["reply_to_domain"] = reply_domain

        if reply_domain and reply_domain != from_domain:

            result["risk_score"] += 2

            result["indicators"].append(
                "Reply-To domain differs from the From domain"
            )

    # --------------------------------------------------
    # 3. Check Return-Path mismatch
    # --------------------------------------------------

    if return_path and from_domain:

        return_domain = extract_domain(return_path)

        result["checks"]["return_path_domain"] = return_domain

        if return_domain and return_domain != from_domain:

            result["risk_score"] += 1

            result["indicators"].append(
                "Return-Path domain differs from the From domain"
            )

    # --------------------------------------------------
    # 4. SPF
    # --------------------------------------------------

    if spf == "fail":

        result["risk_score"] += 2

        result["indicators"].append(
            "SPF authentication failed"
        )

    elif spf == "softfail":

        result["risk_score"] += 1

        result["indicators"].append(
            "SPF authentication returned softfail"
        )

    elif spf == "pass":

        result["checks"]["spf"] = "pass"

    # --------------------------------------------------
    # 5. DKIM
    # --------------------------------------------------

    if dkim == "fail":

        result["risk_score"] += 2

        result["indicators"].append(
            "DKIM authentication failed"
        )

    elif dkim == "pass":

        result["checks"]["dkim"] = "pass"

    # --------------------------------------------------
    # 6. DMARC
    # --------------------------------------------------

    if dmarc == "fail":

        result["risk_score"] += 2

        result["indicators"].append(
            "DMARC authentication failed"
        )

    elif dmarc == "pass":

        result["checks"]["dmarc"] = "pass"

    # --------------------------------------------------
    # Final score limit
    # --------------------------------------------------

    result["risk_score"] = min(result["risk_score"], 10)

    return result


if __name__ == "__main__":

    test_headers = [

        # ---------------------------------------------
        # TEST 1 - Normal email
        # ---------------------------------------------
        {
            "from": "hr@example.com",
            "reply_to": "hr@example.com",
            "return_path": "bounce@example.com",
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass"
        },

        # ---------------------------------------------
        # TEST 2 - Reply-To mismatch
        # ---------------------------------------------
        {
            "from": "security@company.com",
            "reply_to": "attacker@gmail.com",
            "return_path": "bounce@company.com",
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass"
        },

        # ---------------------------------------------
        # TEST 3 - Authentication failures
        # ---------------------------------------------
        {
            "from": "security@company.com",
            "reply_to": "security@company.com",
            "return_path": "bounce@company.com",
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail"
        },

        # ---------------------------------------------
        # TEST 4 - Reply-To + Return-Path mismatch
        # ---------------------------------------------
        {
            "from": "support@bank.com",
            "reply_to": "help@attacker.com",
            "return_path": "bounce@attacker.com",
            "spf": "softfail",
            "dkim": "pass",
            "dmarc": "fail"
        },

        # ---------------------------------------------
        # TEST 5 - Invalid sender
        # ---------------------------------------------
        {
            "from": "invalid-address",
            "reply_to": "",
            "return_path": "",
            "spf": "",
            "dkim": "",
            "dmarc": ""
        }
    ]

    for i, headers in enumerate(test_headers, start=1):

        result = analyze_headers(headers)

        print("\n==============================")
        print(f"TEST {i}")
        print("==============================")

        print("Risk score:", result["risk_score"])

        print("Checks:", result["checks"])

        if result["indicators"]:

            print("Indicators:")

            for indicator in result["indicators"]:
                print("-", indicator)

        else:

            print("Indicators: None")