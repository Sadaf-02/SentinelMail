import re
from urllib.parse import urlparse

def extract_urls(text):
    if not text:
        return[]
    url_pattern=r'https?://[^\s<>"\']+'
    return re.findall(url_pattern, text)
def analyze_url(url):
    result={
        "url":url,
        "suspicious":False,
        "risk_score":0,
        "indicators":[]
    }
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path= parsed.path or ""
        ip_pattern=r"^\d{1,3}(\.\d{1,3}){3}$"
        if re.match(ip_pattern,hostname):
            result["risk_score"] += 2
            result["indicators"].append("URL uses an IP address instead of a domain name")
        
        if "@" in url:
            result["risk_score"] +=2
            result["indicators"].append(
                "URL contains '@' which can hide the real destination"
            )
        suspicious_words=[
            "login",
            "verify",
            "update",
            "secure",
            "account",
            "password",
            "confirm",
            "wallet",
            "verification",
            "signin",
            ]
        url_lower = url.lower()

        found_words = [
            word for word in suspicious_words
            if word in url_lower
        ]

        if found_words:
            result["risk_score"] += min(len(found_words), 3)
            result["indicators"].append(
                "URL contains suspicious keywords: "
                 + ", ".join(found_words)
        )
      
        if not re.match(ip_pattern, hostname):
            subdomain_count = hostname.count(".")

            if subdomain_count >= 3:
                result["risk_score"] += 1
                result["indicators"].append(
                    "URL contains multiple subdomains"
                )

        shortened_domains = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "is.gd",
            "buff.ly"
        ]

        if hostname.lower() in shortened_domains:
            result["risk_score"] += 2
            result["indicators"].append(
                "URL uses a URL shortening service"
            )

        if result["risk_score"] >= 2:
            result["suspicious"] = True

    except Exception:
        result["risk_score"] = 1
        result["indicators"].append(
            "Could not fully analyze this URL"
        )

    return result


def analyze_email_urls(email_text):
    """
    Extract and analyze all URLs present in an email.
    """

    urls = extract_urls(email_text)

    results = []

    for url in urls:
        results.append(analyze_url(url))

    return {
        "url_count": len(urls),
        "urls": results
    }

if __name__ == "__main__":

    test_emails = [
        """Hello,
        Please visit https://www.google.com to continue.
        Thanks.""",

        """Your account needs verification:
        http://192.168.1.100/login""",

        """Please visit:
        https://google.com@evil-example.com/login""",

        """Your account has been suspended.
        Verify your password:
        https://secure-example.com/login/verify""",

        """Please visit:
        https://login.account.verify.security.example.com/update""",

        """Click here:
        https://bit.ly/abc123""",

        """Hello,
        This is a normal email with no links.
        Have a great day."""
    ]

    for i, email in enumerate(test_emails, start=1):

        result = analyze_email_urls(email)

        print("\n==============================")
        print(f"TEST {i}")
        print("==============================")

        print("URLs found:", result["url_count"])

        for item in result["urls"]:
            print("URL:", item["url"])
            print("Risk score:", item["risk_score"])
            print("Suspicious:", item["suspicious"])

            if item["indicators"]:
                print("Indicators:")

                for indicator in item["indicators"]:
                    print("-", indicator)
