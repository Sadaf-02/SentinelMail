import pandas as pd

from url_checker import analyze_email_urls
from keyword_checker import analyze_keywords
from threat_score import calculate_threat_score


DATASET_PATH = "dataset/phishing_legit_dataset_clean.csv"


def analyze_email(email_text):
    """
    Run the available cybersecurity checks on one email.
    """

    # URL analysis
    url_result = analyze_email_urls(email_text)

    # Keyword analysis
    keyword_result = analyze_keywords(email_text)

    # Sender/header information is not available
    # in our current CSV dataset.
    sender_result = {
        "risk_score": 0,
        "indicators": []
    }

    header_result = {
        "risk_score": 0,
        "indicators": []
    }

    # Combine results
    threat_result = calculate_threat_score(
        url_result,
        keyword_result,
        header_result,
        sender_result
    )

    return {
        "url": url_result,
        "keyword": keyword_result,
        "threat": threat_result
    }


if __name__ == "__main__":

    # --------------------------------------------------
    # Load cleaned dataset
    # --------------------------------------------------

    df = pd.read_csv(DATASET_PATH)

    print("==============================")
    print("SENTINELMAIL CYBERSECURITY TEST")
    print("==============================")

    print("Dataset rows:", len(df))

    # --------------------------------------------------
    # Take a small sample from both classes
    # --------------------------------------------------

    phishing_samples = df[df["label"] == 1].head(5)
    legitimate_samples = df[df["label"] == 0].head(5)

    samples = pd.concat(
        [legitimate_samples, phishing_samples]
    )

    # --------------------------------------------------
    # Analyze each email
    # --------------------------------------------------

    for index, row in samples.iterrows():

        email_text = row["text"]
        actual_label = row["label"]

        result = analyze_email(email_text)

        print("\n==============================")
        print("EMAIL")
        print("==============================")

        print("Actual label:",
              "PHISHING" if actual_label == 1 else "LEGITIMATE")

        print("Phishing type:",
              row["phishing_type"])

        print("Severity:",
              row["severity"])

        print("Confidence:",
              row["confidence"])

        print("\nURL analysis:")
        print(
            "URLs found:",
            result["url"]["url_count"]
        )

        print(
            "URL risk:",
            result["url"]["urls"]
        )

        print("\nKeyword analysis:")
        print(
            "Keyword risk:",
            result["keyword"]["risk_score"]
        )

        print(
            "Categories:",
            result["keyword"]["categories"]
        )

        print("\nFinal cybersecurity result:")

        print(
            "Threat score:",
            result["threat"]["threat_score"]
        )

        print(
            "Threat level:",
            result["threat"]["threat_level"]
        )

        print(
            "Indicators:",
            result["threat"]["indicators"]
        )