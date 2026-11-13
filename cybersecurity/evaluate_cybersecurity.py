import pandas as pd

from url_checker import analyze_email_urls
from keyword_checker import analyze_keywords
from threat_score import calculate_threat_score


DATASET_PATH = "dataset/phishing_legit_dataset_clean.csv"


def analyze_email(email_text):

    url_result = analyze_email_urls(email_text)

    keyword_result = analyze_keywords(email_text)

    # Sender and header information are not available
    # in the current CSV dataset.
    sender_result = {
        "risk_score": 0,
        "indicators": []
    }

    header_result = {
        "risk_score": 0,
        "indicators": []
    }

    threat_result = calculate_threat_score(
        url_result,
        keyword_result,
        header_result,
        sender_result
    )

    return threat_result


if __name__ == "__main__":

    print("==============================")
    print("SENTINELMAIL CYBERSECURITY EVALUATION")
    print("==============================")

    df = pd.read_csv(DATASET_PATH)

    scores = []
    levels = []

    for _, row in df.iterrows():

        result = analyze_email(row["text"])

        scores.append(result["threat_score"])
        levels.append(result["threat_level"])

    df["cyber_score"] = scores
    df["cyber_level"] = levels

    # ---------------------------------------------
    # Overall statistics
    # ---------------------------------------------

    print("\nTotal emails:", len(df))

    print("\nAverage threat score:")
    print(
        round(df["cyber_score"].mean(), 2)
    )

    # ---------------------------------------------
    # Compare legitimate vs phishing
    # ---------------------------------------------

    print("\n==============================")
    print("SCORE BY ACTUAL LABEL")
    print("==============================")

    print(
        df.groupby("label")["cyber_score"]
        .agg(["count", "mean", "min", "max"])
    )

    # ---------------------------------------------
    # Threat levels by actual label
    # ---------------------------------------------

    print("\n==============================")
    print("THREAT LEVEL DISTRIBUTION")
    print("==============================")

    print(
        pd.crosstab(
            df["label"],
            df["cyber_level"],
            normalize="index"
        ).round(3) * 100
    )

    # ---------------------------------------------
    # Phishing detection
    # ---------------------------------------------

    # For now, MEDIUM or above is considered detected.
    detected = df["cyber_score"] >= 25

    phishing = df["label"] == 1
    legitimate = df["label"] == 0

    phishing_detected = (detected & phishing).sum()
    phishing_total = phishing.sum()

    legitimate_flagged = (detected & legitimate).sum()
    legitimate_total = legitimate.sum()

    print("\n==============================")
    print("DETECTION SUMMARY")
    print("==============================")

    print(
        "Phishing detected:",
        phishing_detected,
        "/",
        phishing_total
    )

    print(
        "Phishing detection rate:",
        round(
            phishing_detected / phishing_total * 100,
            2
        ),
        "%"
    )

    print(
        "Legitimate falsely flagged:",
        legitimate_flagged,
        "/",
        legitimate_total
    )

    print(
        "False positive rate:",
        round(
            legitimate_flagged / legitimate_total * 100,
            2
        ),
        "%"
    )

    # ---------------------------------------------
    # Phishing types
    # ---------------------------------------------

    print("\n==============================")
    print("PHISHING TYPE ANALYSIS")
    print("==============================")

    phishing_df = df[df["label"] == 1]

    print(
        phishing_df.groupby("phishing_type")["cyber_score"]
        .agg(["count", "mean", "min", "max"])
        .sort_values("mean", ascending=False)
    )