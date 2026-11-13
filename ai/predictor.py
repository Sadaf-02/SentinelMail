import joblib

model = joblib.load("ai/model.pkl")
vectorizer = joblib.load("ai/vectorizer.pkl")

DECISION_THRESHOLD = 0.60


def predict_email(email_text):

    email_vector = vectorizer.transform([email_text])

    probabilities = model.predict_proba(email_vector)[0]

    phishing_probability = probabilities[1]
    safe_probability = probabilities[0]

    # SentinelMail decision threshold
    if phishing_probability >= DECISION_THRESHOLD:
        result = "Phishing"
    else:
        result = "Safe"

    return result, phishing_probability, safe_probability


if __name__ == "__main__":

    test_email = """
    URGENT! Your account has been suspended.
    Click the link below immediately to verify your password.
    Failure to do so will result in permanent account closure.
    """

    result, phishing_probability, safe_probability = predict_email(test_email)

    print("Prediction:", result)
    print(
        "Phishing probability:",
        round(phishing_probability * 100, 2),
        "%"
    )

    print(
        "Safe probability:",
        round(safe_probability * 100, 2),
        "%"
    )

    print(
        "Decision threshold:",
        DECISION_THRESHOLD * 100,
        "%"
    )