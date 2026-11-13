import joblib

model = joblib.load("ai/model.pkl")
vectorizer = joblib.load("ai/vectorizer.pkl")


def predict_email(email_text):
    email_vector = vectorizer.transform([email_text])

    prediction = model.predict(email_vector)[0]
    probabilities = model.predict_proba(email_vector)[0]

    safe_probability = probabilities[0]
    phishing_probability = probabilities[1]

    result = "Phishing" if prediction == 1 else "Safe"

    return result, phishing_probability, safe_probability


test_emails = [

    # 1. Credential phishing
    """
    URGENT: Your Microsoft 365 account will be disabled today.
    We detected unusual activity on your account.
    Verify your identity immediately using the secure link below.
    Enter your password and verification code to prevent permanent suspension.
    """,

    # 2. Financial phishing
    """
    Dear Customer,

    We noticed a suspicious transaction on your bank account.
    Your account has been temporarily restricted.
    Please confirm your account information immediately to restore access.
    Failure to verify within 24 hours may result in account closure.
    """,

    # 3. Legitimate workplace email
    """
    Hi team,

    The meeting has been moved to 3 PM tomorrow.
    Please review the attached project updates before the meeting.

    Thanks,
    Rahul
    """,

    # 4. Legitimate shopping email
    """
    Hi,

    Your order has been shipped and is expected to arrive on Friday.
    You can check the delivery status from your account whenever convenient.

    Thank you for shopping with us.
    """,

    # 5. Legitimate security notification
    """
    Subject: Account Security Notification

    Hello,

    Your password was successfully changed.
    If you made this change, no further action is required.

    If you did not make this change, please contact our support team
    through the official website.

    Thank you,
    Security Team
    """
]


for i, email in enumerate(test_emails, start=1):

    result, phishing_probability, safe_probability = predict_email(email)

    print("\n==============================")
    print(f"EMAIL {i}")
    print("==============================")

    print("Prediction:", result)
    print("Phishing:", round(phishing_probability * 100, 2), "%")
    print("Safe:", round(safe_probability * 100, 2), "%")