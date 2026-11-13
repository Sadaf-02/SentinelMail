import pandas as pd
import joblib

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

# Load validation dataset
df = pd.read_csv("dataset/validation_emails.csv")

# Load trained model and TF-IDF vectorizer
model = joblib.load("ai/model.pkl")
vectorizer = joblib.load("ai/vectorizer.pkl")

# Separate text and actual labels
X = df["text"]
y_true = df["label"]

# Convert emails using the SAME vectorizer used during training
X_tfidf = vectorizer.transform(X)

# Make predictions
y_pred = model.predict(X_tfidf)

# Calculate probabilities
probabilities = model.predict_proba(X_tfidf)

# Evaluation
accuracy = accuracy_score(y_true, y_pred)

print("\n======================================")
print("SENTINELMAIL VALIDATION RESULTS")
print("======================================")

print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:")
print(
    classification_report(
        y_true,
        y_pred,
        target_names=["Safe", "Phishing"]
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_true, y_pred))

# Show every validation email
print("\n======================================")
print("INDIVIDUAL PREDICTIONS")
print("======================================")

for i, row in df.iterrows():

    prediction = y_pred[i]

    phishing_probability = probabilities[i][1] * 100
    safe_probability = probabilities[i][0] * 100

    actual = "Phishing" if row["label"] == 1 else "Safe"
    predicted = "Phishing" if prediction == 1 else "Safe"

    status = "CORRECT" if actual == predicted else "WRONG"

    print(f"\nEmail {i + 1}")
    print(f"Category: {row['category']}")
    print(f"Actual: {actual}")
    print(f"Predicted: {predicted}")
    print(f"Phishing probability: {phishing_probability:.2f}%")
    print(f"Safe probability: {safe_probability:.2f}%")
    print(f"Status: {status}")