import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

df = pd.read_csv("dataset/phishing_legit_dataset_clean.csv")

X = df["text"].fillna("")
y = df["label"]

print("\n==============================")
print("SENTINELMAIL AI MODEL EVALUATION")
print("==============================")

print("Total emails:", len(df))
print("\nLabel distribution:")
print(y.value_counts())

model = joblib.load("ai/model.pkl")
vectorizer = joblib.load("ai/vectorizer.pkl")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

X_test_vectorized = vectorizer.transform(X_test)

predictions = model.predict(X_test_vectorized)

probabilities = model.predict_proba(X_test_vectorized)[:, 1]

accuracy = accuracy_score(y_test, predictions)
precision = precision_score(y_test, predictions)
recall = recall_score(y_test, predictions)
f1 = f1_score(y_test, predictions)

print("\n==============================")
print("MODEL PERFORMANCE")
print("==============================")

print("Accuracy :", round(accuracy * 100, 2), "%")
print("Precision:", round(precision * 100, 2), "%")
print("Recall   :", round(recall * 100, 2), "%")
print("F1 Score :", round(f1 * 100, 2), "%")

cm = confusion_matrix(y_test, predictions)

print("\n==============================")
print("CONFUSION MATRIX")
print("==============================")

print(cm)

tn, fp, fn, tp = cm.ravel()

print("\nTrue Negatives :", tn)
print("False Positives:", fp)
print("False Negatives:", fn)
print("True Positives :", tp)

false_positive_rate = fp / (fp + tn)

print("\nFalse Positive Rate:",
      round(false_positive_rate * 100, 2), "%")

print("\n==============================")
print("CLASSIFICATION REPORT")
print("==============================")

print(
    classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Phishing"]
    )
)

results = pd.DataFrame({
    "text": X_test.values,
    "actual": y_test.values,
    "prediction": predictions,
    "phishing_probability": probabilities
})

legitimate = results[results["actual"] == 0]
phishing = results[results["actual"] == 1]

print("\n==============================")
print("PROBABILITY ANALYSIS")
print("==============================")

print(
    "\nAverage phishing probability for legitimate emails:",
    round(legitimate["phishing_probability"].mean() * 100, 2),
    "%"
)

print(
    "Average phishing probability for phishing emails:",
    round(phishing["phishing_probability"].mean() * 100, 2),
    "%"
)

false_positives = results[
    (results["actual"] == 0) &
    (results["prediction"] == 1)
]

print("\n==============================")
print("FALSE POSITIVES")
print("==============================")

print(
    "Legitimate emails incorrectly classified as phishing:",
    len(false_positives)
)

if len(false_positives) > 0:

    print("\nExamples:\n")

    for _, row in false_positives.head(10).iterrows():

        print("--------------------------------")
        print(
            "Phishing probability:",
            round(
                row["phishing_probability"] * 100,
                2
            ),
            "%"
        )

        print(row["text"][:500])

else:

    print("No false positives found.")

false_negatives = results[
    (results["actual"] == 1) &
    (results["prediction"] == 0)
]

print("\n==============================")
print("FALSE NEGATIVES")
print("==============================")

print(
    "Phishing emails incorrectly classified as legitimate:",
    len(false_negatives)
)

print("\n==============================")
print("EVALUATION COMPLETE")
print("==============================")