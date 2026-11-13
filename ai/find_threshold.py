import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

# ==========================================
# LOAD DATA
# ==========================================

df = pd.read_csv("dataset/phishing_legit_dataset_clean.csv")

X = df["text"].fillna("")
y = df["label"]

# ==========================================
# LOAD MODEL
# ==========================================

model = joblib.load("ai/model.pkl")
vectorizer = joblib.load("ai/vectorizer.pkl")

# ==========================================
# TEST SET
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

X_test_vectorized = vectorizer.transform(X_test)

# ==========================================
# GET PHISHING PROBABILITIES
# ==========================================

probabilities = model.predict_proba(
    X_test_vectorized
)[:, 1]

print("\n==============================")
print("SENTINELMAIL THRESHOLD ANALYSIS")
print("==============================")

# ==========================================
# TEST DIFFERENT THRESHOLDS
# ==========================================

for threshold in [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85]:

    predictions = (
        probabilities >= threshold
    ).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        predictions
    ).ravel()

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    false_positive_rate = (
        fp / (fp + tn)
    )

    print("\n------------------------------")

    print(
        "Threshold:",
        int(threshold * 100),
        "%"
    )

    print(
        "Accuracy:",
        round(accuracy * 100, 2),
        "%"
    )

    print(
        "Precision:",
        round(precision * 100, 2),
        "%"
    )

    print(
        "Recall:",
        round(recall * 100, 2),
        "%"
    )

    print(
        "F1:",
        round(f1 * 100, 2),
        "%"
    )

    print(
        "False Positive Rate:",
        round(false_positive_rate * 100, 2),
        "%"
    )

    print(
        "False Positives:",
        fp
    )

    print(
        "False Negatives:",
        fn
    )

print("\n==============================")
print("ANALYSIS COMPLETE")
print("==============================")