import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# ==================================================
# 1. LOAD DATASET
# ==================================================

dataset_path = "dataset/phishing_email_subset.csv"

df = pd.read_csv(dataset_path)

print("Dataset Loaded Successfully!")
print("Dataset shape:", df.shape)


# ==================================================
# 2. CLEAN DATA
# ==================================================

df = df.dropna(subset=["text", "label"])
df = df.drop_duplicates(subset=["text"])

print("After cleaning:", df.shape)

print("\nClass distribution:")
print(df["label"].value_counts())


# ==================================================
# 3. FEATURES AND LABELS
# ==================================================

X = df["text"]
y = df["label"]


# ==================================================
# 4. TRAIN / TEST SPLIT
# ==================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining emails:", len(X_train))
print("Testing emails:", len(X_test))


# ==================================================
# 5. TF-IDF
# ==================================================

vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",

    # Unigrams + bigrams
    ngram_range=(1, 2),

    # Ignore extremely rare words
    min_df=2,

    # Give the model more information
    max_features=10000,

    # Reduce the influence of repeated words
    sublinear_tf=True
)


X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

print("\nTF-IDF conversion completed!")

print(
    "Training feature matrix:",
    X_train_tfidf.shape
)


# ==================================================
# 6. TRAIN LOGISTIC REGRESSION
# ==================================================

model = LogisticRegression(
    max_iter=2000,
    random_state=42
)

model.fit(
    X_train_tfidf,
    y_train
)

print("\nModel training completed!")


# ==================================================
# 7. EVALUATE
# ==================================================

y_pred = model.predict(X_test_tfidf)

accuracy = accuracy_score(
    y_test,
    y_pred
)


print("\n=======================================")
print("MODEL PERFORMANCE")
print("=======================================")

print(
    f"Accuracy: {accuracy * 100:.2f}%"
)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Safe",
            "Phishing"
        ]
    )
)


print("\nConfusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)

joblib.dump(
    model,
    "ai/model.pkl"
)

joblib.dump(
    vectorizer,
    "ai/vectorizer.pkl"
)


print("\n========================================")
print("MODEL SAVED SUCCESSFULLY")
print("========================================")

print("Saved: ai/model.pkl")
print("Saved: ai/vectorizer.pkl")