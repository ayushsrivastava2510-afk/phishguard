"""
train_model.py
---------------
Trains the "Fraudulent Email Detection Engine" — the NLP/ML component
of PhishGuard. Uses TF-IDF (turns email text into numeric features
based on word importance) + Logistic Regression (a fast, explainable
classifier — good for a hackathon since you can explain *why* it
flagged something, which matters for judges).

Run: python3 train_model.py
Output: models/phishing_classifier.joblib
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
from sklearn.pipeline import Pipeline
import joblib

DATA_PATH = "data/emails_dataset.csv"
MODEL_PATH = "models/phishing_classifier.joblib"


def main():
    df = pd.read_csv(DATA_PATH)
    print(f"Loaded {len(df)} emails")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
    )

    # Pipeline bundles the vectorizer + classifier together so we can
    # save/load them as ONE object and reuse easily in the app.
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),   # captures phrases like "act now", "verify identity"
            max_features=3000,
        )),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nTest Accuracy: {acc:.2%}\n")
    print(classification_report(y_test, y_pred))

    joblib.dump(pipeline, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
