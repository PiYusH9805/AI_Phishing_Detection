import re

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split


SUSPICIOUS_TLDS = (".xyz", ".top", ".ru", ".tk", ".ml")
IP_ADDRESS_PATTERN = re.compile(r"^(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)")


def extract_url_features(url):
    """
    Extract manual URL features for Hybrid Feature Engineering V2.
    Returns features in this order:
    1) URL length
    2) Digit count
    3) Special character count
    4) Suspicious TLD flag
    5) IP address usage flag
    6) HTTPS usage flag
    """
    url = str(url).strip()
    url_lower = url.lower()

    url_length = len(url)
    digit_count = sum(ch.isdigit() for ch in url)
    special_char_count = sum((not ch.isalnum()) for ch in url)
    has_suspicious_tld = int(any(url_lower.endswith(tld) for tld in SUSPICIOUS_TLDS))
    uses_ip_address = int(bool(IP_ADDRESS_PATTERN.search(url_lower)))
    uses_https = int(url_lower.startswith("https://"))

    return [
        url_length,
        digit_count,
        special_char_count,
        has_suspicious_tld,
        uses_ip_address,
        uses_https,
    ]


def main():
    data = pd.read_csv("dataset.csv")

    if "label" not in data.columns:
        raise ValueError("dataset.csv must contain 'label' column.")

    if "url" in data.columns:
        input_column = "url"
    elif "text" in data.columns:
        input_column = "text"
    elif "text_combined" in data.columns:
        input_column = "text_combined"
    else:
        raise ValueError(
            "dataset.csv must contain one of these input columns: "
            "'url', 'text', or 'text_combined'."
        )

    data = data.dropna(subset=[input_column, "label"]).copy()

    urls = data[input_column].astype(str)
    labels = data["label"]

    # Convert manual features into numpy array
    manual_features = np.array(urls.apply(extract_url_features).tolist(), dtype=float)

    # Split both text and manual features together to keep row alignment
    X_train_url, X_test_url, y_train, y_test, X_train_manual, X_test_manual = train_test_split(
        urls,
        labels,
        manual_features,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    vectorizer = TfidfVectorizer(max_features=10000, ngram_range=(1, 2))

    X_train_tfidf = vectorizer.fit_transform(X_train_url)
    X_test_tfidf = vectorizer.transform(X_test_url)

    # Combine TF-IDF sparse matrix with manual features
    X_train_manual_sparse = csr_matrix(X_train_manual)
    X_test_manual_sparse = csr_matrix(X_test_manual)

    X_train_combined = hstack([X_train_tfidf, X_train_manual_sparse])
    X_test_combined = hstack([X_test_tfidf, X_test_manual_sparse])

    # Train LogisticRegression on combined features
    model = LogisticRegression(max_iter=2000)
    model.fit(X_train_combined, y_train)

    predictions = model.predict(X_test_combined)

    # Existing evaluation logic kept
    print("Train Accuracy:", model.score(X_train_combined, y_train))
    print("Test Accuracy:", model.score(X_test_combined, y_test))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    print("\nClassification Report:")
    print(classification_report(y_test, predictions))



if __name__ == "__main__":
    main()
