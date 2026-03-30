from pathlib import Path

import numpy as np
import pandas as pd
import pickle
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from url_features import extract_url_features


def load_dataset(dataset_path):
    data = pd.read_csv(dataset_path)

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
            "dataset.csv must contain one of these columns: 'url', 'text', or 'text_combined'."
        )

    data = data.dropna(subset=[input_column, "label"]).copy()
    data[input_column] = data[input_column].astype(str)
    return data, input_column


def main():
    base_dir = Path(__file__).resolve().parent
    project_root = base_dir.parent
    dataset_path = project_root / "dataset.csv"

    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found at: {dataset_path}")

    data, input_column = load_dataset(dataset_path)
    X_text = data[input_column]
    y = data["label"]

    manual_features = np.array(X_text.apply(extract_url_features).tolist(), dtype=float)

    X_train_text, X_test_text, y_train, y_test, X_train_manual, X_test_manual = train_test_split(
        X_text,
        y,
        manual_features,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    vectorizer = TfidfVectorizer(max_features=10000, ngram_range=(1, 2))
    X_train_tfidf = vectorizer.fit_transform(X_train_text)
    X_test_tfidf = vectorizer.transform(X_test_text)

    scaler = StandardScaler(with_mean=False)
    X_train_manual_scaled = scaler.fit_transform(X_train_manual)
    X_test_manual_scaled = scaler.transform(X_test_manual)

    X_train_combined = hstack([X_train_tfidf, csr_matrix(X_train_manual_scaled)])
    X_test_combined = hstack([X_test_tfidf, csr_matrix(X_test_manual_scaled)])

    model = LogisticRegression(max_iter=2000)
    model.fit(X_train_combined, y_train)

    y_pred = model.predict(X_test_combined)

    print("Train Accuracy:", model.score(X_train_combined, y_train))
    print("Test Accuracy:", model.score(X_test_combined, y_test))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    model_path = base_dir / "url_model.pkl"
    vectorizer_path = base_dir / "url_vectorizer.pkl"
    scaler_path = base_dir / "url_scaler.pkl"

    with open(model_path, "wb") as model_file:
        pickle.dump(model, model_file)
    with open(vectorizer_path, "wb") as vectorizer_file:
        pickle.dump(vectorizer, vectorizer_file)
    with open(scaler_path, "wb") as scaler_file:
        pickle.dump(scaler, scaler_file)

    print(f"\nSaved: {model_path}")
    print(f"Saved: {vectorizer_path}")
    print(f"Saved: {scaler_path}")


if __name__ == "__main__":
    main()
