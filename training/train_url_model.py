from pathlib import Path
import pickle

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split


BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "dataset"
MODELS_DIR = BASE_DIR / "models"
ROOT_DATASET_PATH = BASE_DIR / "phishing_url.csv"
DATASET_PATH = DATASET_DIR / "phishing_url.csv"
MODEL_PATH = MODELS_DIR / "url_model.pkl"
VECTORIZER_PATH = MODELS_DIR / "url_vectorizer.pkl"


def resolve_dataset_path():
    """Return the preferred dataset path, with a root-level fallback for current workspace compatibility."""
    if DATASET_PATH.exists():
        return DATASET_PATH
    if ROOT_DATASET_PATH.exists():
        return ROOT_DATASET_PATH
    raise FileNotFoundError(
        "Could not find phishing_url.csv in either 'dataset/' or the project root."
    )


def load_and_clean_dataset(csv_path):
    """Load the raw URL dataset and keep only the columns needed for training."""
    dataframe = pd.read_csv(csv_path)

    required_columns = ["URL", "ClassLabel"]
    missing_columns = [column for column in required_columns if column not in dataframe.columns]
    if missing_columns:
        raise ValueError(f"Missing required columns: {missing_columns}")

    # Keep only the URL text and the target label for the phishing URL model.
    dataframe = dataframe[required_columns].copy()

    # Remove incomplete rows and duplicate samples before training.
    dataframe = dataframe.dropna()
    dataframe = dataframe.drop_duplicates()

    # Rename columns to the common training schema requested by the project.
    dataframe = dataframe.rename(columns={"URL": "text", "ClassLabel": "label"})

    dataframe["text"] = dataframe["text"].astype(str).str.strip()
    dataframe["label"] = pd.to_numeric(dataframe["label"], errors="coerce")

    # Drop rows that failed label conversion or ended up with empty URLs.
    dataframe = dataframe.dropna(subset=["label"])
    dataframe = dataframe[dataframe["text"] != ""]
    dataframe["label"] = dataframe["label"].astype(int)

    # Keep the classifier binary even if the CSV stores labels as strings or numbers.
    valid_labels = {0, 1}
    dataframe = dataframe[dataframe["label"].isin(valid_labels)]

    if dataframe.empty:
        raise ValueError("The cleaned URL dataset is empty after preprocessing.")

    return dataframe


def train_url_model(dataframe):
    """Vectorize URLs with TF-IDF and train a Logistic Regression classifier."""
    features = dataframe["text"]
    labels = dataframe["label"]

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    # Character-level TF-IDF works well for URLs because phishing signals often appear in substrings.
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2)
    x_train_tfidf = vectorizer.fit_transform(x_train)
    x_test_tfidf = vectorizer.transform(x_test)

    model = LogisticRegression(max_iter=2000, random_state=42)
    model.fit(x_train_tfidf, y_train)

    predictions = model.predict(x_test_tfidf)
    accuracy = accuracy_score(y_test, predictions)

    print(f"Training rows: {len(x_train)}")
    print(f"Testing rows: {len(x_test)}")
    print(f"Test accuracy: {accuracy:.4f}")
    print("\nClassification report:")
    print(classification_report(y_test, predictions))

    return model, vectorizer


def save_artifacts(model, vectorizer):
    """Persist the trained URL model and TF-IDF vectorizer."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    with open(MODEL_PATH, "wb") as model_file:
        pickle.dump(model, model_file)

    with open(VECTORIZER_PATH, "wb") as vectorizer_file:
        pickle.dump(vectorizer, vectorizer_file)

    print(f"Saved model to: {MODEL_PATH}")
    print(f"Saved vectorizer to: {VECTORIZER_PATH}")


def main():
    """Run the complete phishing URL training pipeline."""
    csv_path = resolve_dataset_path()
    cleaned_dataframe = load_and_clean_dataset(csv_path)
    model, vectorizer = train_url_model(cleaned_dataframe)
    save_artifacts(model, vectorizer)


if __name__ == "__main__":
    main()
