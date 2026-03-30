from pathlib import Path
import pickle


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "url_model.pkl"
VECTORIZER_PATH = BASE_DIR / "models" / "url_vectorizer.pkl"
URL_MODEL = None
URL_VECTORIZER = None


def _load_pickle(file_path):
    """Load a pickle file and raise a clear error if the trained artifact is missing."""
    if not file_path.exists():
        raise FileNotFoundError(f"Missing trained artifact: {file_path}")

    with open(file_path, "rb") as file_obj:
        return pickle.load(file_obj)


def _ensure_artifacts_loaded():
    """Load the trained artifacts once and reuse them across requests."""
    global URL_MODEL, URL_VECTORIZER

    if URL_MODEL is None:
        URL_MODEL = _load_pickle(MODEL_PATH)
    if URL_VECTORIZER is None:
        URL_VECTORIZER = _load_pickle(VECTORIZER_PATH)


def preload_url_model():
    """Explicitly load the URL model when the Flask app starts."""
    _ensure_artifacts_loaded()


def predict_url(url_text):
    """Predict whether the provided URL is safe or phishing."""
    normalized_url = str(url_text or "").strip()
    if not normalized_url:
        raise ValueError("URL input is empty.")

    _ensure_artifacts_loaded()
    url_features = URL_VECTORIZER.transform([normalized_url])
    predicted_label = int(URL_MODEL.predict(url_features)[0])

    # In phishing_url.csv, ClassLabel 0 = phishing and 1 = safe.
    if predicted_label == 0:
        return "Phishing URL"
    return "Safe URL"


def predict_url_with_probability(url_text):
    """Return both the user-facing label and the phishing probability for the URL."""
    normalized_url = str(url_text or "").strip()
    if not normalized_url:
        raise ValueError("URL input is empty.")

    _ensure_artifacts_loaded()
    url_features = URL_VECTORIZER.transform([normalized_url])
    predicted_label = int(URL_MODEL.predict(url_features)[0])
    class_probabilities = URL_MODEL.predict_proba(url_features)[0]
    probability_by_class = dict(zip(URL_MODEL.classes_, class_probabilities))
    phishing_probability = float(probability_by_class.get(0, 0.0))

    if predicted_label == 0:
        return "Phishing URL", phishing_probability
    return "Safe URL", phishing_probability


# Load the existing URL artifacts once when this module is imported by the Flask app.
preload_url_model()
