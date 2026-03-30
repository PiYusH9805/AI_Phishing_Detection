from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "dataset"
ROOT_DATASET_PATH = BASE_DIR / "phishing_url.csv"
DATASET_PATH = DATASET_DIR / "phishing_url.csv"

# Basic URL extraction that works for http/https links embedded in email text.
URL_PATTERN = re.compile(r"(https?://[^\s<>'\"()]+)", re.IGNORECASE)


def _resolve_dataset_path():
    """Return the configured phishing URL dataset path."""
    if DATASET_PATH.exists():
        return DATASET_PATH
    if ROOT_DATASET_PATH.exists():
        return ROOT_DATASET_PATH
    raise FileNotFoundError(
        "Could not find phishing_url.csv in either 'dataset/' or the project root."
    )


def _normalize_url(url):
    """Normalize URLs so email content and dataset entries can be compared consistently."""
    cleaned_url = str(url or "").strip().rstrip(".,;:!?)]}>\"'")
    if not cleaned_url:
        return ""

    parts = urlsplit(cleaned_url)
    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    path = parts.path or ""

    # Keep the root path representation stable for direct set matching.
    if path == "/":
        path = ""

    return urlunsplit((scheme, netloc, path, parts.query, parts.fragment))


def _load_dataset_urls():
    """Load and cache the phishing URL values once when the module is imported."""
    dataframe = pd.read_csv(_resolve_dataset_path())

    if "URL" not in dataframe.columns:
        raise ValueError("phishing_url.csv must contain a 'URL' column.")

    urls = dataframe["URL"].dropna().astype(str).map(_normalize_url)
    return {url for url in urls if url}


PHISHING_URL_SET = _load_dataset_urls()


def extract_urls_from_email(email_text):
    """Extract and normalize URLs found in email text."""
    matches = URL_PATTERN.findall(str(email_text or ""))

    # Preserve order while removing duplicates.
    unique_urls = []
    seen_urls = set()
    for match in matches:
        normalized_url = _normalize_url(match)
        if normalized_url and normalized_url not in seen_urls:
            seen_urls.add(normalized_url)
            unique_urls.append(normalized_url)

    return unique_urls


def check_url_in_dataset(url):
    """Return True when the provided URL appears in the phishing URL dataset."""
    normalized_url = _normalize_url(url)
    return normalized_url in PHISHING_URL_SET
