import re

from utils.url_predictor import predict_url_with_probability


# Capture http/https URLs embedded in email bodies.
URL_PATTERN = re.compile(r"(https?://[^\s<>'\"()]+)", re.IGNORECASE)


def _normalize_url(url):
    """Trim common trailing punctuation so extracted email URLs match what users expect."""
    return str(url or "").strip().rstrip(".,;:!?)]}>\"'")


def extract_urls(text):
    """Extract unique URLs from the submitted email text while preserving their original order."""
    matches = URL_PATTERN.findall(str(text or ""))

    unique_urls = []
    seen_urls = set()
    for match in matches:
        normalized_url = _normalize_url(match)
        if normalized_url and normalized_url not in seen_urls:
            seen_urls.add(normalized_url)
            unique_urls.append(normalized_url)

    return unique_urls


def check_urls_with_model(url_list):
    """Check each extracted URL with the existing URL phishing model."""
    url_results = []

    for url in url_list:
        prediction, phishing_probability = predict_url_with_probability(url)
        url_results.append(
            {
                "url": url,
                "prediction": prediction,
                "phishing_probability": round(phishing_probability * 100, 2),
            }
        )

    return url_results
