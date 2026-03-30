from __future__ import annotations

from typing import Any
import re
from urllib.parse import urljoin, urlparse


SUSPICIOUS_KEYWORDS = [
    "verify",
    "account",
    "suspend",
    "login",
    "confirm",
    "update payment",
]

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
}

REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
}


def _normalize_domain(value: str) -> str:
    domain = (value or "").strip().lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _extract_domain(url: str) -> str:
    parsed = urlparse(str(url or "").strip())
    return _normalize_domain(parsed.netloc)


def fetch_webpage_html(url: str) -> dict[str, Any]:
    """
    Fetch webpage HTML with conservative timeouts and browser-like headers.
    Returns a structured response so callers can continue even when fetch fails.
    """
    normalized_url = str(url or "").strip()
    parsed = urlparse(normalized_url)

    if not normalized_url:
        return {"success": False, "html": None, "final_url": None, "error": "URL input is empty."}

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {
            "success": False,
            "html": None,
            "final_url": None,
            "error": "Invalid URL. Please enter a full http:// or https:// address.",
        }

    try:
        import requests
    except ImportError:
        return {
            "success": False,
            "html": None,
            "final_url": normalized_url,
            "error": "Webpage analysis dependencies are not installed. Install requests and beautifulsoup4.",
        }

    try:
        response = requests.get(
            normalized_url,
            headers=REQUEST_HEADERS,
            timeout=(5, 8),
            allow_redirects=True,
        )
        response.raise_for_status()

        content_type = (response.headers.get("Content-Type") or "").lower()
        if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            return {
                "success": False,
                "html": None,
                "final_url": response.url,
                "error": "The target did not return HTML content for analysis.",
            }

        return {
            "success": True,
            "html": response.text,
            "final_url": response.url,
            "error": None,
        }
    except requests.exceptions.SSLError:
        return {
            "success": False,
            "html": None,
            "final_url": normalized_url,
            "error": "The website SSL certificate could not be verified.",
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "html": None,
            "final_url": normalized_url,
            "error": "The website took too long to respond.",
        }
    except requests.exceptions.TooManyRedirects:
        return {
            "success": False,
            "html": None,
            "final_url": normalized_url,
            "error": "The website redirected too many times.",
        }
    except requests.exceptions.HTTPError as exc:
        status_code = getattr(exc.response, "status_code", "unknown")
        return {
            "success": False,
            "html": None,
            "final_url": normalized_url,
            "error": f"The website blocked the request or returned HTTP {status_code}.",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "success": False,
            "html": None,
            "final_url": normalized_url,
            "error": f"Unable to fetch the webpage: {exc}",
        }


def analyze_webpage(html: str, page_url: str | None = None) -> dict[str, Any]:
    """
    Inspect HTML for phishing indicators such as login forms, password fields,
    phishing keywords, and possible brand/domain mismatch.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return {
            "suspicious_elements": [],
            "keyword_hits": [],
            "brand_mentions": [],
            "domain_mismatch": False,
            "domain_mismatch_reasons": [],
            "score": 0.0,
            "reasons": ["BeautifulSoup is not installed, so webpage HTML could not be analyzed."],
            "counts": {
                "login_forms": 0,
                "password_fields": 0,
                "external_form_actions": 0,
            },
        }

    soup = BeautifulSoup(str(html or ""), "html.parser")
    page_text = " ".join(soup.stripped_strings).lower()
    page_domain = _extract_domain(page_url or "")

    suspicious_elements: list[str] = []
    reasons: list[str] = []
    keyword_hits: list[str] = []
    brand_mentions: list[str] = []
    domain_mismatch_reasons: list[str] = []
    login_forms = 0
    password_fields = 0
    external_form_actions = 0

    for form in soup.find_all("form"):
        form_html = str(form).lower()
        form_text = " ".join(form.stripped_strings).lower()
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "get").lower()

        if (
            "login" in form_html
            or "signin" in form_html
            or "sign in" in form_text
            or "password" in form_html
            or method == "post"
        ):
            login_forms += 1

        if action:
            absolute_action = urljoin(page_url or "", action)
            action_domain = _extract_domain(absolute_action)
            if action_domain and page_domain and action_domain != page_domain:
                external_form_actions += 1

    password_fields = len(
        soup.find_all("input", attrs={"type": lambda value: str(value or "").lower() == "password"})
    )

    if login_forms:
        suspicious_elements.append("login_form")
        reasons.append("Suspicious login form detected.")
    if password_fields:
        suspicious_elements.append("password_input")
        reasons.append("Password input field found.")
    if external_form_actions:
        suspicious_elements.append("external_form_action")
        reasons.append("External form action detected.")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in page_text:
            keyword_hits.append(keyword)

    if keyword_hits:
        reasons.append(
            f"Suspicious keywords detected: {', '.join(sorted(keyword_hits))}."
        )

    for brand_name, expected_domain in BRAND_DOMAINS.items():
        brand_regex = r"\b" + re.escape(brand_name) + r"\b"
        if re.search(brand_regex, page_text, flags=re.IGNORECASE):
            brand_mentions.append(brand_name.title())
            if page_domain and expected_domain not in page_domain:
                domain_mismatch_reasons.append(
                    f"{brand_name.title()} is mentioned, but the domain is {page_domain}."
                )

    domain_mismatch = bool(domain_mismatch_reasons)
    if domain_mismatch:
        reasons.append("Brand impersonation possible.")

    score = 0.0
    score += min(login_forms, 1) * 0.18
    score += min(password_fields, 1) * 0.18
    score += min(external_form_actions, 1) * 0.22
    score += min(len(keyword_hits), 4) * 0.07
    score += min(len(domain_mismatch_reasons), 2) * 0.18
    score = max(0.0, min(score, 1.0))

    return {
        "suspicious_elements": suspicious_elements,
        "keyword_hits": keyword_hits,
        "brand_mentions": brand_mentions,
        "domain_mismatch": domain_mismatch,
        "domain_mismatch_reasons": domain_mismatch_reasons,
        "score": score,
        "reasons": reasons,
        "counts": {
            "login_forms": login_forms,
            "password_fields": password_fields,
            "external_form_actions": external_form_actions,
        },
    }


def calculate_risk_score(
    url_prediction_label: str,
    url_model_probability: float,
    webpage_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Combine the existing URL-model result with webpage-content findings.
    The existing URL-model probability is preserved and reused as-is.
    """
    analysis = webpage_analysis or {}
    url_probability = max(0.0, min(float(url_model_probability or 0.0), 1.0))
    webpage_score = max(0.0, min(float(analysis.get("score") or 0.0), 1.0))
    combined_score = (url_probability * 0.65) + (webpage_score * 0.35)
    combined_score = max(0.0, min(combined_score, 1.0))

    reasons = []
    if url_prediction_label == "Phishing URL":
        reasons.append("Existing URL model classified the link as phishing.")

    for reason in analysis.get("reasons", []):
        if reason not in reasons:
            reasons.append(reason)

    final_prediction = "PHISHING" if (url_prediction_label == "Phishing URL" or combined_score >= 0.60) else "SAFE"

    return {
        "prediction": final_prediction,
        "risk_score": round(combined_score * 100, 2),
        "reasons": reasons,
        "url_model_score": round(url_probability * 100, 2),
        "webpage_score": round(webpage_score * 100, 2),
    }
