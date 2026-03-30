import re

SUSPICIOUS_TLDS = (".xyz", ".top", ".ru", ".tk", ".ml")
IP_ADDRESS_PATTERN = re.compile(r"^(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)")


def extract_url_features(url):
    url = str(url).strip()
    url_lower = url.lower()

    url_length = len(url)
    digit_count = sum(char.isdigit() for char in url)
    special_char_count = sum((not char.isalnum()) for char in url)
    has_suspicious_tld = int(any(url_lower.endswith(tld) for tld in SUSPICIOUS_TLDS))
    has_ip_address = int(bool(IP_ADDRESS_PATTERN.search(url_lower)))
    uses_https = int(url_lower.startswith("https://"))

    return [
        url_length,
        digit_count,
        special_char_count,
        has_suspicious_tld,
        has_ip_address,
        uses_https,
    ]
