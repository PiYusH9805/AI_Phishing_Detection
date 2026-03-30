from __future__ import annotations

from collections import Counter
import csv
from datetime import datetime
import re
from pathlib import Path
import sys
from typing import Any
from uuid import uuid4

from utils.url_predictor import predict_url_with_probability


BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "dataset.csv"
REPORTS_DIR = BASE_DIR / "reports"
MAX_DATASET_KEYWORDS = 150
MIN_TOKEN_LENGTH = 4
PHISHING_LABELS = {"1", "phishing", "spam", "malicious"}
ALLOWED_FILE_TYPES = {".exe", ".json", ".txt", ".html"}
URL_PATTERN = re.compile(r"(https?://[^\s<>'\"()]+)", re.IGNORECASE)
TOKEN_PATTERN = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{3,}")
PRINTABLE_STRINGS_PATTERN = re.compile(rb"[\x20-\x7E]{4,}")

# Compact stopword set so keyword extraction works without external NLP downloads.
STOPWORDS = {
    "about", "after", "again", "all", "also", "always", "and", "any", "are", "because",
    "been", "before", "being", "between", "both", "but", "can", "click", "com", "could",
    "dear", "does", "down", "each", "email", "even", "from", "further", "have", "here",
    "http", "https", "into", "just", "know", "like", "mail", "more", "most", "must",
    "need", "next", "only", "other", "our", "out", "please", "regards", "reply", "should",
    "some", "such", "than", "that", "the", "their", "them", "then", "there", "these",
    "they", "this", "those", "through", "today", "update", "upon", "very", "want", "were",
    "what", "when", "where", "which", "while", "with", "your", "you", "will", "would",
}


def load_phishing_keywords_from_dataset(
    dataset_path: str | Path = DATASET_PATH,
    max_keywords: int = MAX_DATASET_KEYWORDS,
) -> set[str]:
    """
    Load phishing keywords from the existing email dataset once at startup.
    The logic is intentionally lightweight: tokenize, remove stopwords, and
    keep the most frequent tokens from rows labeled as phishing.
    """
    dataset_file = Path(dataset_path)
    if not dataset_file.exists():
        return set()

    csv.field_size_limit(sys.maxsize)
    token_counts: Counter[str] = Counter()

    with dataset_file.open("r", encoding="utf-8", errors="ignore", newline="") as file_obj:
        reader = csv.DictReader(file_obj)
        for row in reader:
            label = str(row.get("label", "")).strip().lower()
            if label not in PHISHING_LABELS:
                continue

            text = str(row.get("text_combined", "")).lower()
            for token in TOKEN_PATTERN.findall(text):
                normalized = token.lower()
                if normalized in STOPWORDS or len(normalized) < MIN_TOKEN_LENGTH:
                    continue
                if normalized.isdigit():
                    continue
                token_counts[normalized] += 1

    return {token for token, _ in token_counts.most_common(max_keywords)}


# Load the keyword vocabulary once so each file scan reuses the same dataset summary.
PHISHING_KEYWORDS = load_phishing_keywords_from_dataset()


def _decode_text(file_bytes: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return file_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    return file_bytes.decode("utf-8", errors="ignore")


def _extract_readable_strings(file_bytes: bytes) -> str:
    """
    Extract printable strings from binary content without executing the file.
    This is used for EXE uploads and any non-text payload that still contains
    readable phishing bait or embedded URLs.
    """
    chunks = [match.decode("latin-1", errors="ignore") for match in PRINTABLE_STRINGS_PATTERN.findall(file_bytes)]
    return "\n".join(chunks)


def extract_urls_from_file(text: str) -> list[str]:
    """Extract unique HTTP(S) URLs from the decoded file content."""
    matches = URL_PATTERN.findall(str(text or ""))
    unique_urls: list[str] = []
    seen_urls = set()

    for match in matches:
        normalized = str(match).strip().rstrip(".,;:!?)]}>\"'")
        if normalized and normalized not in seen_urls:
            seen_urls.add(normalized)
            unique_urls.append(normalized)

    return unique_urls


def check_keywords(text: str, phishing_keywords: set[str] | None = None) -> list[str]:
    """Find dataset-derived phishing terms inside the file content."""
    keyword_set = phishing_keywords if phishing_keywords is not None else PHISHING_KEYWORDS
    tokens = {token.lower() for token in TOKEN_PATTERN.findall(str(text or "").lower())}
    matches = sorted(token for token in tokens if token in keyword_set)
    return matches


def scan_file_content(file_name: str, file_bytes: bytes) -> dict[str, Any]:
    """
    Scan uploaded content safely:
    1. Read bytes only.
    2. Extract readable strings.
    3. Match dataset-derived phishing keywords.
    4. Extract URLs and send them to the existing URL model.
    5. Combine the findings into a file-risk result.
    """
    safe_name = Path(file_name or "uploaded_file").name
    file_suffix = Path(safe_name).suffix.lower()
    decoded_text = _decode_text(file_bytes)
    readable_text = decoded_text if file_suffix in {".txt", ".json", ".html"} else _extract_readable_strings(file_bytes)

    suspicious_keywords = check_keywords(readable_text)
    detected_urls = extract_urls_from_file(readable_text)
    url_results = []
    phishing_urls = []
    reasons = []
    score = 0.0

    for keyword in suspicious_keywords:
        reasons.append(f"Suspicious keyword detected: {keyword}")

    if suspicious_keywords:
        score += min(len(suspicious_keywords), 6) * 0.07

    for url in detected_urls:
        prediction, phishing_probability = predict_url_with_probability(url)
        url_result = {
            "url": url,
            "prediction": prediction,
            "phishing_probability": round(phishing_probability * 100, 2),
        }
        url_results.append(url_result)
        if prediction == "Phishing URL":
            phishing_urls.append(url_result)

    if phishing_urls:
        reasons.append("Phishing URL detected")
        score += min(len(phishing_urls), 3) * 0.25

    if file_suffix == ".exe":
        reasons.append("Executable file detected")
        score += 0.40
    elif file_suffix == ".html":
        score += 0.10
    elif file_suffix == ".json":
        score += 0.05

    score = max(0.0, min(score, 1.0))
    risk_score = round(score * 100, 2)

    if risk_score >= 50 or file_suffix == ".exe" or phishing_urls:
        scan_result = "Suspicious File"
        storage_prediction = "PHISHING"
    else:
        scan_result = "Safe File"
        storage_prediction = "SAFE"

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "file_name": safe_name,
        "file_type": file_suffix,
        "scan_result": scan_result,
        "storage_prediction": storage_prediction,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "detected_urls": detected_urls,
        "phishing_urls": phishing_urls,
        "suspicious_keywords": suspicious_keywords,
        "url_results": url_results,
        "content_preview": readable_text[:3000],
    }


def _escape_pdf_text(text: str) -> str:
    return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _write_simple_pdf(output_path: Path, lines: list[str]) -> None:
    """
    Minimal PDF fallback used when reportlab/fpdf is unavailable.
    It produces a standards-compliant text-only PDF without extra dependencies.
    """
    y = 800
    commands = ["BT", "/F1 12 Tf", "50 800 Td"]
    first_line = True

    for raw_line in lines:
        line = _escape_pdf_text(raw_line)
        if not first_line:
            commands.append(f"0 -16 Td ({line}) Tj")
        else:
            commands.append(f"({line}) Tj")
            first_line = False
        y -= 16
        if y < 60:
            break

    commands.append("ET")
    stream = "\n".join(commands).encode("latin-1", errors="ignore")

    objects = []
    objects.append(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
    objects.append(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
    objects.append(
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>endobj\n"
    )
    objects.append(b"4 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n")
    objects.append(f"5 0 obj<< /Length {len(stream)} >>stream\n".encode("latin-1") + stream + b"\nendstream\nendobj\n")

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n".encode("latin-1"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    pdf.extend(
        (
            f"trailer<< /Size {len(offsets)} /Root 1 0 R >>\n"
            f"startxref\n{xref_start}\n%%EOF"
        ).encode("latin-1")
    )
    output_path.write_bytes(pdf)


def generate_pdf_report(scan_result: dict[str, Any], output_dir: str | Path = REPORTS_DIR) -> str:
    """
    Generate a downloadable PDF report for the scanned file.
    Uses reportlab when available and falls back to a lightweight PDF writer.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    # Keep filenames unique per request so one user's report cannot overwrite
    # another user's file when scans happen within the same second.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    report_path = output_path / f"scan_report_{timestamp}_{uuid4().hex[:8]}.pdf"

    lines = [
        "Phishing Detection Scan Report",
        "",
        f"Date and Time of Scan: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "File Information",
        f"File Name: {scan_result['file_name']}",
        f"File Type: {scan_result['file_type']}",
        "",
        "Scan Result",
        f"Result: {scan_result['scan_result']}",
        f"Risk Level: {scan_result['risk_level']}",
        f"Risk Score: {scan_result['risk_score']}%",
        "",
        "Suspicious Keywords Found",
    ]

    if scan_result["suspicious_keywords"]:
        lines.extend(f"- {keyword}" for keyword in scan_result["suspicious_keywords"])
    else:
        lines.append("- None")

    lines.extend(["", "URLs Detected"])
    if scan_result["detected_urls"]:
        lines.extend(f"- {url}" for url in scan_result["detected_urls"])
    else:
        lines.append("- None")

    lines.extend(["", "Reasons"])
    if scan_result["reasons"]:
        lines.extend(f"- {reason}" for reason in scan_result["reasons"])
    else:
        lines.append("- No phishing indicators were found.")

    try:
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Phishing Detection Scan Report", ln=True)
        pdf.ln(4)
        pdf.set_font("Arial", size=11)
        for line in lines[2:]:
            pdf.multi_cell(0, 8, line)
        pdf.output(str(report_path))
    except Exception:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas

            canvas_obj = canvas.Canvas(str(report_path), pagesize=A4)
            text_obj = canvas_obj.beginText(40, 800)
            text_obj.setFont("Helvetica-Bold", 16)
            text_obj.textLine(lines[0])
            text_obj.moveCursor(0, 10)
            text_obj.setFont("Helvetica", 11)
            for line in lines[2:]:
                text_obj.textLine(line)
            canvas_obj.drawText(text_obj)
            canvas_obj.save()
        except Exception:
            _write_simple_pdf(report_path, lines)

    return report_path.name
