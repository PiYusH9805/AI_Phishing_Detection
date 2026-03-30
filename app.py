import os
import secrets

from flask import Flask, abort, g, make_response, redirect, render_template, request, send_from_directory, url_for
import csv
import hashlib
import io
import pickle
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
from scipy.sparse import hstack
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from auth import auth_bp, init_auth_db, login_required
from utils.email_url_analyzer import check_urls_with_model, extract_urls
from utils.file_scanner import ALLOWED_FILE_TYPES, REPORTS_DIR, generate_pdf_report, scan_file_content
from utils.url_predictor import predict_url_with_probability, preload_url_model
from utils.webpage_analyzer import analyze_webpage, calculate_risk_score, fetch_webpage_html

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "phishing.db"
AUTH_DB_PATH = BASE_DIR / "database.db"
PHISHING_THRESHOLD = 0.50
MAX_EMAIL_INPUT_LENGTH = 5000
MAX_URL_INPUT_LENGTH = 2048
MAX_FILE_UPLOAD_BYTES = 5 * 1024 * 1024

app.config["AUTH_DB_PATH"] = AUTH_DB_PATH
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_UPLOAD_BYTES
# Use a deployment-provided secret when available. The random fallback avoids
# shipping a shared hard-coded session signing key in local development.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "FLASK_SESSION_COOKIE_SECURE", ""
).strip().lower() in {"1", "true", "yes", "on"}
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
app.register_blueprint(auth_bp)

# Preload both trained models once when the application starts.
preload_url_model()

model = pickle.load(open(BASE_DIR / "phishing_model.pkl", "rb"))
vectorizer = None
scaler = None

vectorizer_path = BASE_DIR / "vectorizer.pkl"
scaler_path = BASE_DIR / "scaler.pkl"

if vectorizer_path.exists() and scaler_path.exists():
    vectorizer = pickle.load(open(vectorizer_path, "rb"))
    scaler = pickle.load(open(scaler_path, "rb"))


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def build_input_hash(scan_type, input_text):
    normalized = re.sub(r"\s+", " ", input_text).strip().lower()
    return hashlib.sha256(f"{scan_type}:{normalized}".encode("utf-8")).hexdigest()


def sanitize_input(raw_text, scan_type):
    text = (raw_text or "").strip()
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    if scan_type == "URL":
        text = re.sub(r"\s+", "", text)
        max_length = MAX_URL_INPUT_LENGTH
    else:
        text = re.sub(r"[ \t]{2,}", " ", text)
        max_length = MAX_EMAIL_INPUT_LENGTH

    return text[:max_length]


def exceeds_input_limit(raw_text, scan_type):
    limit = MAX_URL_INPUT_LENGTH if scan_type == "URL" else MAX_EMAIL_INPUT_LENGTH
    return len((raw_text or "").strip()) > limit


def is_valid_web_url(url_text):
    """Require a full HTTP(S) URL before URL scanning proceeds."""
    parsed = urlparse(str(url_text or "").strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def is_allowed_upload(filename):
    """Restrict uploads to the explicitly supported file types."""
    return Path(str(filename or "")).suffix.lower() in ALLOWED_FILE_TYPES


def get_risk_level(score_percent):
    if score_percent >= 70:
        return "HIGH"
    if score_percent >= 35:
        return "MEDIUM"
    return "LOW"


def init_db():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email_text TEXT NOT NULL,
            scan_type TEXT NOT NULL DEFAULT 'EMAIL',
            prediction TEXT NOT NULL,
            risk_score REAL NOT NULL,
            timestamp TEXT NOT NULL,
            report_name TEXT
        )
        """
    )

    existing_columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(scans)").fetchall()
    }

    if "scan_type" not in existing_columns:
        conn.execute(
            "ALTER TABLE scans ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'EMAIL'"
        )
    if "user_id" not in existing_columns:
        conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")
    if "confidence" not in existing_columns:
        conn.execute("ALTER TABLE scans ADD COLUMN confidence REAL")
    if "risk_level" not in existing_columns:
        conn.execute("ALTER TABLE scans ADD COLUMN risk_level TEXT")
    if "input_hash" not in existing_columns:
        conn.execute("ALTER TABLE scans ADD COLUMN input_hash TEXT")
    if "report_name" not in existing_columns:
        conn.execute("ALTER TABLE scans ADD COLUMN report_name TEXT")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scans_user_hash ON scans(user_id, input_hash)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scans_user_report ON scans(user_id, report_name)"
    )

    conn.execute(
        """
        UPDATE scans
        SET prediction = CASE
            WHEN prediction LIKE 'PHISHING%' THEN 'PHISHING'
            WHEN prediction LIKE 'SAFE%' THEN 'SAFE'
            ELSE prediction
        END
        """
    )
    conn.execute(
        """
        UPDATE scans
        SET confidence = COALESCE(confidence, risk_score)
        """
    )
    conn.execute(
        """
        UPDATE scans
        SET risk_level = COALESCE(
            risk_level,
            CASE
                WHEN COALESCE(confidence, risk_score) >= 70 THEN 'HIGH'
                WHEN COALESCE(confidence, risk_score) >= 35 THEN 'MEDIUM'
                ELSE 'LOW'
            END
        )
        """
    )

    rows_missing_hash = conn.execute(
        """
        SELECT id, email_text, scan_type
        FROM scans
        WHERE input_hash IS NULL OR input_hash = ''
        """
    ).fetchall()
    for row in rows_missing_hash:
        conn.execute(
            "UPDATE scans SET input_hash = ? WHERE id = ?",
            (build_input_hash(row["scan_type"], row["email_text"]), row["id"]),
        )

    conn.commit()
    conn.close()


def get_current_user_id():
    if g.get("user") is None:
        return None
    return g.user["id"]


def save_scan(
    input_text,
    prediction,
    confidence,
    user_id,
    scan_type="EMAIL",
    report_name=None,
):
    # All scan types share the same history table, so ownership is enforced per
    # row through user_id while scan_type keeps EMAIL/URL/FILE behavior intact.
    input_hash = build_input_hash(scan_type, input_text)
    conn = get_db_connection()
    existing = conn.execute(
        """
        SELECT id FROM scans
        WHERE user_id = ? AND input_hash = ?
        LIMIT 1
        """,
        (user_id, input_hash),
    ).fetchone()

    if existing:
        # Keep one history entry per user/input pair, but allow the newest file
        # report path to be attached so the current user can still download it.
        if report_name:
            conn.execute(
                "UPDATE scans SET report_name = ? WHERE id = ?",
                (report_name, existing["id"]),
            )
            conn.commit()
        conn.close()
        return False

    conn.execute(
        """
        INSERT INTO scans (
            user_id, email_text, scan_type, prediction, risk_score,
            confidence, risk_level, timestamp, input_hash, report_name
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            input_text,
            scan_type,
            prediction,
            confidence,
            confidence,
            get_risk_level(confidence),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            input_hash,
            report_name,
        ),
    )
    conn.commit()
    conn.close()
    return True


def get_scan_history(user_id, filters=None, limit=None):
    filters = filters or {}
    conn = get_db_connection()

    conditions = ["user_id = ?"]
    params = [user_id]

    scan_type = filters.get("scan_type", "")
    prediction = filters.get("prediction", "")
    keyword = filters.get("keyword", "").strip()

    if scan_type in {"EMAIL", "URL", "FILE"}:
        conditions.append("scan_type = ?")
        params.append(scan_type)

    if prediction in {"SAFE", "PHISHING"}:
        conditions.append("prediction = ?")
        params.append(prediction)

    if keyword:
        conditions.append("LOWER(email_text) LIKE ?")
        params.append(f"%{keyword.lower()}%")

    query = """
        SELECT
            id,
            email_text AS input_text,
            scan_type,
            prediction,
            COALESCE(confidence, risk_score) AS confidence,
            risk_level,
            timestamp
        FROM scans
    """

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY datetime(timestamp) DESC, id DESC"

    if limit:
        query += " LIMIT ?"
        params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows


def delete_scan(scan_id, user_id):
    conn = get_db_connection()
    result = conn.execute(
        "DELETE FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, user_id),
    )
    conn.commit()
    conn.close()
    return result.rowcount > 0


def delete_all_scans(user_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()


def get_dashboard_stats(user_id):
    conn = get_db_connection()
    totals = conn.execute(
        """
        SELECT
            COUNT(*) AS total_scans,
            SUM(CASE WHEN scan_type = 'URL' THEN 1 ELSE 0 END) AS total_urls,
            SUM(CASE WHEN scan_type = 'EMAIL' THEN 1 ELSE 0 END) AS total_emails,
            SUM(CASE WHEN scan_type = 'FILE' THEN 1 ELSE 0 END) AS total_files,
            SUM(CASE WHEN prediction = 'PHISHING' THEN 1 ELSE 0 END) AS phishing_count,
            SUM(CASE WHEN prediction = 'SAFE' THEN 1 ELSE 0 END) AS safe_count,
            SUM(
                CASE
                    WHEN prediction = 'PHISHING'
                    AND datetime(timestamp) >= datetime('now', '-1 day')
                    THEN 1 ELSE 0
                END
            ) AS recent_phishing_count
        FROM scans
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()
    conn.close()

    total_scans = totals["total_scans"] or 0
    phishing_count = totals["phishing_count"] or 0
    phishing_rate = round((phishing_count / total_scans) * 100, 2) if total_scans else 0.0

    return {
        "total_scans": total_scans,
        "total_urls": totals["total_urls"] or 0,
        "total_emails": totals["total_emails"] or 0,
        "total_files": totals["total_files"] or 0,
        "phishing_count": phishing_count,
        "safe_count": totals["safe_count"] or 0,
        "phishing_rate": phishing_rate,
        "recent_phishing_count": totals["recent_phishing_count"] or 0,
    }


def get_recent_threats(user_id, limit=5):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT
            id,
            scan_type,
            email_text AS input_text,
            COALESCE(confidence, risk_score) AS confidence,
            risk_level,
            timestamp
        FROM scans
        WHERE user_id = ? AND prediction = 'PHISHING'
        ORDER BY datetime(timestamp) DESC, id DESC
        LIMIT ?
        """,
        (user_id, limit),
    ).fetchall()
    conn.close()
    return rows


def user_can_access_report(user_id, report_name):
    conn = get_db_connection()
    scan = conn.execute(
        """
        SELECT id
        FROM scans
        WHERE user_id = ? AND scan_type = 'FILE' AND report_name = ?
        LIMIT 1
        """,
        (user_id, report_name),
    ).fetchone()
    conn.close()
    return scan is not None


def get_warning_banner(stats):
    if stats["recent_phishing_count"] >= 3 or stats["phishing_rate"] >= 55:
        return {
            "level": "high",
            "title": "High phishing activity detected",
            "message": "Recent scans show elevated malicious activity. Validate suspicious links before opening them.",
        }
    if stats["recent_phishing_count"] > 0:
        return {
            "level": "medium",
            "title": "Active phishing signals observed",
            "message": "The latest scans include suspicious inputs. Review the recent threat panel and keep user warnings visible.",
        }
    return {
        "level": "low",
        "title": "Monitoring stable",
        "message": "No recent phishing spike detected. Continue scanning URLs and emails to maintain coverage.",
    }


def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+", " URL ", text)
    text = re.sub(r"\S+@\S+", " EMAIL ", text)
    text = re.sub(r"[^a-zA-Z0-9 ]", " ", text)
    return text


def extra_features(text):
    text = str(text)
    text_lower = text.lower()

    url_count = len(re.findall(r"http\S+|www\S+", text))
    email_count = len(re.findall(r"\S+@\S+", text))
    word_count = len(text.split())

    suspicious_words = [
        "verify", "update", "password", "bank", "urgent",
        "click", "account", "login", "reset", "expire",
        "suspend", "disable", "confirm", "immediately",
        "locked", "unauthorized", "restricted",
    ]

    suspicious_count = sum(text_lower.count(word) for word in suspicious_words)

    trusted_domains = [
        "google.com", "amazon.com", "amazon.in",
        "microsoft.com", "apple.com", "drive.google.com",
    ]

    trusted_flag = any(domain in text_lower for domain in trusted_domains)
    urgency_flag = 1 if word_count < 40 and suspicious_count > 0 else 0

    return np.array(
        [
            url_count,
            email_count,
            word_count,
            suspicious_count,
            int(trusted_flag),
            urgency_flag,
        ]
    ).reshape(1, -1)


def rule_engine(text):
    text_lower = text.lower()
    score = 0.0

    urls = re.findall(r"https?://[^\s]+", text)
    sender_match = re.search(r"from:\s.*@([^\s]+)", text_lower)
    sender_domain = sender_match.group(1) if sender_match else None
    suspicious_tlds = ["xyz", "top", "click", "gq", "loan", "ru"]
    bank_keywords = ["bank", "hdfc", "icici", "sbi", "punjab", "central", "axis", "kotak"]

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if parsed.scheme != "https":
            score += 0.20

        if any(domain.endswith("." + tld) for tld in suspicious_tlds):
            score += 0.45

        for keyword in bank_keywords:
            if keyword in domain and not domain.endswith(".com") and not domain.endswith(".co.in"):
                score += 0.40

    if sender_domain:
        for keyword in bank_keywords:
            if keyword in sender_domain and not sender_domain.endswith(".com") and not sender_domain.endswith(".co.in"):
                score += 0.35

    suspicious_words = [
        "urgent", "verify", "update", "password",
        "login", "reset", "locked", "suspend",
    ]

    keyword_hits = sum(word in text_lower for word in suspicious_words)
    score += keyword_hits * 0.05

    if "urgent" in text_lower and len(text.split()) < 40:
        score += 0.10

    if "click here" in text_lower:
        score += 0.10

    return max(0.0, min(score, 1.0))


def predict_phishing(text):
    if vectorizer is not None and scaler is not None:
        cleaned = clean_text(text)
        text_features = vectorizer.transform([cleaned])
        extra_feat = extra_features(text)
        extra_feat_scaled = scaler.transform(extra_feat)
        final_features = hstack([text_features, extra_feat_scaled])
        ml_prob = float(model.predict_proba(final_features)[0][1])
        rule_score = rule_engine(text)

        if rule_score < 0.10:
            final_score = 0.4 * ml_prob
        else:
            final_score = (0.6 * ml_prob) + (0.4 * rule_score)

        final_score = max(0.0, min(final_score, 1.0))
    else:
        final_score = float(model.predict_proba([text])[0][1])

    prediction = 1 if final_score >= PHISHING_THRESHOLD else 0
    return prediction, final_score


def predict_url_phishing(url):
    """Run the dedicated URL predictor and convert its result into UI/storage fields."""
    return predict_url_with_probability(url)


def build_page_context(history_limit=None):
    filters = {
        "scan_type": (request.args.get("scan_type") or "").upper(),
        "prediction": (request.args.get("prediction") or "").upper(),
        "keyword": (request.args.get("keyword") or "").strip(),
    }
    current_user_id = get_current_user_id()

    if current_user_id is None:
        stats = {
            "total_scans": 0,
            "total_urls": 0,
            "total_emails": 0,
            "total_files": 0,
            "phishing_count": 0,
            "safe_count": 0,
            "phishing_rate": 0.0,
            "recent_phishing_count": 0,
        }
        scans = []
        recent_threats = []
    else:
        stats = get_dashboard_stats(current_user_id)
        scans = get_scan_history(current_user_id, filters=filters, limit=history_limit)
        recent_threats = get_recent_threats(current_user_id, limit=5)
    analytics_bars = [
        {
            "label": "URL Coverage",
            "value": stats["total_urls"],
            "percent": round((stats["total_urls"] / stats["total_scans"]) * 100, 2) if stats["total_scans"] else 0,
            "tone": "accent",
        },
        {
            "label": "Email Coverage",
            "value": stats["total_emails"],
            "percent": round((stats["total_emails"] / stats["total_scans"]) * 100, 2) if stats["total_scans"] else 0,
            "tone": "accent",
        },
        {
            "label": "File Coverage",
            "value": stats["total_files"],
            "percent": round((stats["total_files"] / stats["total_scans"]) * 100, 2) if stats["total_scans"] else 0,
            "tone": "accent",
        },
        {
            "label": "Safe Inputs",
            "value": stats["safe_count"],
            "percent": round((stats["safe_count"] / stats["total_scans"]) * 100, 2) if stats["total_scans"] else 0,
            "tone": "safe",
        },
        {
            "label": "Phishing Hits",
            "value": stats["phishing_count"],
            "percent": round((stats["phishing_count"] / stats["total_scans"]) * 100, 2) if stats["total_scans"] else 0,
            "tone": "danger",
        },
    ]

    return {
        "stats": stats,
        "scans": scans,
        "filters": filters,
        "recent_threats": recent_threats,
        "warning_banner": get_warning_banner(stats),
        "analytics_bars": analytics_bars,
    }


@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    current_user_id = get_current_user_id()
    context = build_page_context(history_limit=6)
    context.update(
        {
            "prediction": None,
            "email_prediction_display": None,
            "risk_score": None,
            "risk_level": None,
            "error": None,
            "notice": None,
            "detected_urls": [],
            "email_url_risk_result": None,
            "url_prediction": None,
            "url_storage_prediction": None,
            "url_risk_score": None,
            "url_risk_level": None,
            "url_error": None,
            "url_notice": None,
            "url_reasons": [],
            "url_model_score": None,
            "webpage_score": None,
            "file_prediction": None,
            "file_storage_prediction": None,
            "file_risk_score": None,
            "file_risk_level": None,
            "file_error": None,
            "file_notice": None,
            "file_name": None,
            "file_type": None,
            "file_reasons": [],
            "file_urls": [],
            "file_keywords": [],
            "file_report_name": None,
            "active_panel": "email-panel",
        }
    )

    if request.method == "POST":
        raw_email_text = request.form.get("email_text")
        email_text = sanitize_input(raw_email_text, "EMAIL")
        context["active_panel"] = "email-panel"

        if not email_text:
            context["error"] = "Please enter email text to scan."
        elif exceeds_input_limit(raw_email_text, "EMAIL"):
            context["error"] = f"Email input exceeds the {MAX_EMAIL_INPUT_LENGTH} character limit."
        else:
            try:
                extracted_urls = extract_urls(email_text)
                context["detected_urls"] = extracted_urls

                url_results = check_urls_with_model(extracted_urls) if extracted_urls else []
                malicious_url_result = next(
                    (
                        result
                        for result in url_results
                        if result["prediction"] == "Phishing URL"
                    ),
                    None,
                )

                # URL model has priority for email scans when malicious links are present.
                if malicious_url_result:
                    confidence = malicious_url_result["phishing_probability"]
                    context["prediction"] = "PHISHING"
                    context["email_prediction_display"] = "Phishing Email (Malicious URL detected)"
                    context["risk_score"] = confidence
                    context["risk_level"] = get_risk_level(confidence)
                    context["email_url_risk_result"] = (
                        f"Malicious URL detected: {malicious_url_result['url']} "
                        f"({malicious_url_result['prediction']}, {confidence}%)"
                    )
                else:
                    pred, score = predict_phishing(email_text)
                    confidence = round(score * 100, 2)
                    context["prediction"] = "PHISHING" if pred == 1 else "SAFE"
                    context["email_prediction_display"] = context["prediction"]
                    context["risk_score"] = confidence
                    context["risk_level"] = get_risk_level(confidence)
                    if url_results:
                        context["email_url_risk_result"] = "All detected URLs were classified as safe by the URL model."
                    else:
                        context["email_url_risk_result"] = "No URLs detected in the email content."

                saved = save_scan(
                    email_text,
                    context["prediction"],
                    confidence,
                    current_user_id,
                    scan_type="EMAIL",
                )
                if not saved:
                    duplicate_notice = "Duplicate input detected. Existing history entry was preserved."
                    if context["notice"]:
                        context["notice"] = f"{context['notice']} {duplicate_notice}"
                    else:
                        context["notice"] = duplicate_notice
                context.update(build_page_context(history_limit=6))
            except Exception as exc:
                context["error"] = f"Scan failed: {exc}"

    return render_template("index.html", **context)


@app.route("/url-scan", methods=["GET", "POST"])
@login_required
def url_scan():
    current_user_id = get_current_user_id()
    context = build_page_context(history_limit=6)
    context.update(
        {
            "prediction": None,
            "email_prediction_display": None,
            "risk_score": None,
            "risk_level": None,
            "error": None,
            "notice": None,
            "detected_urls": [],
            "email_url_risk_result": None,
            "url_prediction": None,
            "url_storage_prediction": None,
            "url_risk_score": None,
            "url_risk_level": None,
            "url_error": None,
            "url_notice": None,
            "url_reasons": [],
            "url_model_score": None,
            "webpage_score": None,
            "active_panel": "url-panel",
        }
    )

    if request.method == "POST":
        raw_input_url = request.form.get("input_url")
        input_url = sanitize_input(raw_input_url, "URL")
        context["active_panel"] = "url-panel"

        if not input_url:
            context["url_error"] = "Please enter a URL to scan."
        elif exceeds_input_limit(raw_input_url, "URL"):
            context["url_error"] = f"URL exceeds the {MAX_URL_INPUT_LENGTH} character limit."
        elif not is_valid_web_url(input_url):
            context["url_error"] = "Please enter a valid URL starting with http:// or https://."
        else:
            try:
                # Keep the existing URL model untouched and run it first.
                url_prediction_label, score = predict_url_phishing(input_url)
                fetch_result = fetch_webpage_html(input_url)
                webpage_analysis = {}

                if fetch_result["success"]:
                    webpage_analysis = analyze_webpage(
                        fetch_result["html"],
                        fetch_result.get("final_url") or input_url,
                    )
                else:
                    context["url_notice"] = fetch_result["error"]

                combined_result = calculate_risk_score(
                    url_prediction_label,
                    score,
                    webpage_analysis,
                )

                context["url_prediction"] = combined_result["prediction"]
                context["url_storage_prediction"] = combined_result["prediction"]
                context["url_risk_score"] = combined_result["risk_score"]
                context["url_risk_level"] = get_risk_level(combined_result["risk_score"])
                context["url_reasons"] = combined_result["reasons"]
                context["url_model_score"] = combined_result["url_model_score"]
                context["webpage_score"] = combined_result["webpage_score"]
                saved = save_scan(
                    input_url,
                    context["url_storage_prediction"],
                    context["url_risk_score"],
                    current_user_id,
                    scan_type="URL",
                )
                if not saved:
                    duplicate_notice = "Duplicate URL detected. Existing history entry was preserved."
                    context["url_notice"] = (
                        f"{context['url_notice']} {duplicate_notice}".strip()
                        if context["url_notice"]
                        else duplicate_notice
                    )
                context.update(build_page_context(history_limit=6))
            except Exception as exc:
                context["url_error"] = f"URL scan failed: {exc}"

    return render_template("index.html", **context)


@app.route("/scan-file", methods=["GET", "POST"])
@login_required
def scan_file():
    current_user_id = get_current_user_id()
    context = build_page_context(history_limit=6)
    context.update(
        {
            "prediction": None,
            "email_prediction_display": None,
            "risk_score": None,
            "risk_level": None,
            "error": None,
            "notice": None,
            "detected_urls": [],
            "email_url_risk_result": None,
            "url_prediction": None,
            "url_storage_prediction": None,
            "url_risk_score": None,
            "url_risk_level": None,
            "url_error": None,
            "url_notice": None,
            "url_reasons": [],
            "url_model_score": None,
            "webpage_score": None,
            "file_prediction": None,
            "file_storage_prediction": None,
            "file_risk_score": None,
            "file_risk_level": None,
            "file_error": None,
            "file_notice": None,
            "file_name": None,
            "file_type": None,
            "file_reasons": [],
            "file_urls": [],
            "file_keywords": [],
            "file_report_name": None,
            "active_panel": "file-panel",
        }
    )

    if request.method == "POST":
        uploaded_file = request.files.get("scan_file")
        context["active_panel"] = "file-panel"

        if not uploaded_file or not uploaded_file.filename:
            context["file_error"] = "Please upload a file to scan."
        elif not is_allowed_upload(uploaded_file.filename):
            allowed_list = ", ".join(sorted(ALLOWED_FILE_TYPES))
            context["file_error"] = f"Unsupported file type. Allowed types: {allowed_list}."
        else:
            try:
                safe_name = secure_filename(uploaded_file.filename)
                file_bytes = uploaded_file.read()

                if not file_bytes:
                    context["file_error"] = "The uploaded file is empty."
                elif len(file_bytes) > MAX_FILE_UPLOAD_BYTES:
                    context["file_error"] = f"File exceeds the {MAX_FILE_UPLOAD_BYTES // (1024 * 1024)} MB upload limit."
                else:
                    # File scanning is isolated from the existing email and URL routes.
                    file_result = scan_file_content(safe_name, file_bytes)
                    report_name = generate_pdf_report(file_result)

                    context["file_prediction"] = file_result["scan_result"]
                    context["file_storage_prediction"] = file_result["storage_prediction"]
                    context["file_risk_score"] = file_result["risk_score"]
                    context["file_risk_level"] = file_result["risk_level"]
                    context["file_name"] = file_result["file_name"]
                    context["file_type"] = file_result["file_type"]
                    context["file_reasons"] = file_result["reasons"]
                    context["file_urls"] = file_result["detected_urls"]
                    context["file_keywords"] = file_result["suspicious_keywords"]
                    context["file_report_name"] = report_name

                    saved = save_scan(
                        (
                            f"{file_result['file_name']} | type={file_result['file_type']} "
                            f"| urls={len(file_result['detected_urls'])} "
                            f"| keywords={len(file_result['suspicious_keywords'])}"
                        ),
                        file_result["storage_prediction"],
                        file_result["risk_score"],
                        current_user_id,
                        scan_type="FILE",
                        report_name=report_name,
                    )
                    if not saved:
                        context["file_notice"] = "Duplicate file summary detected. Existing history entry was preserved."

                    context.update(build_page_context(history_limit=6))
            except Exception as exc:
                context["file_error"] = f"File scan failed: {exc}"

    return render_template("index.html", **context)


@app.errorhandler(RequestEntityTooLarge)
def handle_large_upload(_error):
    context = build_page_context(history_limit=6)
    context.update(
        {
            "prediction": None,
            "email_prediction_display": None,
            "risk_score": None,
            "risk_level": None,
            "error": None,
            "notice": None,
            "detected_urls": [],
            "email_url_risk_result": None,
            "url_prediction": None,
            "url_storage_prediction": None,
            "url_risk_score": None,
            "url_risk_level": None,
            "url_error": None,
            "url_notice": None,
            "url_reasons": [],
            "url_model_score": None,
            "webpage_score": None,
            "file_prediction": None,
            "file_storage_prediction": None,
            "file_risk_score": None,
            "file_risk_level": None,
            "file_error": f"File exceeds the {MAX_FILE_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.",
            "file_notice": None,
            "file_name": None,
            "file_type": None,
            "file_reasons": [],
            "file_urls": [],
            "file_keywords": [],
            "file_report_name": None,
            "active_panel": "file-panel",
        }
    )
    return render_template("index.html", **context), 413


@app.route("/reports/<path:report_name>")
@login_required
def download_scan_report(report_name):
    safe_name = Path(report_name).name
    report_path = REPORTS_DIR / safe_name
    if (
        not report_path.exists()
        or get_current_user_id() is None
        or not user_can_access_report(get_current_user_id(), safe_name)
    ):
        abort(404)
    return send_from_directory(REPORTS_DIR, safe_name, as_attachment=True)


@app.route("/history")
@login_required
def history():
    context = build_page_context(history_limit=None)
    return render_template("history.html", **context)


@app.route("/dashboard")
@login_required
def dashboard():
    context = build_page_context(history_limit=12)
    return render_template("dashboard.html", **context)


@app.route("/history/delete/<int:scan_id>", methods=["POST"])
@login_required
def history_delete(scan_id):
    if not delete_scan(scan_id, get_current_user_id()):
        abort(404)
    return redirect(request.form.get("return_to") or url_for("dashboard"))


@app.route("/history/delete-all", methods=["POST"])
@login_required
def history_delete_all():
    delete_all_scans(get_current_user_id())
    return redirect(request.form.get("return_to") or url_for("dashboard"))


@app.route("/history/export.csv")
@login_required
def export_history_csv():
    filters = {
        "scan_type": (request.args.get("scan_type") or "").upper(),
        "prediction": (request.args.get("prediction") or "").upper(),
        "keyword": (request.args.get("keyword") or "").strip(),
    }
    scans = get_scan_history(get_current_user_id(), filters=filters, limit=None)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Input", "Prediction", "Confidence", "Risk Level", "Timestamp"])
    for scan in scans:
        writer.writerow(
            [
                scan["scan_type"],
                scan["input_text"],
                scan["prediction"],
                f'{scan["confidence"]:.2f}%',
                scan["risk_level"],
                scan["timestamp"],
            ]
        )

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=phishing_history.csv"
    return response


@app.route("/history/report")
@login_required
def download_report():
    stats = get_dashboard_stats(get_current_user_id())
    recent_threats = get_recent_threats(get_current_user_id(), limit=5)

    report_lines = [
        "AI Phishing Detection Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"User: {g.user['username']} ({g.user['email']})",
        "",
        f"Total scans: {stats['total_scans']}",
        f"Total URLs scanned: {stats['total_urls']}",
        f"Total emails scanned: {stats['total_emails']}",
        f"Phishing detected: {stats['phishing_count']}",
        f"Safe inputs: {stats['safe_count']}",
        f"Phishing rate: {stats['phishing_rate']}%",
        "",
        "Recent threat activity:",
    ]

    if recent_threats:
        for threat in recent_threats:
            report_lines.append(
                f"- {threat['timestamp']} | {threat['scan_type']} | {threat['risk_level']} | {threat['confidence']:.2f}%"
            )
    else:
        report_lines.append("- No recent phishing entries.")

    response = make_response("\n".join(report_lines))
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=phishing_report.txt"
    return response


init_db()
init_auth_db(app)


if __name__ == "__main__":
    app.run(debug=True)
