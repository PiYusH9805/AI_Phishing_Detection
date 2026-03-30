import re
import sqlite3
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

auth_bp = Blueprint("auth", __name__)

EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,30}$")


def get_auth_db_connection():
    conn = sqlite3.connect(current_app.config["AUTH_DB_PATH"])
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db(app):
    with app.app_context():
        conn = get_auth_db_connection()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()


def sanitize_auth_input(value):
    text = (value or "").strip()
    return re.sub(r"[\x00-\x1f\x7f]", "", text)


def is_safe_redirect_target(target):
    if not target:
        return False
    parsed = urlparse(target)
    return parsed.scheme == "" and parsed.netloc == ""


def get_redirect_target(default_endpoint="home"):
    target = request.args.get("next") or request.form.get("next")
    if is_safe_redirect_target(target):
        return target
    return url_for(default_endpoint)


def get_user_by_id(user_id):
    conn = get_auth_db_connection()
    user = conn.execute(
        "SELECT id, username, email, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()
    return user


def get_user_by_identity(identity):
    conn = get_auth_db_connection()
    user = conn.execute(
        """
        SELECT id, username, email, password_hash, created_at
        FROM users
        WHERE lower(username) = lower(?) OR lower(email) = lower(?)
        LIMIT 1
        """,
        (identity, identity),
    ).fetchone()
    conn.close()
    return user


def create_user(username, email, password):
    conn = get_auth_db_connection()
    conn.execute(
        """
        INSERT INTO users (username, email, password_hash, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            username,
            email.lower(),
            generate_password_hash(password),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            flash("Log in to access the phishing detection dashboard.", "error")
            return redirect(url_for("auth.login", next=request.full_path or request.path))
        return view(*args, **kwargs)

    return wrapped_view


@auth_bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = get_user_by_id(user_id) if user_id else None


@auth_bp.app_context_processor
def inject_auth_context():
    return {"current_user": g.get("user")}


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("home"))

    if request.method == "POST":
        identity = sanitize_auth_input(request.form.get("identity"))
        password = request.form.get("password") or ""

        if not identity or not password:
            flash("Enter your username or email and password.", "error")
        else:
            user = get_user_by_identity(identity)
            if user is None or not check_password_hash(user["password_hash"], password):
                flash("Invalid login credentials.", "error")
            else:
                session.clear()
                # Regenerate the session payload on login and give it a bounded lifetime.
                session.permanent = True
                session["user_id"] = user["id"]
                flash(f"Welcome back, {user['username']}.", "success")
                return redirect(get_redirect_target())

    return render_template("login.html", next_target=get_redirect_target())


@auth_bp.route("/register", methods=["GET", "POST"])
@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if g.user is not None:
        return redirect(url_for("home"))

    if request.method == "POST":
        username = sanitize_auth_input(request.form.get("username"))
        email = sanitize_auth_input(request.form.get("email")).lower()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

        if not username or not email or not password or not confirm_password:
            flash("Complete all required fields.", "error")
        elif not USERNAME_PATTERN.fullmatch(username):
            flash("Username must be 3-30 characters and use only letters, numbers, or underscores.", "error")
        elif not EMAIL_PATTERN.fullmatch(email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
        elif password != confirm_password:
            flash("Passwords do not match.", "error")
        else:
            try:
                create_user(username, email, password)
            except sqlite3.IntegrityError:
                flash("That username or email is already registered.", "error")
            else:
                flash("Account created successfully. Log in to continue.", "success")
                return redirect(url_for("auth.login"))

    return render_template("signup.html", next_target=get_redirect_target())


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
