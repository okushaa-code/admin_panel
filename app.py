"""INaRa үл хөдлөх хөрөнгийн админ самбар (Flask + Supabase REST)."""

import json
import logging
import math
import os
import secrets
import ssl
import threading
import time
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

import bcrypt
import certifi
from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, request, session, url_for

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "")
LOCAL_TZ = ZoneInfo("Asia/Ulaanbaatar")

PROPERTY_SECTIONS = {
    "sales": {
        "table": "properties_for_sale",
        "title": "Худалдах байр",
        "price_label": "Үнэ",
        "price_period": "",
    },
    "rentals": {
        "table": "properties_for_rent",
        "title": "Түрээслүүлэх байр",
        "price_label": "Сарын түрээс",
        "price_period": "/сар",
    },
}
BOOKING_STATUSES = ("pending", "approved", "rejected")
MESSAGE_STATUSES = ("unread", "read", "archived")

# PostgreSQL-ийн bigint ба numeric(10, 2) хязгаар
PRICE_MAX = 9_223_372_036_854_775_807
AREA_MAX = Decimal("99999999.99")

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_BYTES = 72  # bcrypt нь 72 байтаас хойшхыг үл тооцдог

LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 15 * 60

app = Flask(__name__)
_secret_key = os.getenv("APP_SECRET_KEY", "")
if not _secret_key:
    app.logger.warning(
        "APP_SECRET_KEY тохируулаагүй тул түр түлхүүр үүсгэлээ; сервер дахин "
        "асахад бүх session хүчингүй болно."
    )
app.secret_key = _secret_key or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=64 * 1024,
)

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "style-src 'self' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self'; "
    "script-src 'none'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

# Хэрэглэгч олдоогүй үед ч bcrypt шалгалт хийж, хариу өгөх хугацаагаар
# бүртгэлтэй и-мэйлийг тааж олохоос сэргийлнэ.
_DUMMY_HASH = bcrypt.hashpw(secrets.token_bytes(16), bcrypt.gensalt(rounds=12))

_failed_logins: dict[str, list[float]] = {}
_failed_logins_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Supabase REST
# ---------------------------------------------------------------------------


class SupabaseError(Exception):
    def __init__(self, status: int | None = None, code: str | None = None) -> None:
        super().__init__(f"Supabase error (status={status}, code={code})")
        self.status = status
        self.code = code


def supabase_configured() -> bool:
    return bool(SUPABASE_URL and SUPABASE_SECRET_KEY)


def _supabase_request(
    method: str,
    table: str,
    query: dict[str, str] | None = None,
    values: dict[str, Any] | None = None,
    prefer: str | None = None,
) -> tuple[Any, Any]:
    """Supabase REST руу хүсэлт илгээж (бие, толгой)-г буцаана.

    Түлхүүр зөвхөн серверээс Supabase руу явна; лог болон алдаанд орохгүй.
    """
    if not supabase_configured():
        raise SupabaseError(code="config")

    url = f"{SUPABASE_URL}/rest/v1/{table}"
    if query:
        url = f"{url}?{urlencode(query)}"
    headers = {
        "apikey": SUPABASE_SECRET_KEY,
        "Authorization": f"Bearer {SUPABASE_SECRET_KEY}",
        "Accept": "application/json",
    }
    data = None
    if values is not None:
        data = json.dumps(values).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if prefer:
        headers["Prefer"] = prefer

    api_request = Request(url, data=data, method=method, headers=headers)
    try:
        with urlopen(
            api_request,
            timeout=15,
            context=ssl.create_default_context(cafile=certifi.where()),
        ) as response:
            body = response.read()
            response_headers = response.headers
    except HTTPError as error:
        try:
            error_body = json.loads(error.read())
        except (UnicodeDecodeError, ValueError):
            error_body = {}
        code = error_body.get("code") if isinstance(error_body, dict) else None
        raise SupabaseError(error.code, code) from error
    except (URLError, TimeoutError, OSError) as error:
        raise SupabaseError(code="network") from error

    if method == "HEAD" or not body:
        return None, response_headers
    try:
        return json.loads(body), response_headers
    except (UnicodeDecodeError, ValueError) as error:
        raise SupabaseError(code="invalid_json") from error


def _as_rows(data: Any) -> list[dict[str, Any]]:
    if data is None:
        return []
    if not isinstance(data, list):
        raise SupabaseError(code="invalid_shape")
    return data


def supabase_get(table: str, query: dict[str, str]) -> list[dict[str, Any]]:
    data, _ = _supabase_request("GET", table, query)
    return _as_rows(data)


def supabase_count(table: str, query: dict[str, str] | None = None) -> int:
    """Мөрүүдийг татахгүйгээр нийт тоог Content-Range толгойгоос уншина."""
    params = {"select": "id", **(query or {})}
    _, headers = _supabase_request("HEAD", table, params, prefer="count=exact")
    content_range = (headers.get("Content-Range") or "") if headers else ""
    total = content_range.rpartition("/")[2]
    if not total.isdigit():
        raise SupabaseError(code="invalid_count")
    return int(total)


def supabase_patch(
    table: str, query: dict[str, str], values: dict[str, Any]
) -> list[dict[str, Any]]:
    data, _ = _supabase_request(
        "PATCH", table, query, values, prefer="return=representation"
    )
    return _as_rows(data)


def supabase_post(table: str, values: dict[str, Any]) -> list[dict[str, Any]]:
    data, _ = _supabase_request(
        "POST", table, None, values, prefer="return=representation"
    )
    return _as_rows(data)


def supabase_delete(table: str, query: dict[str, str]) -> list[dict[str, Any]]:
    data, _ = _supabase_request("DELETE", table, query, prefer="return=representation")
    return _as_rows(data)


def log_supabase_error(action: str, error: SupabaseError) -> None:
    # Зөвхөн HTTP статус ба PostgreSQL/PostgREST кодыг бичнэ — хувийн мэдээлэл,
    # түлхүүр, хүсэлтийн биеийг логт оруулахгүй.
    app.logger.error("Supabase %s failed (status=%s, code=%s)", action, error.status, error.code)


def db_error_message(error: SupabaseError, fallback: str) -> str:
    if error.code == "config":
        return "Supabase холболтын тохиргоо дутуу байна. SUPABASE_URL болон SUPABASE_SECRET_KEY орчны хувьсагчийг шалгана уу."
    if error.status in (401, 403):
        return "Өгөгдлийн сантай ажиллах эрх хүрэхгүй байна. Supabase-ийн нууц (service-role) түлхүүрээ шалгана уу."
    if error.code in ("PGRST205", "42P01"):
        return "Шаардлагатай хүснэгт өгөгдлийн санд алга байна. Supabase SQL Editor дээр supabase.sql файлыг ажиллуулна уу."
    if error.code in ("42703", "PGRST204"):
        return "Өгөгдлийн санд шаардлагатай багана дутуу байна. Supabase SQL Editor дээр supabase.sql файлыг дахин ажиллуулна уу."
    if error.code == "23505":
        return "Ийм нэр, байршилтай байр аль хэдийн бүртгэлтэй байна. Нэр эсвэл байршлыг өөрчилнө үү."
    if error.code == "23514":
        return "Оруулсан утга өгөгдлийн сангийн хязгаарлалтад нийцэхгүй байна."
    if error.code in ("network", "invalid_json", "invalid_shape", "invalid_count"):
        return "Өгөгдлийн сантай холбогдож чадсангүй. Түр хүлээгээд дахин оролдоно уу."
    return fallback


# ---------------------------------------------------------------------------
# Session, CSRF, хамгаалалт
# ---------------------------------------------------------------------------


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def check_csrf() -> None:
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(submitted, expected):
        abort(400, description="csrf")


@app.before_request
def csrf_protect() -> None:
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        check_csrf()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_email"):
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)

    return wrapped


@app.after_request
def security_headers(response):
    response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "no-store"
    return response


def start_session(email: str) -> None:
    session.clear()
    session.permanent = True
    session["user_email"] = email
    csrf_token()


def _login_key(email: str) -> str:
    return f"{request.remote_addr or '-'}|{email}"


def login_locked(key: str) -> bool:
    now = time.monotonic()
    with _failed_logins_lock:
        attempts = [t for t in _failed_logins.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
        if attempts:
            _failed_logins[key] = attempts
        else:
            _failed_logins.pop(key, None)
        return len(attempts) >= LOGIN_MAX_FAILURES


def record_login_failure(key: str) -> None:
    with _failed_logins_lock:
        _failed_logins.setdefault(key, []).append(time.monotonic())


def clear_login_failures(key: str) -> None:
    with _failed_logins_lock:
        _failed_logins.pop(key, None)


def check_password(password: str, password_hash: str) -> bool:
    """bcrypt шалгалт. Хэш эвдэрсэн бол ValueError шиднэ."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def password_problems(new_password: str) -> list[str]:
    problems = []
    if len(new_password) < PASSWORD_MIN_LENGTH:
        problems.append(f"Шинэ нууц үг {PASSWORD_MIN_LENGTH}-аас доошгүй тэмдэгттэй байна.")
    if len(new_password.encode("utf-8")) > PASSWORD_MAX_BYTES:
        problems.append("Шинэ нууц үг хэт урт байна (72 байтаас ихгүй).")
    if not any(ch.isalpha() for ch in new_password) or not any(ch.isdigit() for ch in new_password):
        problems.append("Шинэ нууц үг дор хаяж нэг үсэг, нэг тоо агуулна.")
    if new_password != new_password.strip():
        problems.append("Шинэ нууц үг хоосон зайгаар эхэлж, төгсөж болохгүй.")
    return problems


# ---------------------------------------------------------------------------
# Нэвтрэх, гарах, профайл
# ---------------------------------------------------------------------------


def render_login(error: str | None, status: int = 200, email: str = ""):
    return (
        render_template("login.html", csrf_token=csrf_token(), error=error, email=email),
        status,
    )


@app.get("/")
def login_page():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))
    return render_login(None)


@app.post("/login")
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not email or not password:
        return render_login("И-мэйл болон нууц үгээ оруулна уу.", 400, email)

    key = _login_key(email)
    if login_locked(key):
        return render_login(
            "Олон удаа буруу оролдсон тул түр хаагдлаа. 15 минутын дараа дахин оролдоно уу.",
            429,
            email,
        )

    try:
        users = supabase_get(
            "users",
            {"select": "email,password_hash", "email": f"eq.{email}", "limit": "1"},
        )
    except SupabaseError as error:
        log_supabase_error("user lookup", error)
        return render_login(
            "Системд түр алдаа гарлаа. Хэсэг хугацааны дараа дахин оролдоно уу.", 503, email
        )

    password_hash = users[0].get("password_hash") if users else None
    if users and not isinstance(password_hash, str):
        app.logger.error("User row has no valid password_hash")
        return render_login("Хэрэглэгчийн бүртгэлд алдаа байна. Админд хандана уу.", 500, email)

    try:
        matches = check_password(password, password_hash or _DUMMY_HASH.decode())
    except ValueError:
        app.logger.error("User row contains an invalid bcrypt hash")
        return render_login("Хэрэглэгчийн бүртгэлд алдаа байна. Админд хандана уу.", 500, email)

    if not users or not matches:
        record_login_failure(key)
        return render_login("И-мэйл эсвэл нууц үг буруу байна.", 401, email)

    clear_login_failures(key)
    start_session(users[0].get("email") or email)
    return redirect(url_for("dashboard"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.post("/profile/password")
@login_required
def change_password():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not current_password or not new_password or not confirm_password:
        return render_panel("profile", error="Бүх талбарыг бөглөнө үү.", status=400)
    problems = password_problems(new_password)
    if new_password != confirm_password:
        problems.append("Шинэ нууц үг давтан оруулсантай таарахгүй байна.")
    if new_password == current_password:
        problems.append("Шинэ нууц үг одоогийнхоос өөр байх ёстой.")
    if problems:
        return render_panel("profile", error=" ".join(problems), status=400)

    email = session["user_email"]
    try:
        users = supabase_get(
            "users", {"select": "password_hash", "email": f"eq.{email}", "limit": "1"}
        )
    except SupabaseError as error:
        log_supabase_error("password lookup", error)
        return render_panel(
            "profile",
            error=db_error_message(error, "Хэрэглэгчийн мэдээллийг уншиж чадсангүй."),
            status=503,
        )

    if not users or not isinstance(users[0].get("password_hash"), str):
        app.logger.error("User row missing or has no password_hash during password change")
        return render_panel("profile", error="Хэрэглэгчийн бүртгэл олдсонгүй.", status=500)
    try:
        matches = check_password(current_password, users[0]["password_hash"])
    except ValueError:
        app.logger.error("User row contains an invalid bcrypt hash")
        return render_panel("profile", error="Хэрэглэгчийн бүртгэлд алдаа байна.", status=500)
    if not matches:
        return render_panel("profile", error="Одоогийн нууц үг буруу байна.", status=400)

    new_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode()
    try:
        updated = supabase_patch("users", {"email": f"eq.{email}"}, {"password_hash": new_hash})
    except SupabaseError as error:
        log_supabase_error("password update", error)
        return render_panel(
            "profile",
            error=db_error_message(error, "Шинэ нууц үгийг хадгалж чадсангүй."),
            status=503,
        )
    if not updated:
        return render_panel(
            "profile", error="Нууц үг солигдсон эсэхийг баталгаажуулж чадсангүй.", status=503
        )

    # Нууц үг солигдсоны дараа session болон CSRF токеныг шинэчилнэ.
    start_session(email)
    session["panel_success"] = "Нууц үг амжилттай солигдлоо."
    return redirect(url_for("profile_page"))


# ---------------------------------------------------------------------------
# Самбарын хуудсууд
# ---------------------------------------------------------------------------


@app.get("/dashboard")
@login_required
def dashboard():
    return render_panel("home")


@app.get("/content")
@login_required
def content_page():
    return render_panel("content")


@app.get("/bookings")
@login_required
def bookings_page():
    return render_panel("bookings")


@app.get("/facebook")
@login_required
def facebook_page():
    return render_panel("facebook")


@app.get("/chat")
@login_required
def chat_page():
    return render_panel("chat")


@app.get("/sales")
@login_required
def sales_page():
    return render_panel("sales")


@app.get("/rentals")
@login_required
def rentals_page():
    return render_panel("rentals")


@app.get("/profile")
@login_required
def profile_page():
    return render_panel("profile")


def _status_filter(allowed: tuple[str, ...]) -> str:
    value = request.args.get("status", "").strip()
    return value if value in allowed else ""


def load_home(ctx: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    stat_queries = [
        ("Ноорог нийтлэл", "content_drafts", None, "content_page"),
        ("Цаг товлолт", "bookings", None, "bookings_page"),
        ("Худалдах байр", "properties_for_sale", None, "sales_page"),
        ("Түрээслүүлэх байр", "properties_for_rent", None, "rentals_page"),
        ("Уншаагүй зурвас", "customer_messages", {"status": "eq.unread"}, "chat_page"),
    ]
    stats = []
    for label, table, query, endpoint in stat_queries:
        try:
            count: int | None = supabase_count(table, query)
        except SupabaseError as error:
            log_supabase_error(f"dashboard count ({table})", error)
            failures.append(label)
            count = None
        stats.append({"label": label, "count": count, "url": url_for(endpoint)})
    ctx["home_stats"] = stats

    chart_items = [s for s in stats[:4] if s["count"] is not None]
    chart_max = max((s["count"] for s in chart_items), default=0)
    ctx["home_chart"] = [
        {**s, "percent": round(s["count"] / chart_max * 100) if chart_max else 0}
        for s in chart_items
    ]

    try:
        rows = supabase_get("bookings", {"select": "status"})
        counts = dict.fromkeys(BOOKING_STATUSES, 0)
        for row in rows:
            if row.get("status") in counts:
                counts[row["status"]] += 1
        ctx["booking_status_counts"] = counts
    except SupabaseError as error:
        log_supabase_error("dashboard booking statuses", error)
        failures.append("Цаг товлолтын төлөв")
        ctx["booking_status_counts"] = None
    return failures


def render_panel(
    section: str,
    error: str | None = None,
    status: int = 200,
    form_state: dict[str, Any] | None = None,
):
    ctx: dict[str, Any] = {
        "section": section,
        "email": session["user_email"],
        "drafts": [],
        "bookings": [],
        "messages": [],
        "properties": [],
        "total_count": 0,
        "home_stats": [],
        "home_chart": [],
        "booking_status_counts": None,
        "property_search": request.args.get("q", "").strip()[:200],
        "property_config": PROPERTY_SECTIONS.get(section),
        "status_filter": "",
        "form_state": form_state or {},
        "success": session.pop("panel_success", None),
        "csrf_token": csrf_token(),
    }

    if section == "home":
        failures = load_home(ctx)
        if failures and not error:
            error = (
                "Дараах мэдээллийг уншиж чадсангүй: " + ", ".join(failures) + ". "
                "Supabase холболт болон supabase.sql-ийн хүснэгтүүдийг шалгана уу."
            )
        ctx["error"] = error
        return render_template("dashboard.html", **ctx), status

    table, query, target, label = "", {}, "", ""
    if section == "content":
        table, target, label = "content_drafts", "drafts", "Ноорог нийтлэлүүдийг"
        query = {"select": "id,title,content,status,created_at", "order": "created_at.desc"}
    elif section == "bookings":
        table, target, label = "bookings", "bookings", "Цаг товлолтуудыг"
        query = {
            "select": "id,customer_name,email,phone,scheduled_at,notes,status",
            "order": "scheduled_at.asc",
        }
        ctx["status_filter"] = _status_filter(BOOKING_STATUSES)
    elif section == "chat":
        table, target, label = "customer_messages", "messages", "Зурвасуудыг"
        query = {
            "select": "id,sender_name,email,phone,subject,content,created_at,status",
            "order": "created_at.desc",
        }
        ctx["status_filter"] = _status_filter(MESSAGE_STATUSES)
    elif section in PROPERTY_SECTIONS:
        table, target, label = PROPERTY_SECTIONS[section]["table"], "properties", "Байрны мэдээллийг"
        query = {
            "select": "id,title,location,price,area_sqm,bedrooms,description,created_at",
            "order": "created_at.desc",
        }

    if ctx["status_filter"]:
        query["status"] = f"eq.{ctx['status_filter']}"

    if table:
        try:
            rows = supabase_get(table, query)
        except SupabaseError as exc:
            log_supabase_error(f"{table} lookup", exc)
            ctx["error"] = error or db_error_message(
                exc, f"{label} уншиж чадсангүй. Холболт болон эрхийн тохиргоог шалгана уу."
            )
            return render_template("dashboard.html", **ctx), 503
        ctx["total_count"] = len(rows)
        if target == "properties" and ctx["property_search"]:
            needle = ctx["property_search"].casefold()
            rows = [
                row
                for row in rows
                if needle
                in " ".join(
                    str(row.get(field) or "") for field in ("title", "location", "description")
                ).casefold()
            ]
        ctx[target] = rows

    ctx["error"] = error
    return render_template("dashboard.html", **ctx), status


# ---------------------------------------------------------------------------
# Цаг товлолт
# ---------------------------------------------------------------------------


@app.post("/bookings/<int:booking_id>/status")
@login_required
def update_booking_status(booking_id: int):
    status = request.form.get("status", "")
    status_labels = {"approved": "баталлаа", "rejected": "татгалзлаа"}
    if status not in status_labels:
        abort(400)

    try:
        # Зөвхөн "pending" төлөвтэйг өөрчилнө — шийдвэрлэсэн хүсэлт дахин өөрчлөгдөхгүй.
        updated = supabase_patch(
            "bookings",
            {"id": f"eq.{booking_id}", "status": "eq.pending"},
            {"status": status},
        )
    except SupabaseError as error:
        log_supabase_error("booking update", error)
        return render_panel(
            "bookings",
            error=db_error_message(error, "Цагийн төлөвийг хадгалж чадсангүй."),
            status=503,
        )

    if updated:
        session["panel_success"] = f"Цаг товлолтыг {status_labels[status]}."
        return redirect(url_for("bookings_page"))
    return render_panel(
        "bookings",
        error="Цаг товлолт олдсонгүй эсвэл өмнө нь шийдвэрлэгдсэн тул өөрчлөх боломжгүй.",
        status=409,
    )


# ---------------------------------------------------------------------------
# Харилцагчийн зурвас
# ---------------------------------------------------------------------------


@app.post("/messages/<int:message_id>/status")
@login_required
def update_message_status(message_id: int):
    status = request.form.get("status", "")
    if status == "read":
        query = {"id": f"eq.{message_id}", "status": "eq.unread"}
        done = "Зурвасыг уншсанд тэмдэглэлээ."
    elif status == "archived":
        query = {"id": f"eq.{message_id}", "status": "neq.archived"}
        done = "Зурвасыг архивлалаа."
    else:
        abort(400)

    try:
        updated = supabase_patch("customer_messages", query, {"status": status})
    except SupabaseError as error:
        log_supabase_error("message update", error)
        return render_panel(
            "chat", error=db_error_message(error, "Зурвасын төлөвийг өөрчилж чадсангүй."), status=503
        )
    if not updated:
        return render_panel(
            "chat",
            error="Зурвас олдсонгүй эсвэл аль хэдийн энэ төлөвт орсон байна.",
            status=409,
        )
    session["panel_success"] = done
    return redirect(url_for("chat_page"))


@app.post("/messages/<int:message_id>/delete")
@login_required
def delete_message(message_id: int):
    if request.form.get("confirm") != "yes":
        return render_panel("chat", error="Устгахын өмнө баталгаажуулна уу.", status=400)
    try:
        deleted = supabase_delete("customer_messages", {"id": f"eq.{message_id}"})
    except SupabaseError as error:
        log_supabase_error("message delete", error)
        return render_panel(
            "chat", error=db_error_message(error, "Зурвасыг устгаж чадсангүй."), status=503
        )
    if not deleted:
        return render_panel("chat", error="Устгах зурвас олдсонгүй.", status=404)
    session["panel_success"] = "Зурвасыг устгалаа."
    return redirect(url_for("chat_page"))


# ---------------------------------------------------------------------------
# Үл хөдлөх хөрөнгө
# ---------------------------------------------------------------------------


class PropertyValidationError(ValueError):
    def __init__(self, problems: list[str]) -> None:
        super().__init__(" ".join(problems))
        self.problems = problems


def _clean_line(value: str) -> str:
    return " ".join(value.split())


def property_values(form: Any) -> dict[str, Any]:
    title = _clean_line(form.get("title", ""))
    location = _clean_line(form.get("location", ""))
    description = form.get("description", "").strip().replace("\r\n", "\n")
    price_text = form.get("price", "").strip().replace(" ", "").replace(",", "")
    area_text = form.get("area_sqm", "").strip().replace(",", ".")
    bedrooms_text = form.get("bedrooms", "").strip()

    problems: list[str] = []
    if not title:
        problems.append("Байрны нэрийг оруулна уу.")
    elif len(title) < 3 or len(title) > 160:
        problems.append("Байрны нэр 3–160 тэмдэгт байна.")
    if not location:
        problems.append("Байршлыг оруулна уу.")
    elif len(location) > 200:
        problems.append("Байршил 200 тэмдэгтээс ихгүй байна.")
    if len(description) > 5000:
        problems.append("Тайлбар 5000 тэмдэгтээс ихгүй байна.")

    price = None
    if not price_text:
        problems.append("Үнийг оруулна уу.")
    elif not price_text.isascii() or not price_text.isdigit() or not 0 < int(price_text) <= PRICE_MAX:
        problems.append("Үнийг 0-ээс их бүхэл тоогоор (₮) оруулна уу.")
    else:
        price = int(price_text)

    area = None
    if not area_text:
        problems.append("Талбайг оруулна уу.")
    else:
        try:
            parsed = Decimal(area_text)
            if not parsed.is_finite():
                raise InvalidOperation
            parsed = parsed.quantize(Decimal("0.01"))
        except InvalidOperation:
            problems.append("Талбайг тоогоор оруулна уу (жишээ: 68.5).")
        else:
            if parsed <= 0 or parsed > AREA_MAX:
                problems.append("Талбай 0.01–99 999 999.99 м² хооронд байна.")
            else:
                area = float(parsed)

    bedrooms = None
    if not bedrooms_text:
        problems.append("Өрөөний тоог оруулна уу.")
    elif not bedrooms_text.isascii() or not bedrooms_text.isdigit() or int(bedrooms_text) > 30:
        problems.append("Өрөөний тоо 0–30 хооронд бүхэл тоо байна.")
    else:
        bedrooms = int(bedrooms_text)

    if problems:
        raise PropertyValidationError(problems)
    return {
        "title": title,
        "location": location,
        "price": price,
        "area_sqm": area,
        "bedrooms": bedrooms,
        "description": description,
    }


def _submitted_property(form: Any) -> dict[str, str]:
    fields = ("title", "location", "price", "area_sqm", "bedrooms", "description")
    return {field: form.get(field, "")[:5000] for field in fields}


@app.post("/properties/<section>/new")
@login_required
def create_property(section: str):
    if section not in PROPERTY_SECTIONS:
        abort(404)
    form_state = {"mode": "create", "values": _submitted_property(request.form)}
    try:
        values = property_values(request.form)
    except PropertyValidationError as error:
        return render_panel(section, error=str(error), status=400, form_state=form_state)

    try:
        created = supabase_post(PROPERTY_SECTIONS[section]["table"], values)
    except SupabaseError as error:
        log_supabase_error("property insert", error)
        status = 409 if error.code == "23505" else 503
        return render_panel(
            section,
            error=db_error_message(error, "Байрыг хадгалж чадсангүй."),
            status=status,
            form_state=form_state,
        )
    if not created:
        return render_panel(
            section, error="Байрыг хадгалсан эсэхийг баталгаажуулж чадсангүй.", status=503
        )
    session["panel_success"] = "Байр амжилттай нэмэгдлээ."
    return redirect(url_for(f"{section}_page"))


@app.post("/properties/<section>/<int:property_id>/edit")
@login_required
def edit_property(section: str, property_id: int):
    if section not in PROPERTY_SECTIONS:
        abort(404)
    form_state = {"mode": "edit", "id": property_id, "values": _submitted_property(request.form)}
    try:
        values = property_values(request.form)
    except PropertyValidationError as error:
        return render_panel(section, error=str(error), status=400, form_state=form_state)

    try:
        updated = supabase_patch(
            PROPERTY_SECTIONS[section]["table"], {"id": f"eq.{property_id}"}, values
        )
    except SupabaseError as error:
        log_supabase_error("property update", error)
        status = 409 if error.code == "23505" else 503
        return render_panel(
            section,
            error=db_error_message(error, "Өөрчлөлтийг хадгалж чадсангүй."),
            status=status,
            form_state=form_state,
        )
    if not updated:
        return render_panel(section, error="Засах байр олдсонгүй.", status=404)
    session["panel_success"] = "Байрны мэдээлэл амжилттай засагдлаа."
    return redirect(url_for(f"{section}_page"))


@app.post("/properties/<section>/<int:property_id>/delete")
@login_required
def delete_property(section: str, property_id: int):
    if section not in PROPERTY_SECTIONS:
        abort(404)
    if request.form.get("confirm") != "yes":
        return render_panel(section, error="Устгахын өмнө баталгаажуулна уу.", status=400)
    try:
        deleted = supabase_delete(PROPERTY_SECTIONS[section]["table"], {"id": f"eq.{property_id}"})
    except SupabaseError as error:
        log_supabase_error("property delete", error)
        return render_panel(
            section, error=db_error_message(error, "Байрыг устгаж чадсангүй."), status=503
        )
    if not deleted:
        return render_panel(section, error="Устгах байр олдсонгүй.", status=404)
    session["panel_success"] = "Байр амжилттай устгагдлаа."
    return redirect(url_for(f"{section}_page"))


# ---------------------------------------------------------------------------
# Алдааны хуудас
# ---------------------------------------------------------------------------

ERROR_MESSAGES = {
    400: ("Хүсэлт хүчингүй байна", "Илгээсэн мэдээлэл буруу эсвэл дутуу байна."),
    404: ("Хуудас олдсонгүй", "Таны хайсан хуудас байхгүй эсвэл зөөгдсөн байна."),
    405: ("Зөвшөөрөгдөөгүй үйлдэл", "Энэ хаягаар ийм төрлийн хүсэлт илгээх боломжгүй."),
    413: ("Хүсэлт хэт том байна", "Илгээсэн мэдээллийн хэмжээ зөвшөөрөгдөх хэмжээнээс их байна."),
    500: ("Системийн алдаа", "Гэнэтийн алдаа гарлаа. Хэсэг хугацааны дараа дахин оролдоно уу."),
}


def render_error(status: int, description: str | None = None):
    title, message = ERROR_MESSAGES.get(status, ERROR_MESSAGES[500])
    if status == 400 and description == "csrf":
        title = "Хуудасны хугацаа дууссан байна"
        message = "Аюулгүй байдлын токен хүчингүй боллоо. Хуудсыг дахин ачаалаад оролдоно уу."
    return (
        render_template(
            "error.html",
            status=status,
            title=title,
            message=message,
            logged_in=bool(session.get("user_email")),
        ),
        status,
    )


@app.errorhandler(400)
def bad_request(error):
    return render_error(400, getattr(error, "description", None))


@app.errorhandler(404)
def not_found(_error):
    return render_error(404)


@app.errorhandler(405)
def method_not_allowed(_error):
    return render_error(405)


@app.errorhandler(413)
def too_large(_error):
    return render_error(413)


@app.errorhandler(500)
def server_error(_error):
    return render_error(500)


# ---------------------------------------------------------------------------
# Template шүүлтүүрүүд
# ---------------------------------------------------------------------------


def _to_local(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=LOCAL_TZ)
    return parsed.astimezone(LOCAL_TZ)


@app.template_filter("pretty_date")
def pretty_date(value: Any) -> str:
    local = _to_local(value)
    return local.strftime("%Y.%m.%d") if local else str(value or "—")


@app.template_filter("mongolian_datetime")
def mongolian_datetime(value: Any) -> str:
    local = _to_local(value)
    return local.strftime("%Y.%m.%d · %H:%M") if local else str(value or "—")


@app.template_filter("iso_datetime")
def iso_datetime(value: Any) -> str:
    local = _to_local(value)
    return local.isoformat() if local else ""


@app.template_filter("status_mn")
def status_mn(value: Any) -> str:
    text = str(value or "")
    return {
        "draft": "Ноорог",
        "published": "Нийтэлсэн",
        "scheduled": "Товлосон",
        "pending": "Хүлээгдэж буй",
        "approved": "Батлагдсан",
        "rejected": "Татгалзсан",
        "unread": "Уншаагүй",
        "read": "Уншсан",
        "archived": "Архивласан",
    }.get(text.lower(), text or "Тодорхойгүй")


@app.template_filter("money")
def money(value: Any) -> str:
    try:
        return f"{int(value):,}".replace(",", " ") + " ₮"
    except (TypeError, ValueError):
        return "—"


@app.template_filter("area")
def area(value: Any) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return "—"
    if not math.isfinite(number):
        return "—"
    return f"{number:,.2f}".rstrip("0").rstrip(".").replace(",", " ")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5001")), debug=False)
