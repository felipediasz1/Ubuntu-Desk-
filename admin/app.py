"""
Ubuntu Desk — Painel de Administração
Lê o banco SQLite gerado pelo hbbs e exibe os dispositivos registrados.
"""

import sqlite3
import json
import os
import re
import socket
import hashlib
import hmac
import secrets
import time
import csv
import io
import base64
from collections import defaultdict
from datetime import datetime, timedelta, timezone, date
from functools import wraps
from urllib.parse import urlparse, urljoin
from io import BytesIO
import pyotp
import qrcode
from flask import Flask, render_template, redirect, url_for, request, session, g, abort, send_file, jsonify, Response, flash

app = Flask(__name__)

# ── Secret key persistente (sobrevive a restarts) ─────────────────────────────
_SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), ".secret_key")

def _load_secret_key():
    # Prioridade 1: variável de ambiente SECRET_KEY (recomendado em produção)
    env_key = os.environ.get("SECRET_KEY", "").strip()
    if env_key and env_key not in ("ALTERAR_OBRIGATORIO", "mude-esta-chave-antes-de-ir-para-producao", "mude-esta-chave-em-producao"):
        return env_key
    # Prioridade 2: arquivo persistente em disco (gerado automaticamente na 1ª execução)
    if os.path.exists(_SECRET_KEY_FILE):
        return open(_SECRET_KEY_FILE).read().strip()
    key = secrets.token_hex(32)
    with open(_SECRET_KEY_FILE, "w") as f:
        f.write(key)
    return key

app.secret_key = _load_secret_key()
app.permanent_session_lifetime = timedelta(hours=2)
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_HTTPONLY"] = True
# Ativar apenas quando o painel estiver atrás de HTTPS (nginx/proxy)
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("HTTPS_ONLY", "").lower() in ("1", "true", "yes")

_DEFAULT_PASSWORD = "ubuntu-desk-admin"

# ── Configuração ──────────────────────────────────────────────────────────────
DB_PATH       = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "..", "server", "data", "db_v2.sqlite3"))
AUDIT_DB      = os.environ.get("AUDIT_DB", os.path.join(os.path.dirname(__file__), "data", "audit.db"))
API_DB        = os.environ.get("API_DB", os.path.join(os.path.dirname(__file__), "data", "api.db"))
SESSIONS_DB   = os.environ.get("SESSIONS_DB", os.path.join(os.path.dirname(__file__), "data", "sessions.db"))
ADMIN_PASS    = os.environ.get("ADMIN_PASSWORD", "ubuntu-desk-admin")
TOTP_SECRET   = os.environ.get("TOTP_SECRET", "")  # Opcional: ativar 2FA no admin
RECORDING_DIR = os.environ.get("RECORDING_DIR", os.path.join(os.path.dirname(__file__), "data", "recordings"))
PORT           = int(os.environ.get("PORT", 8088))
PEERS_PAGE_SIZE = 50
LOG_FORMAT    = os.environ.get("LOG_FORMAT", "").lower()

# ── IP Allowlist ───────────────────────────────────────────────────────────────
import ipaddress as _ipaddress

_ALLOWED_NETWORKS = []
_raw_ips = os.environ.get("ALLOWED_IPS", "").strip()
if _raw_ips:
    for _entry in _raw_ips.split(","):
        try:
            _ALLOWED_NETWORKS.append(_ipaddress.ip_network(_entry.strip(), strict=False))
        except ValueError:
            pass
_app_start_time = time.time()

# ── Rate limiting (proteção contra brute-force) ───────────────────────────────
_login_attempts: dict = defaultdict(list)
MAX_ATTEMPTS    = 5
LOCKOUT_SECONDS = 900  # 15 minutos

def _is_locked(ip: str) -> bool:
    now = time.time()
    recent = [t for t in _login_attempts[ip] if now - t < LOCKOUT_SECONDS]
    _login_attempts[ip] = recent
    return len(recent) >= MAX_ATTEMPTS

def _record_attempt(ip: str):
    _login_attempts[ip].append(time.time())

def _clear_attempts(ip: str):
    _login_attempts[ip] = []

def _remaining_attempts(ip: str) -> int:
    now = time.time()
    recent = [t for t in _login_attempts[ip] if now - t < LOCKOUT_SECONDS]
    return max(0, MAX_ATTEMPTS - len(recent))

# ── Audit log (SQLite próprio) ────────────────────────────────────────────────
AUDIT_RETENTION_DAYS = int(os.environ.get("AUDIT_RETENTION_DAYS", 90))
_audit_purged = False              # purge uma vez por processo
_audit_db_initialized    = False  # DDL executado uma vez por processo
_api_db_initialized      = False  # DDL executado uma vez por processo
_sessions_db_initialized = False  # DDL executado uma vez por processo

# Mapeamento ação → categoria
_ACTION_CATEGORY = {
    "login_ok":       "security",
    "login_falha":    "security",
    "login_bloqueado":"security",
    "logout":         "security",
    "api_login_ok":   "security",
    "api_login_falha":"security",
    "peer_visualizado":"access",
    "nota_atualizada": "admin",
    "gravacao_download":"access",
    "user_created":        "admin",
    "user_role_changed":   "admin",
    "user_password_reset": "security",
    "user_deactivated":    "security",
    "user_reactivated":    "admin",
    "user_deleted":        "security",
    "ab_shared_written":   "admin",
    "ab_viewed":           "access",
    "peer_blocked":        "security",
    "peer_unblocked":      "admin",
    "peer_tag_add":        "admin",
    "peer_tag_remove":     "admin",
    "history_viewed":      "access",
    "2fa_enabled":         "security",
    "2fa_disabled":        "security",
}

# ── Sort allowlist (SQL injection protection) ─────────────────────────────────
_SORT_ALLOWLIST = {
    "peers":   {"id": "id", "status": "status", "created_at": "created_at",
                "hostname": "json_extract(info,'$.hostname')"},
    "users":   {"username": "username", "role": "role", "created_at": "created_at"},
    "history": {"started_at": "started_at", "duration_secs": "duration_secs", "peer_from": "peer_from"},
    "audit":   {"ts": "ts", "category": "category", "action": "action"},
}

def _safe_sort(table: str, sort_col: str, sort_dir: str):
    col = _SORT_ALLOWLIST.get(table, {}).get(sort_col)
    if not col:
        first_key = list(_SORT_ALLOWLIST.get(table, {"created_at": "created_at"}))[0]
        return _SORT_ALLOWLIST[table][first_key], "DESC"
    direction = "ASC" if sort_dir.upper() == "ASC" else "DESC"
    return col, direction


def _categorize(action: str) -> str:
    if action in _ACTION_CATEGORY:
        return _ACTION_CATEGORY[action]
    for kw in ("login", "logout", "bloqueado", "falha"):
        if kw in action:
            return "security"
    for kw in ("visualizado", "download", "gravacao"):
        if kw in action:
            return "access"
    for kw in ("nota", "atualizada", "config"):
        if kw in action:
            return "admin"
    return "system"

def _get_audit_db():
    global _audit_db_initialized
    os.makedirs(os.path.dirname(AUDIT_DB), exist_ok=True)
    conn = sqlite3.connect(AUDIT_DB)
    if not _audit_db_initialized:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT    NOT NULL,
                action    TEXT    NOT NULL,
                detail    TEXT,
                ip        TEXT,
                category  TEXT    NOT NULL DEFAULT 'system'
            )
        """)
        # migração: adiciona coluna category se não existir
        cols = [r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()]
        if "category" not in cols:
            conn.execute("ALTER TABLE audit_log ADD COLUMN category TEXT NOT NULL DEFAULT 'system'")
        conn.commit()
        _audit_db_initialized = True
    return conn

def _get_sessions_db():
    global _sessions_db_initialized
    os.makedirs(os.path.dirname(SESSIONS_DB), exist_ok=True)
    conn = sqlite3.connect(SESSIONS_DB)
    conn.row_factory = sqlite3.Row
    if not _sessions_db_initialized:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_from     TEXT    NOT NULL,
                peer_to       TEXT    NOT NULL,
                hostname_from TEXT,
                hostname_to   TEXT,
                started_at    DATETIME NOT NULL,
                ended_at      DATETIME,
                duration_secs INTEGER,
                created_by    TEXT
            )
        """)
        conn.commit()
        _sessions_db_initialized = True
    return conn


def _generate_recovery_codes(username: str) -> list:
    """Gera 8 códigos de recuperação e salva os hashes."""
    codes = [secrets.token_urlsafe(6)[:8].upper() for _ in range(8)]
    conn = _get_api_db()
    conn.execute("DELETE FROM totp_recovery_codes WHERE username=?", (username,))
    for code in codes:
        h = hashlib.sha256(code.encode()).hexdigest()
        conn.execute("INSERT INTO totp_recovery_codes (username, code_hash) VALUES (?,?)", (username, h))
    conn.commit()
    conn.close()
    return codes


def _verify_recovery_code(username: str, code: str) -> bool:
    h = hashlib.sha256(code.upper().encode()).hexdigest()
    conn = _get_api_db()
    row = conn.execute(
        "SELECT id FROM totp_recovery_codes WHERE username=? AND code_hash=? AND used=0",
        (username, h)
    ).fetchone()
    if row:
        conn.execute("UPDATE totp_recovery_codes SET used=1 WHERE id=?", (row["id"],))
        conn.commit()
    conn.close()
    return row is not None


def _purge_old_audit():
    global _audit_purged
    if _audit_purged:
        return
    _audit_purged = True
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=AUDIT_RETENTION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
        conn = _get_audit_db()
        conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
        conn.commit()
        conn.close()
    except Exception:
        pass

def _sanitize_log(s: str) -> str:
    """Remove newlines e caracteres de controle para evitar log injection."""
    return re.sub(r"[\x00-\x1f\x7f]", " ", s).strip()[:512]

def audit(action: str, detail: str = "", category: str = ""):
    try:
        ip = request.remote_addr
    except RuntimeError:
        ip = "system"
    ts  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cat = category or _categorize(action)
    action = _sanitize_log(action)
    detail = _sanitize_log(detail)
    try:
        conn = _get_audit_db()
        conn.execute(
            "INSERT INTO audit_log (ts, action, detail, ip, category) VALUES (?,?,?,?,?)",
            (ts, action, detail, ip, cat),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

# ── Peer DB helpers ────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        if not os.path.exists(DB_PATH):
            return None
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        # Migração: adicionar coluna blocked se não existir
        cols = [r[1] for r in g.db.execute("PRAGMA table_info(peer)").fetchall()]
        if "blocked" not in cols:
            g.db.execute("ALTER TABLE peer ADD COLUMN blocked INTEGER DEFAULT 0")
            g.db.commit()
        if "starred" not in cols:
            g.db.execute("ALTER TABLE peer ADD COLUMN starred INTEGER DEFAULT 0")
            g.db.commit()
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def query(sql, args=()):
    db = get_db()
    if db is None:
        return []
    cur = db.execute(sql, args)
    return cur.fetchall()

# ── Auth helpers ───────────────────────────────────────────────────────────────

# Cache do hash da senha admin — derivado uma vez com PBKDF2 (260k iterações).
# Salt fixo derivado da secret key para não precisar de storage extra.
_PASS_HASH_CACHE: bytes | None = None

def _pass_salt() -> bytes:
    """Salt de 16 bytes derivado da secret key do app."""
    raw = app.secret_key.encode("utf-8", errors="replace")
    return hashlib.sha256(raw).digest()[:16]

def _pbkdf2(pwd: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pwd.encode(), _pass_salt(), 260_000)

def _admin_hash() -> bytes:
    global _PASS_HASH_CACHE
    if _PASS_HASH_CACHE is None:
        _PASS_HASH_CACHE = _pbkdf2(ADMIN_PASS)
    return _PASS_HASH_CACHE

def check_password(pwd: str) -> bool:
    """Compara senha usando PBKDF2-SHA256 + timing-safe compare."""
    return hmac.compare_digest(_pbkdf2(pwd), _admin_hash())

# ── Per-user password hashing (random salt per user) ─────────────────────────
def _hash_user_password(pwd: str) -> str:
    """Hash password with random per-user salt. Returns 'salt_hex$hash_hex'."""
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 260_000)
    return salt.hex() + "$" + h.hex()

_SYMBOL_RE = re.compile(r"[!@#$%^&*\-_+=]")

def _validate_password(pwd: str):
    if len(pwd) < 8:
        return "Senha deve ter ao menos 8 caracteres."
    if not any(c.isdigit() for c in pwd):
        return "Senha deve conter ao menos 1 número."
    if not _SYMBOL_RE.search(pwd):
        return "Senha deve conter ao menos 1 símbolo (!@#$%^&*-_+=)."
    return None

def _verify_user_password(pwd: str, stored: str) -> bool:
    """Verify password against stored 'salt_hex$hash_hex'."""
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        actual = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 260_000)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def check_totp(code: str) -> bool:
    if not TOTP_SECRET:
        return True
    try:
        import pyotp
        return pyotp.TOTP(TOTP_SECRET).verify(code, valid_window=1)
    except Exception:
        return False

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        if session.get("role", "admin") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ── Security headers ──────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    # Gera um nonce único por request para permitir inline scripts/styles sem unsafe-inline
    nonce = g.get("csp_nonce", "")
    response.headers["X-Frame-Options"]           = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = (
        "camera=(), microphone=(), geolocation=(), "
        "payment=(), usb=(), bluetooth=()"
    )
    nonce_src = f"'nonce-{nonce}'" if nonce else "'unsafe-inline'"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        f"script-src 'self' {nonce_src}; "
        f"style-src 'self' {nonce_src}; "
        f"img-src 'self' data:; "
        f"font-src 'self'; "
        f"object-src 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'; "
        f"frame-ancestors 'self';"
    )
    if app.config.get("SESSION_COOKIE_SECURE"):
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response


# ── Structured JSON logging ────────────────────────────────────────────────────
@app.after_request
def structured_log(response):
    if LOG_FORMAT == "json":
        import sys as _sys, json as _json
        duration_ms = int((time.time() - g.get("req_start", time.time())) * 1000)
        print(_json.dumps({
            "ts":          time.strftime("%Y-%m-%d %H:%M:%S"),
            "method":      request.method,
            "path":        request.path,
            "status":      response.status_code,
            "duration_ms": duration_ms,
            "ip":          request.remote_addr,
        }), file=_sys.stdout, flush=True)
    return response

# ── CSP nonce + CSRF + context processor ─────────────────────────────────────
@app.before_request
def generate_csp_nonce():
    if request.path == "/health":
        return
    g.csp_nonce = secrets.token_hex(16)
    g.req_start = time.time()

def _get_csrf_token() -> str:
    """Retorna (ou cria) o token CSRF da sessão atual."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(24)
    return session["_csrf"]

@app.before_request
def check_csrf():
    """Valida token CSRF em todos os POSTs de rotas web (não API)."""
    if request.path == "/health":
        return
    if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return
    if request.path.startswith("/api/"):
        return  # APIs usam Bearer/X-Api-Key
    token_form   = request.form.get("csrf_token", "")
    token_header = request.headers.get("X-CSRF-Token", "")
    token        = token_form or token_header
    expected     = session.get("_csrf", "")
    if not expected or not token or not hmac.compare_digest(token, expected):
        abort(403)

@app.context_processor
def inject_globals():
    return {
        "csp_nonce":               g.get("csp_nonce", ""),
        "csrf_token":              _get_csrf_token(),
        "default_password_warning": ADMIN_PASS == _DEFAULT_PASSWORD,
    }

# ── Session timeout ───────────────────────────────────────────────────────────
@app.before_request
def check_session_timeout():
    if request.path == "/health":
        return
    # Rotas da API usam Bearer token — não precisam de session cookie
    if request.path.startswith("/api/"):
        return
    if session.get("logged_in"):
        last = session.get("last_active", 0)
        if time.time() - last > app.permanent_session_lifetime.total_seconds():
            session.clear()
            return redirect(url_for("login"))
        session["last_active"] = time.time()
        session.permanent = True

# ── Enforce 2FA for admin role ────────────────────────────────────────────────
_2FA_EXEMPT_PREFIXES = ("/login", "/logout", "/static", "/health", "/settings/2fa")

@app.before_request
def enforce_admin_2fa():
    if app.config.get("TESTING"):
        return
    if os.environ.get("REQUIRE_ADMIN_2FA", "1") == "0":
        return
    if not session.get("logged_in"):
        return
    if session.get("role", "admin") != "admin":
        return
    if any(request.path.startswith(p) for p in _2FA_EXEMPT_PREFIXES):
        return
    username = session.get("username", "admin")
    conn = _get_api_db()
    row = conn.execute(
        "SELECT totp_enabled FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    if row and not row["totp_enabled"]:
        return redirect(url_for("totp_setup"))

@app.before_request
def check_ip_allowlist():
    if not _ALLOWED_NETWORKS:
        return
    if request.path == "/health":
        return
    try:
        client_ip = _ipaddress.ip_address(request.remote_addr)
        if not any(client_ip in net for net in _ALLOWED_NETWORKS):
            return jsonify({"error": "IP not allowed"}), 403
    except ValueError:
        return jsonify({"error": "IP not allowed"}), 403

# ── Helpers ───────────────────────────────────────────────────────────────────
def _safe_redirect(target: str) -> str:
    """Valida que o redirect aponta para o mesmo host (evita open redirect CWE-601)."""
    if not target:
        return url_for("index")
    ref_url  = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    if test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc:
        return target
    return url_for("index")

def parse_info(info_str):
    try:
        return json.loads(info_str) if info_str else {}
    except Exception:
        return {}

def fmt_dt(dt_str):
    if not dt_str:
        return "—"
    try:
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return dt_str

def _count_new_peers_since(since_iso: str) -> int:
    """Return count of peers registered on or after since_iso (YYYY-MM-DD)."""
    row = query("SELECT COUNT(*) AS cnt FROM peer WHERE created_at >= ?", (since_iso,))
    return row[0]["cnt"] if row else 0

# ── Rotas ─────────────────────────────────────────────────────────────────────
@app.route("/health")
def health():
    results = {}
    for name, path in [("api", API_DB), ("audit", AUDIT_DB), ("sessions", SESSIONS_DB)]:
        try:
            conn = sqlite3.connect(path, timeout=2)
            conn.execute("SELECT 1")
            conn.close()
            results[name] = True
        except Exception:
            results[name] = False
    peer_ok = os.path.exists(DB_PATH)
    all_ok = all(results.values())
    return jsonify({
        "status": "ok" if all_ok else "degraded",
        "db": all_ok,
        "db_detail": {**results, "peer": peer_ok},
        "uptime_seconds": int(time.time() - _app_start_time),
    }), 200 if all_ok else 503


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    ip = request.remote_addr
    totp_required = bool(TOTP_SECRET)

    if request.method == "POST":
        if _is_locked(ip):
            audit("login_bloqueado", "IP bloqueado por excesso de tentativas")
            _dispatch_alert("login_bloqueado", {"ip": ip})
            error = "Muitas tentativas falhas. Aguarde 15 minutos."
        else:
            pwd      = request.form.get("password", "")
            code     = request.form.get("totp", "")
            username = request.form.get("username", "admin").strip() or "admin"
            if check_password(pwd) and check_totp(code):
                _clear_attempts(ip)
                # Verificar 2FA por usuário (novo sistema per-user)
                conn2 = _get_api_db()
                user_row = conn2.execute(
                    "SELECT totp_enabled FROM users WHERE username=?", (username,)
                ).fetchone()
                conn2.close()
                if user_row and user_row["totp_enabled"]:
                    session["pending_totp_username"] = username
                    return redirect(url_for("login_totp"))
                session["logged_in"]   = True
                session["username"]    = username
                session["last_active"] = time.time()
                session.permanent      = True
                audit("login_ok")
                _dispatch_alert("login_ok", {"username": username, "ip": ip})
                return redirect(_safe_redirect(request.args.get("next", "")))
            else:
                _record_attempt(ip)
                rem = _remaining_attempts(ip)
                audit("login_falha", f"tentativas restantes={rem}")
                _dispatch_alert("login_falha", {"ip": ip, "remaining": rem})
                error = f"Credenciais inválidas. {rem} tentativa(s) restante(s)."

    return render_template("login.html", error=error, totp_required=totp_required)

@app.route("/logout")
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    sort_col = request.args.get("sort", "created_at")
    sort_dir = request.args.get("dir", "desc")
    col_expr, direction = _safe_sort("peers", sort_col, sort_dir)
    page        = max(1, request.args.get("page", 1, type=int))
    tag_filter  = request.args.get("tag", "").strip()

    # If tag filter active, get matching peer_ids from api DB first
    tagged_ids = None
    if tag_filter:
        aconn = _get_api_db()
        tagged_rows = aconn.execute(
            "SELECT DISTINCT peer_id FROM peer_tags WHERE tag=?", (tag_filter,)
        ).fetchall()
        aconn.close()
        tagged_ids = [r["peer_id"] for r in tagged_rows]

    peer_count  = query("SELECT COUNT(*) AS cnt FROM peer")
    total_peers = peer_count[0]["cnt"] if peer_count else 0
    pages       = max(1, (total_peers + PEERS_PAGE_SIZE - 1) // PEERS_PAGE_SIZE)
    page        = min(page, pages)
    offset      = (page - 1) * PEERS_PAGE_SIZE
    rows = query(
        f"SELECT id, info, status, created_at, note, blocked, starred FROM peer ORDER BY starred DESC, {col_expr} {direction} LIMIT ? OFFSET ?",
        (PEERS_PAGE_SIZE, offset)
    )
    peers = []
    for r in rows:
        info = parse_info(r["info"])
        peers.append({
            "id":         r["id"],
            "hostname":   info.get("hostname", "—"),
            "os":         info.get("os", "—"),
            "cpu":        info.get("cpu", "—"),
            "memory":     info.get("memory", "—"),
            "username":   info.get("username", "—"),
            "status":     r["status"],
            "created_at": fmt_dt(r["created_at"]),
            "note":       r["note"] or "",
            "blocked":    r["blocked"] or 0,
            "starred":    r["starred"] or 0,
        })

    # Apply tag filter in Python
    if tagged_ids is not None:
        if not tagged_ids:
            peers = []
        else:
            peers = [p for p in peers if p["id"] in set(tagged_ids)]

    # Load tags for peers on current page
    aconn = _get_api_db()
    if peers:
        ids_on_page = [p["id"] for p in peers]
        ph = ",".join("?" * len(ids_on_page))
        tag_rows = aconn.execute(
            f"SELECT peer_id, tag FROM peer_tags WHERE peer_id IN ({ph})", ids_on_page
        ).fetchall()
        tags_by_peer = {}
        for tr in tag_rows:
            tags_by_peer.setdefault(tr["peer_id"], []).append(tr["tag"])
        for p in peers:
            p["tags"] = tags_by_peer.get(p["id"], [])
    all_tags_rows = aconn.execute("SELECT DISTINCT tag FROM peer_tags ORDER BY tag").fetchall()
    aconn.close()
    all_tags = [r["tag"] for r in all_tags_rows]

    db_exists = os.path.exists(DB_PATH)
    total     = total_peers
    active    = sum(1 for p in peers if p["status"] == 1)

    # Novos dispositivos esta semana
    week_ago_peers = (date.today() - timedelta(days=7)).isoformat()
    new_this_week = _count_new_peers_since(week_ago_peers)

    # Métricas de sessões
    today    = date.today().isoformat()
    week_ago = (date.today() - timedelta(days=7)).isoformat()
    sconn = _get_sessions_db()
    sessions_today = sconn.execute(
        "SELECT COUNT(*) FROM sessions WHERE started_at >= ?", (today,)
    ).fetchone()[0]
    sessions_week = sconn.execute(
        "SELECT COUNT(*) FROM sessions WHERE started_at >= ?", (week_ago,)
    ).fetchone()[0]
    daily_rows = sconn.execute("""
        SELECT date(started_at) as day, COUNT(*) as cnt
        FROM sessions
        WHERE started_at >= ?
        GROUP BY day ORDER BY day
    """, (week_ago,)).fetchall()
    sconn.close()

    daily_labels = [r["day"] for r in daily_rows]
    daily_data   = [r["cnt"]  for r in daily_rows]

    return render_template("dashboard.html",
        peers=peers,
        total=total,
        active=active,
        db_exists=db_exists,
        db_path=DB_PATH,
        new_this_week=new_this_week,
        sessions_today=sessions_today,
        sessions_week=sessions_week,
        daily_labels=daily_labels,
        daily_data=daily_data,
        sort_col=sort_col,
        sort_dir=sort_dir,
        page=page,
        pages=pages,
        tag_filter=tag_filter,
        all_tags=all_tags,
    )

@app.route("/search")
@login_required
def global_search():
    q = request.args.get("q", "").strip()
    results = {"peers": [], "users": [], "audit": []}
    if len(q) >= 2:
        like = f"%{q}%"
        db = get_db()
        if db:
            rows = db.execute(
                "SELECT id, info, status FROM peer WHERE id LIKE ? OR note LIKE ? LIMIT 5",
                (like, like)
            ).fetchall()
            results["peers"] = [
                {"id": r["id"], "hostname": (parse_info(r["info"]) or {}).get("hostname", "—")}
                for r in rows
            ]
        conn = _get_api_db()
        urows = conn.execute(
            "SELECT username, role FROM users WHERE username LIKE ? LIMIT 5", (like,)
        ).fetchall()
        results["users"] = [{"username": r[0], "role": r[1]} for r in urows]
        conn.close()
        try:
            aconn = _get_audit_db()
            arows = aconn.execute(
                "SELECT ts, action, detail FROM audit_log WHERE action LIKE ? OR detail LIKE ? ORDER BY id DESC LIMIT 5",
                (like, like)
            ).fetchall()
            results["audit"] = [{"ts": r[0], "action": r[1], "detail": r[2] or ""} for r in arows]
            aconn.close()
        except Exception:
            pass
    return render_template("search.html", q=q, results=results)

@app.route("/peer/<peer_id>")
@login_required
def peer_detail(peer_id):
    rows = query(
        "SELECT id, info, status, created_at, note, blocked FROM peer WHERE id = ?",
        (peer_id,)
    )
    if not rows:
        abort(404)
    r    = rows[0]
    info = parse_info(r["info"])
    peer = {
        "id":         r["id"],
        "hostname":   info.get("hostname", "—"),
        "os":         info.get("os", "—"),
        "cpu":        info.get("cpu", "—"),
        "memory":     info.get("memory", "—"),
        "username":   info.get("username", "—"),
        "status":     r["status"],
        "created_at": fmt_dt(r["created_at"]),
        "note":       r["note"] or "",
        "blocked":    r["blocked"] or 0,
        "info_raw":   json.dumps(info, indent=2, ensure_ascii=False),
    }
    aconn = _get_api_db()
    peer_tag_rows = aconn.execute(
        "SELECT tag FROM peer_tags WHERE peer_id=? ORDER BY tag", (peer_id,)
    ).fetchall()
    all_tags_rows = aconn.execute("SELECT DISTINCT tag FROM peer_tags ORDER BY tag").fetchall()
    aconn.close()
    peer["tags"] = [r["tag"] for r in peer_tag_rows]
    all_tags = [r["tag"] for r in all_tags_rows]
    audit("peer_visualizado", f"id={peer_id} hostname={peer['hostname']}")
    return render_template("peer.html", peer=peer, all_tags=all_tags)

@app.route("/peers/<peer_id>/block", methods=["POST"])
@login_required
def peer_block(peer_id):
    db = get_db()
    if db:
        db.execute("UPDATE peer SET blocked=1 WHERE id=?", (peer_id,))
        db.commit()
        audit("peer_blocked", f"peer_id={peer_id}")
        _dispatch_alert("peer_blocked", {"peer_id": peer_id})
        flash("Device marcado como bloqueado (visão admin apenas).", "success")
    return redirect(url_for("peer_detail", peer_id=peer_id))


@app.route("/peers/<peer_id>/unblock", methods=["POST"])
@login_required
def peer_unblock(peer_id):
    db = get_db()
    if db:
        db.execute("UPDATE peer SET blocked=0 WHERE id=?", (peer_id,))
        db.commit()
        audit("peer_unblocked", f"peer_id={peer_id}")
        _dispatch_alert("peer_unblocked", {"peer_id": peer_id})
        flash("Bloqueio removido.", "success")
    return redirect(url_for("peer_detail", peer_id=peer_id))


@app.route("/peers/<peer_id>/star", methods=["POST"])
@login_required
def peer_star(peer_id):
    db = get_db()
    if db:
        db.execute("UPDATE peer SET starred=1 WHERE id=?", (peer_id,))
        db.commit()
    return redirect(request.referrer or url_for("index"))


@app.route("/peers/<peer_id>/unstar", methods=["POST"])
@login_required
def peer_unstar(peer_id):
    db = get_db()
    if db:
        db.execute("UPDATE peer SET starred=0 WHERE id=?", (peer_id,))
        db.commit()
    return redirect(request.referrer or url_for("index"))


_TAG_RE = re.compile(r'^[\w\s\-\.]+$')

@app.route("/peers/<peer_id>/tags", methods=["POST"])
@login_required
def peer_tags_update(peer_id):
    action = request.form.get("action", "")
    tag    = request.form.get("tag", "").strip()[:50]
    if action not in ("add", "remove") or not tag or not _TAG_RE.match(tag):
        flash("Tag inválida.", "error")
        return redirect(url_for("peer_detail", peer_id=peer_id))
    conn = _get_api_db()
    if action == "add":
        conn.execute(
            "INSERT OR IGNORE INTO peer_tags (peer_id, tag) VALUES (?,?)", (peer_id, tag)
        )
    else:
        conn.execute(
            "DELETE FROM peer_tags WHERE peer_id=? AND tag=?", (peer_id, tag)
        )
    conn.commit()
    conn.close()
    audit(f"peer_tag_{action}", f"peer={peer_id} tag={tag}")
    return redirect(url_for("peer_detail", peer_id=peer_id))


@app.route("/peers/bulk", methods=["POST"])
@login_required
def peers_bulk():
    action   = request.form.get("action", "")
    peer_ids = [p.strip() for p in request.form.getlist("peer_ids") if p.strip()]

    if not peer_ids or action not in ("block", "unblock", "export"):
        flash("Selecione ao menos um dispositivo e uma ação válida.", "error")
        return redirect(url_for("index"))

    if action == "export":
        placeholders = ",".join("?" * len(peer_ids))
        rows = query(
            f"SELECT id, info, status, created_at FROM peer WHERE id IN ({placeholders})",
            peer_ids,
        )
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ID", "Hostname", "Sistema", "Usuário", "Status", "Registrado em"])
        for r in rows:
            info = parse_info(r["info"])
            writer.writerow([
                r["id"],
                info.get("hostname", ""),
                info.get("os", ""),
                info.get("username", ""),
                "Online" if r["status"] == 1 else "Offline",
                r["created_at"],
            ])
        output = buf.getvalue()
        fname  = f"devices_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
        return Response(
            output, mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={fname}"},
        )

    db = get_db()
    if db is None:
        flash("Banco de dados não disponível.", "error")
        return redirect(url_for("index"))

    val          = 1 if action == "block" else 0
    placeholders = ",".join("?" * len(peer_ids))
    db.execute(
        f"UPDATE peer SET blocked=? WHERE id IN ({placeholders})",
        [val] + peer_ids,
    )
    db.commit()
    audit(
        f"peer_bulk_{action}",
        f"count={len(peer_ids)} ids={','.join(peer_ids[:10])}",
    )
    label = "bloqueados" if action == "block" else "desbloqueados"
    flash(f"{len(peer_ids)} dispositivo(s) {label}.", "success")
    return redirect(url_for("index"))


# ── Configurações / 2FA ───────────────────────────────────────────────────────

@app.route("/settings")
@login_required
def settings():
    username = session.get("username", "admin")
    conn = _get_api_db()
    row = conn.execute("SELECT totp_enabled FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    totp_enabled = row["totp_enabled"] if row else 0
    return render_template("settings.html", totp_enabled=totp_enabled)


@app.route("/settings/2fa/setup")
@login_required
def totp_setup():
    secret = pyotp.random_base32()
    session["pending_totp_secret"] = secret
    username = session.get("username", "admin")
    totp = pyotp.TOTP(secret)
    uri  = totp.provisioning_uri(name=username, issuer_name="Ubuntu Desk Admin")
    img  = qrcode.make(uri)
    buf  = BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template("settings_2fa_setup.html", qr_b64=qr_b64, secret=secret)


@app.route("/settings/2fa/enable", methods=["POST"])
@login_required
def totp_enable():
    secret = session.pop("pending_totp_secret", None)
    code   = request.form.get("code", "").strip()
    if not secret or not pyotp.TOTP(secret).verify(code, valid_window=1):
        flash("Código inválido. Tente novamente.", "error")
        return redirect(url_for("totp_setup"))
    username = session.get("username", "admin")
    conn = _get_api_db()
    conn.execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE username=?", (secret, username))
    conn.commit()
    conn.close()
    recovery_codes = _generate_recovery_codes(username)
    audit("2fa_enabled", f"username={username}")
    flash("2FA ativado com sucesso.", "success")
    return render_template("settings_2fa_recovery.html", codes=recovery_codes)


@app.route("/settings/2fa/disable", methods=["POST"])
@login_required
def totp_disable():
    username = session.get("username", "admin")
    conn = _get_api_db()
    conn.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE username=?", (username,))
    conn.commit()
    conn.close()
    audit("2fa_disabled", f"username={username}")
    flash("2FA desativado.", "success")
    return redirect(url_for("settings"))


@app.route("/settings/alerts", methods=["GET", "POST"])
@login_required
@admin_required
def settings_alerts():
    conn = _get_api_db()
    if request.method == "POST":
        import json as _json
        _known_events = ["login_ok", "login_falha", "login_bloqueado", "peer_blocked", "peer_unblocked", "user_created", "user_deleted"]
        selected = [e for e in _known_events if request.form.get(f"event_{e}")]
        data = {
            "webhook_url":    request.form.get("webhook_url", "").strip(),
            "webhook_secret": request.form.get("webhook_secret", "").strip(),
            "smtp_host":      request.form.get("smtp_host", "").strip(),
            "smtp_port":      int(request.form.get("smtp_port", 587) or 587),
            "smtp_user":      request.form.get("smtp_user", "").strip(),
            "smtp_pass":      request.form.get("smtp_pass", "").strip(),
            "smtp_from":      request.form.get("smtp_from", "").strip(),
            "smtp_to":        request.form.get("smtp_to", "").strip(),
            "alert_events":   _json.dumps(selected),
        }
        conn.execute("""
            UPDATE alert_config SET
                webhook_url=:webhook_url, webhook_secret=:webhook_secret,
                smtp_host=:smtp_host, smtp_port=:smtp_port,
                smtp_user=:smtp_user, smtp_pass=:smtp_pass,
                smtp_from=:smtp_from, smtp_to=:smtp_to,
                alert_events=:alert_events
            WHERE id=1
        """, data)
        conn.commit()
        conn.close()
        flash("Configurações de alertas salvas.", "success")
        return redirect(url_for("settings_alerts"))
    import json as _json
    cfg = conn.execute("SELECT * FROM alert_config WHERE id=1").fetchone()
    conn.close()
    active_events = _json.loads(cfg["alert_events"] or "[]") if cfg else []
    return render_template("settings_alerts.html", cfg=cfg, active_events=active_events)


@app.route("/settings/alerts/test", methods=["POST"])
@login_required
@admin_required
def settings_alerts_test():
    detail = {"message": "Teste de alerta Ubuntu Desk", "origin": "manual"}
    results = _send_alert_sync("test", detail, bypass_filter=True)
    _log_alert_results("test", detail, results)
    if not results:
        flash("Nenhum canal configurado (webhook ou SMTP).", "error")
    else:
        ok   = [c for c, s, _ in results if s]
        fail = [(c, e) for c, s, e in results if not s]
        if ok:
            flash(f"Alerta enviado com sucesso via: {', '.join(ok)}.", "success")
        for c, e in fail:
            flash(f"Falha no canal {c}: {e}", "error")
    return redirect(url_for("settings_alerts"))


@app.route("/settings/alerts/log")
@login_required
@admin_required
def settings_alerts_log():
    conn = _get_api_db()
    logs = conn.execute(
        "SELECT * FROM alert_log ORDER BY id DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return render_template("settings_alerts_log.html", logs=logs)


@app.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    if "pending_totp_username" not in session:
        return redirect(url_for("login"))
    username = session["pending_totp_username"]
    ip = request.remote_addr
    error = None
    if request.method == "POST":
        if _is_locked(ip):
            audit("login_bloqueado", f"username={username} IP bloqueado (2FA)")
            _dispatch_alert("login_bloqueado", {"username": username, "ip": ip})
            session.clear()
            return redirect(url_for("login"))
        code = request.form.get("code", "").strip()
        conn = _get_api_db()
        row  = conn.execute("SELECT totp_secret FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if row and pyotp.TOTP(row["totp_secret"]).verify(code, valid_window=1):
            _clear_attempts(ip)
            session.pop("pending_totp_username")
            session["logged_in"]   = True
            session["username"]    = username
            session["last_active"] = time.time()
            session.permanent      = True
            audit("login_ok", f"username={username} (2FA)")
            _dispatch_alert("login_ok", {"username": username, "ip": ip, "method": "totp"})
            return redirect(url_for("index"))
        if _verify_recovery_code(username, code):
            _clear_attempts(ip)
            session.pop("pending_totp_username")
            session["logged_in"]   = True
            session["username"]    = username
            session["last_active"] = time.time()
            session.permanent      = True
            audit("login_ok", f"username={username} (recovery code)")
            _dispatch_alert("login_ok", {"username": username, "ip": ip, "method": "recovery_code"})
            return redirect(url_for("index"))
        _record_attempt(ip)
        rem = _remaining_attempts(ip)
        error = f"Código inválido. {rem} tentativa(s) restante(s)."
        audit("login_falha", f"username={username} (2FA) tentativas_restantes={rem}")
        _dispatch_alert("login_falha", {"username": username, "ip": ip, "remaining": rem, "method": "totp"})
    return render_template("login_totp.html", error=error)


@app.route("/peer/<peer_id>/note", methods=["POST"])
@login_required
def update_note(peer_id):
    note = request.form.get("note", "")[:300]
    db   = get_db()
    if db:
        db.execute("UPDATE peer SET note=? WHERE id=?", (note, peer_id))
        db.commit()
    audit("nota_atualizada", f"id={peer_id}")
    flash("Nota salva.", "success")
    return redirect(url_for("peer_detail", peer_id=peer_id))

# ── Gravações ─────────────────────────────────────────────────────────────────
# Padrão de nome: incoming_PEERID_YYYYMMDDHHmmSSms_display0_vp9.webm
_REC_RE = re.compile(
    r"^(incoming|outgoing)_(.+?)_(\d{17,})_(camera|display)\d+_\w+\.(webm|mp4)$"
)

def _parse_recording(fname: str) -> dict | None:
    m = _REC_RE.match(fname)
    if not m:
        return None
    direction, peer_id, ts_raw, _, ext = m.groups()
    try:
        dt = datetime.strptime(ts_raw[:14], "%Y%m%d%H%M%S")
        ts_fmt = dt.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        ts_fmt = ts_raw
    return {
        "filename": fname,
        "direction": direction,
        "peer_id":   peer_id,
        "ts":        ts_fmt,
        "ts_raw":    ts_raw,
        "ext":       ext,
    }

def _list_recordings() -> list:
    if not os.path.isdir(RECORDING_DIR):
        return []
    recs = []
    for fname in sorted(os.listdir(RECORDING_DIR), reverse=True):
        r = _parse_recording(fname)
        if r is None:
            continue
        fpath = os.path.join(RECORDING_DIR, fname)
        r["size"] = os.path.getsize(fpath)
        r["size_fmt"] = f"{r['size'] / 1024 / 1024:.1f} MB" if r["size"] >= 1024*1024 else f"{r['size'] // 1024} KB"
        recs.append(r)
    return recs

@app.route("/recordings")
@login_required
def recordings():
    all_recs    = _list_recordings()
    peer_filter = request.args.get("peer", "").strip()
    dir_filter  = request.args.get("direction", "").strip()
    recs = all_recs
    if peer_filter:
        recs = [r for r in recs if peer_filter.lower() in r["peer_id"].lower()]
    if dir_filter in ("incoming", "outgoing"):
        recs = [r for r in recs if r["direction"] == dir_filter]
    peers = sorted({r["peer_id"] for r in all_recs})
    return render_template("recordings.html",
        recordings=recs,
        peers=peers,
        peer_filter=peer_filter,
        dir_filter=dir_filter,
        recording_dir=RECORDING_DIR,
    )

@app.route("/recordings/download/<path:filename>")
@login_required
def download_recording(filename):
    safe = os.path.basename(filename)
    fpath = os.path.join(RECORDING_DIR, safe)
    if not os.path.isfile(fpath):
        abort(404)
    audit("gravacao_download", f"arquivo={safe}")
    return send_file(fpath, as_attachment=True)


@app.route("/recordings/stream/<path:filename>")
@login_required
def stream_recording(filename):
    safe  = os.path.basename(filename)
    fpath = os.path.join(RECORDING_DIR, safe)
    if not os.path.isfile(fpath):
        abort(404)
    file_size = os.path.getsize(fpath)
    range_header = request.headers.get("Range")
    if range_header:
        m = re.match(r"bytes=(\d+)-(\d*)", range_header)
        if m:
            start = int(m.group(1))
            end   = int(m.group(2)) if m.group(2) else file_size - 1
            end   = min(end, file_size - 1)
            length = end - start + 1
            with open(fpath, "rb") as f:
                f.seek(start)
                data = f.read(length)
            rv = Response(data, 206, mimetype="video/webm")
            rv.headers["Content-Range"]  = f"bytes {start}-{end}/{file_size}"
            rv.headers["Accept-Ranges"]  = "bytes"
            rv.headers["Content-Length"] = str(length)
            return rv
    return send_file(fpath, mimetype="video/webm")

_RECORD_MAX_FILE_BYTES = int(os.environ.get("RECORD_MAX_FILE_MB", 500)) * 1024 * 1024
_RECORD_MAX_CHUNK_BYTES = 4 * 1024 * 1024  # 4 MB por chunk

@app.route("/api/record", methods=["POST"])
def api_record():
    """Recebe chunks de gravação enviados pelo cliente Ubuntu Desk."""
    api_key = request.headers.get("X-Api-Key", "")
    if not api_key or not _api_key_valid(api_key):
        abort(401)
    action   = request.form.get("action", "")
    filename = os.path.basename(request.form.get("filename", "unknown.webm"))
    if not filename or filename in (".", ".."):
        abort(400)
    os.makedirs(RECORDING_DIR, exist_ok=True)
    fpath = os.path.join(RECORDING_DIR, filename)
    if action == "new":
        # Não sobrescreve arquivo existente — gera nome único para evitar perda de dados
        if os.path.exists(fpath):
            base, ext = os.path.splitext(filename)
            filename = f"{base}_{secrets.token_hex(4)}{ext}"
            fpath = os.path.join(RECORDING_DIR, filename)
        open(fpath, "wb").close()
    elif action in ("part", "tail"):
        chunk = request.files.get("data")
        if chunk:
            # Verificar tamanho do chunk
            chunk_data = chunk.read(_RECORD_MAX_CHUNK_BYTES + 1)
            if len(chunk_data) > _RECORD_MAX_CHUNK_BYTES:
                abort(413)
            # Verificar tamanho total acumulado do arquivo
            current_size = os.path.getsize(fpath) if os.path.exists(fpath) else 0
            if current_size + len(chunk_data) > _RECORD_MAX_FILE_BYTES:
                abort(413)
            with open(fpath, "ab") as f:
                f.write(chunk_data)
    elif action == "remove":
        if os.path.exists(fpath):
            os.remove(fpath)
    return "", 204

AUDIT_PAGE_SIZE = 50

@app.route("/audit")
@login_required
def audit_log():
    _purge_old_audit()

    # ── Parâmetros de filtro ──────────────────────────────────────────────────
    cat_filter    = request.args.get("category", "").strip()
    date_filter   = request.args.get("date", "").strip()   # today | week | month
    search_filter = request.args.get("search", "").strip()
    page          = max(1, int(request.args.get("page", 1) or 1))

    try:
        conn = _get_audit_db()

        # ── Stats (sempre sem filtros) ────────────────────────────────────────
        total_all   = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        today_str   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        today_count = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE ts LIKE ?", (today_str + "%",)
        ).fetchone()[0]
        failures    = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE category = 'security' AND (action LIKE '%falha%' OR action LIKE '%bloqueado%')"
        ).fetchone()[0]
        warnings_24h = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE category = 'security' AND ts >= ?",
            ((datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S"),)
        ).fetchone()[0]

        # ── Query filtrada ────────────────────────────────────────────────────
        where_clauses, params = [], []

        if cat_filter:
            where_clauses.append("category = ?")
            params.append(cat_filter)

        if date_filter == "today":
            where_clauses.append("ts LIKE ?")
            params.append(today_str + "%")
        elif date_filter == "week":
            cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
            where_clauses.append("ts >= ?")
            params.append(cutoff)
        elif date_filter == "month":
            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
            where_clauses.append("ts >= ?")
            params.append(cutoff)

        if search_filter:
            where_clauses.append("(action LIKE ? OR detail LIKE ? OR ip LIKE ?)")
            like = f"%{search_filter}%"
            params += [like, like, like]

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        total_filtered = conn.execute(
            f"SELECT COUNT(*) FROM audit_log {where_sql}", params
        ).fetchone()[0]

        offset = (page - 1) * AUDIT_PAGE_SIZE
        rows = conn.execute(
            f"SELECT ts, action, detail, ip, category FROM audit_log {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [AUDIT_PAGE_SIZE, offset]
        ).fetchall()
        conn.close()

        events = [
            {"ts": r[0], "action": r[1], "detail": r[2] or "", "ip": r[3] or "", "category": r[4] or "system"}
            for r in rows
        ]
    except Exception:
        events, total_all, today_count, failures, warnings_24h, total_filtered = [], 0, 0, 0, 0, 0

    total_pages = max(1, (total_filtered + AUDIT_PAGE_SIZE - 1) // AUDIT_PAGE_SIZE)

    return render_template("audit.html",
        events=events,
        stats={
            "total":    total_all,
            "today":    today_count,
            "failures": failures,
            "security_24h": warnings_24h,
        },
        filters={
            "category": cat_filter,
            "date":     date_filter,
            "search":   search_filter,
        },
        page=page,
        total_pages=total_pages,
        total_filtered=total_filtered,
    )


@app.route("/history")
@login_required
def history():
    page        = max(1, request.args.get("page", 1, type=int))
    per_page    = 50
    peer_filter = request.args.get("peer", "").strip()
    date_from   = request.args.get("from", "").strip()
    date_to     = request.args.get("to", "").strip()

    conn   = _get_sessions_db()
    where  = []
    params = []

    if peer_filter:
        where.append("(peer_from = ? OR peer_to = ?)")
        params += [peer_filter, peer_filter]
    if date_from:
        where.append("started_at >= ?")
        params.append(date_from)
    if date_to:
        where.append("started_at <= ?")
        params.append(date_to + " 23:59:59")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM sessions {where_sql}", params).fetchone()[0]
    rows  = conn.execute(
        f"SELECT * FROM sessions {where_sql} ORDER BY started_at DESC LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page]
    ).fetchall()
    conn.close()

    audit("history_viewed", f"page={page} peer={peer_filter}")
    return render_template(
        "history.html",
        sessions=rows,
        page=page,
        total=total,
        per_page=per_page,
        peer_filter=peer_filter,
        date_from=date_from,
        date_to=date_to,
        pages=max(1, (total + per_page - 1) // per_page),
    )


@app.route("/live-stats")
@login_required
def live_stats():
    rows = query("SELECT status FROM peer")
    total  = len(rows)
    online = sum(1 for r in rows if r["status"] == 1)
    today    = date.today().isoformat()
    week_ago = (date.today() - timedelta(days=7)).isoformat()
    new_this_week = _count_new_peers_since(week_ago)
    conn = _get_sessions_db()
    sessions_today = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE started_at >= ?", (today,)
    ).fetchone()[0]
    conn.close()
    return jsonify({
        "total":          total,
        "online":         online,
        "offline":        total - online,
        "sessions_today": sessions_today,
        "new_this_week":  new_this_week,
    })


@app.route("/audit/export.csv")
@login_required
def audit_export():
    """Exporta todos os logs de auditoria como CSV."""
    _purge_old_audit()
    try:
        conn = _get_audit_db()
        rows = conn.execute(
            "SELECT ts, category, action, detail, ip FROM audit_log ORDER BY id DESC"
        ).fetchall()
        conn.close()
    except Exception:
        rows = []

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Data/Hora (UTC)", "Categoria", "Ação", "Detalhe", "IP"])
    for r in rows:
        writer.writerow([r[0], r[1] or "system", r[2], r[3] or "", r[4] or ""])

    output = buf.getvalue()
    filename = f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

# ── Página de Deploy ──────────────────────────────────────────────────────────

# Lê server IP e pub key do config.rs do cliente (fonte de verdade)
def _read_client_config():
    """Extrai RENDEZVOUS_SERVERS e RS_PUB_KEY do config.rs do cliente."""
    config_path = os.path.join(
        os.path.dirname(__file__), "..", "client", "libs", "hbb_common", "src", "config.rs"
    )
    server_ip = ""
    pub_key   = ""
    try:
        with open(config_path, encoding="utf-8") as f:
            for line in f:
                if "RENDEZVOUS_SERVERS" in line and "&[" in line:
                    # pub const RENDEZVOUS_SERVERS: &[&str] = &["192.168.18.4"];
                    m = re.search(r'"([^"]+)"', line)
                    if m:
                        server_ip = m.group(1)
                elif "RS_PUB_KEY" in line and '= "' in line:
                    m = re.search(r'"([^"]+)"', line)
                    if m:
                        pub_key = m.group(1)
    except Exception:
        pass
    return server_ip, pub_key

@app.route("/deploy")
@login_required
def deploy():
    server_ip, pub_key = _read_client_config()
    api_url = f"http://{server_ip}:{PORT}" if server_ip else ""
    return render_template("deploy.html",
        server_ip=server_ip,
        pub_key=pub_key,
        api_url=api_url,
        admin_port=PORT,
    )

# ── Address Book API (compatível com cliente Ubuntu Desk / RustDesk) ──────────
# Permite que clientes usem a address book sincronizada via painel admin.
# Protocolo: legacy mode (GET/POST /api/ab com Bearer token).

def _get_api_db():
    global _api_db_initialized
    os.makedirs(os.path.dirname(API_DB), exist_ok=True)
    conn = sqlite3.connect(API_DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    if not _api_db_initialized:
        _init_api_db(conn)
        _api_db_initialized = True
    return conn

def _init_api_db(conn):
    """Run all migrations idempotently. Called once per process."""
    # ── api_tokens ────────────────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_tokens (
            token      TEXT PRIMARY KEY,
            created_at REAL NOT NULL,
            username   TEXT NOT NULL DEFAULT 'admin'
        )
    """)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(api_tokens)").fetchall()]
    if "username" not in cols:
        conn.execute("ALTER TABLE api_tokens ADD COLUMN username TEXT NOT NULL DEFAULT 'admin'")

    # ── api_keys ──────────────────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            key        TEXT    UNIQUE NOT NULL,
            created_at REAL    NOT NULL,
            last_used  REAL
        )
    """)

    # ── address_books — migrate from id INTEGER to owner TEXT ─────────────────
    ab_cols = [r[1] for r in conn.execute("PRAGMA table_info(address_books)").fetchall()]
    if not ab_cols:
        conn.execute("""
            CREATE TABLE address_books (
                owner TEXT PRIMARY KEY,
                data  TEXT NOT NULL DEFAULT '{}'
            )
        """)
    elif ab_cols[0] == "id":
        conn.execute("""
            CREATE TABLE address_books_new (
                owner TEXT PRIMARY KEY,
                data  TEXT NOT NULL DEFAULT '{}'
            )
        """)
        conn.execute("""
            INSERT OR IGNORE INTO address_books_new (owner, data)
            SELECT '__shared__', data FROM address_books WHERE id = 1
        """)
        conn.execute("DROP TABLE address_books")
        conn.execute("ALTER TABLE address_books_new RENAME TO address_books")

    # ── users ─────────────────────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username      TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'user',
            is_active     INTEGER NOT NULL DEFAULT 1,
            created_at    REAL NOT NULL
        )
    """)
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
            ("admin", _hash_user_password(ADMIN_PASS), "admin", time.time()),
        )

    # Migração: colunas 2FA
    u_cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
    if "totp_secret" not in u_cols:
        conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    if "totp_enabled" not in u_cols:
        conn.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0")

    # Tabela de recovery codes
    conn.execute("""
        CREATE TABLE IF NOT EXISTS totp_recovery_codes (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT    NOT NULL,
            code_hash TEXT    NOT NULL,
            used      INTEGER DEFAULT 0
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_config (
            id           INTEGER PRIMARY KEY CHECK (id = 1),
            webhook_url  TEXT DEFAULT '',
            webhook_secret TEXT DEFAULT '',
            smtp_host    TEXT DEFAULT '',
            smtp_port    INTEGER DEFAULT 587,
            smtp_user    TEXT DEFAULT '',
            smtp_pass    TEXT DEFAULT '',
            smtp_from    TEXT DEFAULT '',
            smtp_to      TEXT DEFAULT '',
            alert_events TEXT DEFAULT '[]'
        )
    """)
    conn.execute("INSERT OR IGNORE INTO alert_config (id) VALUES (1)")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alert_log (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            event   TEXT    NOT NULL,
            ts      TEXT    NOT NULL,
            channel TEXT    NOT NULL,
            success INTEGER NOT NULL DEFAULT 0,
            error   TEXT    DEFAULT '',
            detail  TEXT    DEFAULT ''
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS peer_tags (
            peer_id TEXT NOT NULL,
            tag     TEXT NOT NULL,
            PRIMARY KEY (peer_id, tag)
        )
    """)

    conn.commit()

def _api_token_valid(token: str):
    """Returns username if token is valid and user is active, else None."""
    try:
        conn = _get_api_db()
        row = conn.execute(
            "SELECT t.created_at, t.username, u.is_active "
            "FROM api_tokens t LEFT JOIN users u ON t.username = u.username "
            "WHERE t.token = ?",
            (token,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        created_at, username, is_active = row
        if (time.time() - created_at) >= 30 * 86400:
            return None
        if is_active is not None and not is_active:
            return None
        return username
    except Exception:
        return None

def _api_key_valid(key: str) -> bool:
    """Named API key — permanente até ser revogada."""
    try:
        conn = _get_api_db()
        row = conn.execute("SELECT id FROM api_keys WHERE key = ?", (key,)).fetchone()
        if row:
            conn.execute("UPDATE api_keys SET last_used = ? WHERE key = ?", (time.time(), key))
            conn.commit()
        conn.close()
        return bool(row)
    except Exception:
        return False

def api_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Bearer token (session, expira 30d)
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            username = _api_token_valid(auth[7:])
            if username:
                conn = _get_api_db()
                row = conn.execute(
                    "SELECT role FROM users WHERE username=?", (username,)
                ).fetchone()
                conn.close()
                g.api_user = {"username": username, "role": row[0] if row else "user"}
                return f(*args, **kwargs)
        # X-Api-Key (named, permanente) — treated as admin
        api_key = request.headers.get("X-Api-Key", "")
        if api_key and _api_key_valid(api_key):
            g.api_user = {"username": "admin", "role": "admin"}
            return f(*args, **kwargs)
        return jsonify({"error": "Unauthorized"}), 401
    return decorated

@app.route("/api/login-options", methods=["GET"])
def api_login_options():
    return jsonify(["password"])

@app.route("/api/login", methods=["POST"])
def api_login():
    ip = request.remote_addr
    if _is_locked(ip):
        audit("login_bloqueado", "IP bloqueado (API) por excesso de tentativas")
        return jsonify({"error": "Too many login attempts. Try again later."}), 429
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or body.get("id") or "").strip()
    password = body.get("password") or ""
    conn = _get_api_db()
    row = conn.execute(
        "SELECT password_hash, role, is_active FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    if row and row[2] and _verify_user_password(password, row[0]):
        token = secrets.token_hex(32)
        conn = _get_api_db()
        conn.execute(
            "INSERT OR REPLACE INTO api_tokens (token, created_at, username) VALUES (?,?,?)",
            (token, time.time(), username),
        )
        conn.commit()
        conn.close()
        _clear_attempts(ip)
        audit("api_login_ok", f"user={username}")
        is_admin = row[1] == "admin"
        return jsonify({
            "type": "access_token",
            "access_token": token,
            "user": {
                "name": username,
                "email": "admin@ubuntudesk.app" if username == "admin" else "",
                "note": row[1],
                "status": 1,
                "grp": "",
                "is_admin": is_admin,
            },
        })
    _record_attempt(ip)
    rem = _remaining_attempts(ip)
    audit("api_login_falha", f"user={username} tentativas_restantes={rem}")
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/currentUser", methods=["GET", "POST"])
@api_auth_required
def api_current_user():
    username = g.api_user["username"]
    role = g.api_user["role"]
    return jsonify({
        "name": username,
        "email": "admin@ubuntudesk.app" if username == "admin" else "",
        "note": role,
        "status": 1,
        "grp": "",
        "is_admin": role == "admin",
    })

@app.route("/api/logout", methods=["POST"])
def api_logout_endpoint():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            conn = _get_api_db()
            conn.execute("DELETE FROM api_tokens WHERE token = ?", (auth[7:],))
            conn.commit()
            conn.close()
        except Exception:
            pass
    return "", 200

@app.route("/api/ab/settings", methods=["POST"])
@api_auth_required
def api_ab_settings():
    # Retorna 404 para forçar o cliente a usar o modo legacy (/api/ab)
    return "", 404

@app.route("/api/ab", methods=["GET", "POST"])
@api_auth_required
def api_ab():
    ab_type = request.args.get("type", "")
    if ab_type not in ("", "shared"):
        return jsonify({"error": "Invalid type"}), 400

    username = g.api_user["username"]
    role     = g.api_user["role"]
    owner    = "__shared__" if ab_type == "shared" else username

    if request.method == "GET":
        conn = _get_api_db()
        row = conn.execute(
            "SELECT data FROM address_books WHERE owner=?", (owner,)
        ).fetchone()
        conn.close()
        if not row:
            return "null", 200
        return jsonify({"data": row[0], "licensed_devices": 0})
    else:
        # POST — write
        if ab_type == "shared" and role not in ("admin", "manager"):
            return jsonify({"error": "Permission denied"}), 403
        body = request.get_json(silent=True) or {}
        data = body.get("data", "{}")
        conn = _get_api_db()
        conn.execute(
            "INSERT OR REPLACE INTO address_books (owner, data) VALUES (?,?)", (owner, data)
        )
        conn.commit()
        conn.close()
        if ab_type == "shared":
            audit("ab_shared_written", f"user={username}")
        return "", 200

# ── REST API — Peers ──────────────────────────────────────────────────────────

@app.route("/api/peers", methods=["GET"])
@api_auth_required
def api_peers_list():
    rows = query("SELECT id, info, status, created_at, note FROM peer ORDER BY created_at DESC")
    peers = []
    for r in rows:
        info = parse_info(r["info"])
        peers.append({
            "id":         r["id"],
            "hostname":   info.get("hostname", ""),
            "os":         info.get("os", ""),
            "cpu":        info.get("cpu", ""),
            "memory":     info.get("memory", ""),
            "username":   info.get("username", ""),
            "status":     r["status"],
            "online":     r["status"] == 1,
            "created_at": r["created_at"],
            "note":       r["note"] or "",
        })
    return jsonify({"peers": peers, "total": len(peers)})

@app.route("/api/peers/<peer_id>", methods=["GET"])
@api_auth_required
def api_peer_get(peer_id):
    rows = query("SELECT id, info, status, created_at, note FROM peer WHERE id = ?", (peer_id,))
    if not rows:
        return jsonify({"error": "Not found"}), 404
    r = rows[0]
    info = parse_info(r["info"])
    return jsonify({
        "id":         r["id"],
        "hostname":   info.get("hostname", ""),
        "os":         info.get("os", ""),
        "cpu":        info.get("cpu", ""),
        "memory":     info.get("memory", ""),
        "username":   info.get("username", ""),
        "status":     r["status"],
        "online":     r["status"] == 1,
        "created_at": r["created_at"],
        "note":       r["note"] or "",
        "info":       info,
    })

@app.route("/api/peers/<peer_id>", methods=["PUT"])
@api_auth_required
def api_peer_update(peer_id):
    body = request.get_json(silent=True) or {}
    note = str(body.get("note", ""))[:300]
    db = get_db()
    if db:
        db.execute("UPDATE peer SET note=? WHERE id=?", (note, peer_id))
        db.commit()
    audit("nota_atualizada", f"id={peer_id} (API)")
    return jsonify({"ok": True})

@app.route("/api/peers/<peer_id>", methods=["DELETE"])
@api_auth_required
def api_peer_delete(peer_id):
    db = get_db()
    if db:
        db.execute("DELETE FROM peer WHERE id=?", (peer_id,))
        db.commit()
    audit("peer_deletado", f"id={peer_id}", category="admin")
    return jsonify({"ok": True})

# ── REST API — Stats ──────────────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
@api_auth_required
def api_stats():
    rows = query("SELECT status FROM peer")
    total  = len(rows)
    online = sum(1 for r in rows if r["status"] == 1)
    try:
        conn = _get_audit_db()
        today_str    = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        events_today = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE ts LIKE ?", (today_str + "%",)
        ).fetchone()[0]
        failures = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action LIKE '%falha%' OR action LIKE '%bloqueado%'"
        ).fetchone()[0]
        conn.close()
    except Exception:
        events_today = failures = 0
    recordings_count = len(_list_recordings())
    return jsonify({
        "peers":      {"total": total, "online": online, "offline": total - online},
        "audit":      {"events_today": events_today, "login_failures": failures},
        "recordings": {"count": recordings_count},
    })

# ── REST API — Audit ──────────────────────────────────────────────────────────

@app.route("/api/audit", methods=["GET"])
@api_auth_required
def api_audit_list():
    cat_filter = request.args.get("category", "").strip()
    search     = request.args.get("search", "").strip()
    limit      = min(int(request.args.get("limit", 100) or 100), 500)
    offset     = int(request.args.get("offset", 0) or 0)
    where_clauses, params = [], []
    if cat_filter:
        where_clauses.append("category = ?")
        params.append(cat_filter)
    if search:
        where_clauses.append("(action LIKE ? OR detail LIKE ?)")
        like = f"%{search}%"
        params += [like, like]
    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
    try:
        conn   = _get_audit_db()
        total  = conn.execute(f"SELECT COUNT(*) FROM audit_log {where_sql}", params).fetchone()[0]
        rows   = conn.execute(
            f"SELECT ts, action, detail, ip, category FROM audit_log {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        conn.close()
        events = [{"ts": r[0], "action": r[1], "detail": r[2] or "", "ip": r[3] or "", "category": r[4] or "system"} for r in rows]
    except Exception:
        events, total = [], 0
    return jsonify({"events": events, "total": total, "limit": limit, "offset": offset})

# ── REST API — Recordings ─────────────────────────────────────────────────────

@app.route("/api/recordings", methods=["GET"])
@api_auth_required
def api_recordings_list_endpoint():
    recs = _list_recordings()
    peer_filter = request.args.get("peer", "").strip()
    if peer_filter:
        recs = [r for r in recs if peer_filter.lower() in r["peer_id"].lower()]
    return jsonify({"recordings": recs, "total": len(recs)})

@app.route("/api/recordings/<path:filename>", methods=["DELETE"])
@api_auth_required
def api_recording_delete(filename):
    safe  = os.path.basename(filename)
    fpath = os.path.join(RECORDING_DIR, safe)
    if not os.path.isfile(fpath):
        return jsonify({"error": "Not found"}), 404
    os.remove(fpath)
    audit("gravacao_deletada", f"arquivo={safe}", category="admin")
    return jsonify({"ok": True})

# ── REST API — Wake-on-LAN ────────────────────────────────────────────────────

def _send_wol_packet(mac: str) -> bool:
    mac_clean = mac.replace(":", "").replace("-", "").replace(".", "")
    if len(mac_clean) != 12:
        return False
    try:
        mac_bytes = bytes.fromhex(mac_clean)
    except ValueError:
        return False
    magic = b"\xff" * 6 + mac_bytes * 16
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(magic, ("<broadcast>", 9))
        return True
    except Exception:
        return False

@app.route("/api/wol", methods=["POST"])
@api_auth_required
def api_wol():
    body    = request.get_json(silent=True) or {}
    mac     = body.get("mac", "").strip()
    peer_id = body.get("peer_id", "").strip()
    if not mac:
        return jsonify({"error": "mac is required"}), 400
    if not _send_wol_packet(mac):
        return jsonify({"error": "Invalid MAC address format"}), 400
    audit("wol_enviado", f"peer={peer_id} mac={mac}", category="access")
    return jsonify({"ok": True, "mac": mac})

# ── REST API — API Keys ───────────────────────────────────────────────────────

@app.route("/api/apikeys", methods=["GET"])
@api_auth_required
def api_apikeys_list():
    try:
        conn = _get_api_db()
        rows = conn.execute(
            "SELECT id, name, created_at, last_used FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        keys = [{
            "id":        r[0],
            "name":      r[1],
            "created_at": datetime.fromtimestamp(r[2], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "last_used":  datetime.fromtimestamp(r[3], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if r[3] else None,
        } for r in rows]
    except Exception:
        keys = []
    return jsonify({"keys": keys})

@app.route("/api/apikeys", methods=["POST"])
@api_auth_required
def api_apikeys_create():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name", "")).strip()[:80]
    if not name:
        return jsonify({"error": "name is required"}), 400
    key = "ud_" + secrets.token_hex(24)
    try:
        conn = _get_api_db()
        conn.execute(
            "INSERT INTO api_keys (name, key, created_at) VALUES (?, ?, ?)",
            (name, key, time.time()),
        )
        conn.commit()
        key_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    audit("apikey_criada", f"name={name}", category="admin")
    return jsonify({"id": key_id, "name": name, "key": key}), 201

@app.route("/api/apikeys/<int:key_id>", methods=["DELETE"])
@api_auth_required
def api_apikeys_delete(key_id):
    try:
        conn = _get_api_db()
        row  = conn.execute("SELECT name FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Not found"}), 404
        conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        conn.commit()
        conn.close()
        audit("apikey_revogada", f"id={key_id} name={row[0]}", category="admin")
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})

# ── Admin UI — gerenciamento de API keys via sessão ──────────────────────────

@app.route("/apiadmin/createkey", methods=["POST"])
@login_required
def apiadmin_createkey():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name", "")).strip()[:80]
    if not name:
        return jsonify({"error": "name is required"}), 400
    key = "ud_" + secrets.token_hex(24)
    try:
        conn = _get_api_db()
        conn.execute(
            "INSERT INTO api_keys (name, key, created_at) VALUES (?, ?, ?)",
            (name, key, time.time()),
        )
        conn.commit()
        key_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    audit("apikey_criada", f"name={name}", category="admin")
    return jsonify({"id": key_id, "name": name, "key": key}), 201

@app.route("/apiadmin/deletekey/<int:key_id>", methods=["POST"])
@login_required
def apiadmin_deletekey(key_id):
    try:
        conn = _get_api_db()
        row  = conn.execute("SELECT name FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Not found"}), 404
        conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        conn.commit()
        conn.close()
        audit("apikey_revogada", f"id={key_id} name={row[0]}", category="admin")
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})

@app.route("/apiadmin/listkeys")
@login_required
def apiadmin_listkeys():
    try:
        conn = _get_api_db()
        rows = conn.execute(
            "SELECT id, name, created_at, last_used FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        keys = [{
            "id":        r[0],
            "name":      r[1],
            "created_at": datetime.fromtimestamp(r[2], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "last_used":  datetime.fromtimestamp(r[3], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if r[3] else None,
        } for r in rows]
    except Exception:
        keys = []
    return jsonify({"keys": keys})

# ── Página de documentação da API ─────────────────────────────────────────────

@app.route("/apidocs")
@login_required
def apidocs():
    server_ip, _ = _read_client_config()
    base_url = f"http://{server_ip}:{PORT}" if server_ip else f"http://SEU-SERVIDOR:{PORT}"
    return render_template("api_docs.html", base_url=base_url)

def _startup_security_check():
    import sys
    # ── Bloqueadores — impedem o servidor de subir em produção com config insegura ──
    if ADMIN_PASS == _DEFAULT_PASSWORD:
        print(
            "\n[Ubuntu Desk Admin] ERRO CRÍTICO DE SEGURANÇA:\n"
            "  ADMIN_PASSWORD está no valor padrão ('ubuntu-desk-admin').\n"
            "  Defina ADMIN_PASSWORD=<senha-forte> no arquivo server/.env antes de continuar.\n"
            "  Servidor encerrado para proteger seus dados.\n",
            file=sys.stderr,
        )
        sys.exit(1)
    # ── Avisos — não bloqueiam, mas devem ser corrigidos antes de expor na rede ──
    w = []
    if not TOTP_SECRET:
        w.append("2FA desativado — defina TOTP_SECRET para maior segurança")
    if not app.config.get("SESSION_COOKIE_SECURE"):
        w.append("HTTPS_ONLY não ativado — recomendado atrás de proxy HTTPS")
    if w:
        print("\n[Ubuntu Desk Admin] AVISOS DE SEGURANÇA:", file=sys.stderr)
        for msg in w:
            print(f"  ⚠  {msg}", file=sys.stderr)
        print("", file=sys.stderr)

# ── User management (web panel — admin only) ──────────────────────────────────

@app.route("/users")
@admin_required
def users_list():
    conn = _get_api_db()
    rows = conn.execute(
        "SELECT username, role, is_active, created_at FROM users ORDER BY created_at"
    ).fetchall()
    conn.close()
    user_list = [
        {
            "username": r[0],
            "role": r[1],
            "is_active": bool(r[2]),
            "created_at": datetime.fromtimestamp(r[3], tz=timezone.utc).strftime("%Y-%m-%d %H:%M"),
        }
        for r in rows
    ]
    return render_template("users.html", users=user_list)


@app.route("/users/new", methods=["POST"])
@admin_required
def users_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role     = request.form.get("role", "user")
    if username == "__shared__" or not username:
        return render_template("users.html",
            error="Username inválido.", users=_users_list_data()), 400
    pwd_error = _validate_password(password)
    if pwd_error:
        flash(pwd_error, "error")
        return redirect(url_for("users_list"))
    if role not in ("user", "manager"):
        return render_template("users.html",
            error="Role inválida.", users=_users_list_data()), 400
    conn = _get_api_db()
    existing = conn.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        conn.close()
        return render_template("users.html",
            error="Username já existe.", users=_users_list_data()), 400
    conn.execute(
        "INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES (?,?,?,1,?)",
        (username, _hash_user_password(password), role, time.time()),
    )
    conn.commit()
    conn.close()
    audit("user_created", f"username={username} role={role}")
    _dispatch_alert("user_created", {"username": username, "role": role})
    flash(f"Usuário '{username}' criado.", "success")
    return redirect(url_for("users_list"))


@app.route("/users/<username>/role", methods=["POST"])
@admin_required
def users_set_role(username):
    if username == "admin":
        return redirect(url_for("users_list"))
    role = request.form.get("role", "user")
    if role not in ("user", "manager"):
        return redirect(url_for("users_list"))
    conn = _get_api_db()
    conn.execute("UPDATE users SET role=? WHERE username=?", (role, username))
    conn.commit()
    conn.close()
    audit("user_role_changed", f"username={username} new_role={role}")
    flash(f"Role de '{username}' alterada para {role}.", "success")
    return redirect(url_for("users_list"))


@app.route("/users/<username>/password", methods=["POST"])
@admin_required
def users_reset_password(username):
    if username == "admin":
        return redirect(url_for("users_list"))
    password = request.form.get("password", "")
    pwd_error = _validate_password(password)
    if pwd_error:
        flash(pwd_error, "error")
        return redirect(url_for("users_list"))
    conn = _get_api_db()
    conn.execute(
        "UPDATE users SET password_hash=? WHERE username=?",
        (_hash_user_password(password), username),
    )
    # purge all active tokens for this user
    conn.execute("DELETE FROM api_tokens WHERE username=?", (username,))
    conn.commit()
    conn.close()
    audit("user_password_reset", f"username={username}", category="security")
    flash(f"Senha de '{username}' redefinida.", "success")
    return redirect(url_for("users_list"))


@app.route("/users/<username>/toggle", methods=["POST"])
@admin_required
def users_toggle(username):
    if username == "admin":
        return redirect(url_for("users_list"))
    conn = _get_api_db()
    row = conn.execute("SELECT is_active FROM users WHERE username=?", (username,)).fetchone()
    if row:
        new_state = 0 if row[0] else 1
        conn.execute("UPDATE users SET is_active=? WHERE username=?", (new_state, username))
        conn.commit()
        action = "user_reactivated" if new_state else "user_deactivated"
        cat    = "admin" if new_state else "security"
        audit(action, f"username={username}", category=cat)
        flash(f"Usuário '{username}' {'reativado' if new_state else 'desativado'}.", "success")
    conn.close()
    return redirect(url_for("users_list"))


@app.route("/users/<username>/delete", methods=["POST"])
@admin_required
def users_delete(username):
    if username == "admin":
        return redirect(url_for("users_list"))
    conn = _get_api_db()
    with conn:  # transaction
        conn.execute("DELETE FROM api_tokens WHERE username=?", (username,))
        conn.execute("DELETE FROM address_books WHERE owner=?", (username,))
        conn.execute("DELETE FROM users WHERE username=?", (username,))
    conn.close()
    audit("user_deleted", f"username={username}", category="security")
    _dispatch_alert("user_deleted", {"username": username})
    flash(f"Usuário '{username}' excluído.", "success")
    return redirect(url_for("users_list"))


@app.route("/users/<username>/ab")
@admin_required
def users_view_ab(username):
    conn = _get_api_db()
    row = conn.execute(
        "SELECT data FROM address_books WHERE owner=?", (username,)
    ).fetchone()
    conn.close()
    data = row[0] if row else "{}"
    audit("ab_viewed", f"username={username}", category="access")
    return render_template("users.html",
        users=_users_list_data(),
        view_ab={"username": username, "data": data})


def _users_list_data():
    conn = _get_api_db()
    rows = conn.execute(
        "SELECT username, role, is_active, created_at FROM users ORDER BY created_at"
    ).fetchall()
    conn.close()
    return [
        {
            "username": r[0],
            "role": r[1],
            "is_active": bool(r[2]),
            "created_at": datetime.fromtimestamp(r[3], tz=timezone.utc).strftime("%Y-%m-%d %H:%M"),
        }
        for r in rows
    ]


# ── Backup automático SQLite ───────────────────────────────────────────────────
BACKUP_DIR            = os.environ.get("BACKUP_DIR", os.path.join(os.path.dirname(__file__), "data", "backups"))
BACKUP_RETENTION_DAYS = int(os.environ.get("BACKUP_RETENTION_DAYS", 7))
BACKUP_INTERVAL_HOURS = int(os.environ.get("BACKUP_INTERVAL_HOURS", 24))

def _backup_databases(backup_dir: str = BACKUP_DIR):
    today = time.strftime("%Y-%m-%d")
    dest = os.path.join(backup_dir, today)
    os.makedirs(dest, exist_ok=True)
    for name, path in [("api.db", API_DB), ("audit.db", AUDIT_DB), ("sessions.db", SESSIONS_DB)]:
        if not os.path.exists(path):
            continue
        try:
            src  = sqlite3.connect(path)
            dst  = sqlite3.connect(os.path.join(dest, name))
            src.backup(dst)
            src.close()
            dst.close()
        except Exception:
            pass

def _cleanup_old_backups(backup_dir: str = BACKUP_DIR, retention_days: int = BACKUP_RETENTION_DAYS):
    if not os.path.isdir(backup_dir):
        return
    import shutil
    dirs = sorted(
        [d for d in os.listdir(backup_dir) if os.path.isdir(os.path.join(backup_dir, d))],
        reverse=True
    )
    for old_dir in dirs[retention_days:]:
        shutil.rmtree(os.path.join(backup_dir, old_dir), ignore_errors=True)

def _backup_loop():
    interval = BACKUP_INTERVAL_HOURS * 3600
    while True:
        time.sleep(interval)
        _backup_databases()
        _cleanup_old_backups()


def _send_alert_sync(event: str, detail: dict, bypass_filter: bool = False) -> list:
    """Envia alerta de forma síncrona. Retorna lista de (channel, success, error_msg)."""
    import json as _j, datetime as _dt
    results = []
    try:
        conn = _get_api_db()
        cfg = conn.execute("SELECT * FROM alert_config WHERE id=1").fetchone()
        conn.close()
        if not cfg:
            return results
        events = _j.loads(cfg["alert_events"] or "[]")
        if not bypass_filter and events and event not in events:
            return results
        payload = _j.dumps({
            "event": event,
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "detail": detail,
        }).encode()
        if cfg["webhook_url"]:
            try:
                import urllib.request, hmac as _hmac, hashlib as _hashlib
                sig = "sha256=" + _hmac.new(
                    (cfg["webhook_secret"] or "").encode(), payload, _hashlib.sha256
                ).hexdigest()
                req = urllib.request.Request(
                    cfg["webhook_url"], data=payload,
                    headers={"Content-Type": "application/json", "X-Ubuntu-Desk-Signature": sig},
                )
                urllib.request.urlopen(req, timeout=5)
                results.append(("webhook", True, ""))
            except Exception as e:
                results.append(("webhook", False, str(e)))
        if cfg["smtp_host"] and cfg["smtp_to"]:
            try:
                import smtplib
                from email.mime.text import MIMEText
                msg = MIMEText(f"Evento: {event}\n\n{_j.dumps(detail, indent=2)}", "plain")
                msg["Subject"] = f"[Ubuntu Desk] Alerta: {event}"
                msg["From"]    = cfg["smtp_from"] or cfg["smtp_user"]
                msg["To"]      = cfg["smtp_to"]
                with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=5) as s:
                    if cfg["smtp_user"]:
                        s.starttls()
                        s.login(cfg["smtp_user"], cfg["smtp_pass"])
                    s.send_message(msg)
                results.append(("smtp", True, ""))
            except Exception as e:
                results.append(("smtp", False, str(e)))
    except Exception as e:
        results.append(("internal", False, str(e)))
    return results


def _log_alert_results(event: str, detail: dict, results: list):
    """Persiste resultados de envio na tabela alert_log."""
    if not results:
        return
    import json as _j, datetime as _dt
    ts = _dt.datetime.now(_dt.timezone.utc).isoformat()
    detail_str = _j.dumps(detail)
    try:
        conn = _get_api_db()
        for channel, success, error in results:
            conn.execute(
                "INSERT INTO alert_log (event, ts, channel, success, error, detail) VALUES (?,?,?,?,?,?)",
                (event, ts, channel, 1 if success else 0, error or "", detail_str),
            )
        conn.commit()
        conn.close()
    except Exception:
        pass


def _dispatch_alert(event: str, detail: dict):
    import threading as _t
    def _send():
        results = _send_alert_sync(event, detail)
        _log_alert_results(event, detail, results)
    _t.Thread(target=_send, daemon=True).start()


if __name__ == "__main__":
    _startup_security_check()
    import threading as _threading
    _t = _threading.Thread(target=_backup_loop, daemon=True)
    _t.start()
    app.run(host="0.0.0.0", port=PORT, debug=False)
