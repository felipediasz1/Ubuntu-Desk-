"""
Ubuntu Desk — Painel de Administração
Lê o banco SQLite gerado pelo hbbs e exibe os dispositivos registrados.
"""

import sqlite3
import json
import os
import re
import hashlib
import secrets
import time
import csv
import io
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, session, g, abort, send_file, jsonify, Response

app = Flask(__name__)

# ── Secret key persistente (sobrevive a restarts) ─────────────────────────────
_SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), ".secret_key")

def _load_secret_key():
    if os.path.exists(_SECRET_KEY_FILE):
        return open(_SECRET_KEY_FILE).read().strip()
    key = secrets.token_hex(32)
    with open(_SECRET_KEY_FILE, "w") as f:
        f.write(key)
    return key

app.secret_key = _load_secret_key()
app.permanent_session_lifetime = timedelta(hours=2)

# ── Configuração ──────────────────────────────────────────────────────────────
DB_PATH       = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "..", "server", "data", "db_v2.sqlite3"))
AUDIT_DB      = os.environ.get("AUDIT_DB", os.path.join(os.path.dirname(__file__), "data", "audit.db"))
API_DB        = os.environ.get("API_DB", os.path.join(os.path.dirname(__file__), "data", "api.db"))
ADMIN_PASS    = os.environ.get("ADMIN_PASSWORD", "ubuntu-desk-admin")
TOTP_SECRET   = os.environ.get("TOTP_SECRET", "")  # Opcional: ativar 2FA no admin
RECORDING_DIR = os.environ.get("RECORDING_DIR", os.path.join(os.path.dirname(__file__), "data", "recordings"))
PORT          = int(os.environ.get("PORT", 8088))

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
_audit_purged = False  # purge uma vez por processo

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
}

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
    os.makedirs(os.path.dirname(AUDIT_DB), exist_ok=True)
    conn = sqlite3.connect(AUDIT_DB)
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
    return conn

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

def audit(action: str, detail: str = "", category: str = ""):
    try:
        ip = request.remote_addr
    except RuntimeError:
        ip = "system"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cat = category or _categorize(action)
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
def check_password(pwd: str) -> bool:
    return (
        hashlib.sha256(pwd.encode()).hexdigest()
        == hashlib.sha256(ADMIN_PASS.encode()).hexdigest()
    )

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

# ── Session timeout ───────────────────────────────────────────────────────────
@app.before_request
def check_session_timeout():
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

# ── Helpers ───────────────────────────────────────────────────────────────────
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

# ── Rotas ─────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    ip = request.remote_addr
    totp_required = bool(TOTP_SECRET)

    if request.method == "POST":
        if _is_locked(ip):
            audit("login_bloqueado", "IP bloqueado por excesso de tentativas")
            error = "Muitas tentativas falhas. Aguarde 15 minutos."
        else:
            pwd  = request.form.get("password", "")
            code = request.form.get("totp", "")
            if check_password(pwd) and check_totp(code):
                _clear_attempts(ip)
                session["logged_in"]   = True
                session["last_active"] = time.time()
                session.permanent      = True
                audit("login_ok")
                return redirect(request.args.get("next") or url_for("index"))
            else:
                _record_attempt(ip)
                rem = _remaining_attempts(ip)
                audit("login_falha", f"tentativas restantes={rem}")
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
    rows = query(
        "SELECT id, info, status, created_at, note FROM peer ORDER BY created_at DESC"
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
        })

    db_exists = os.path.exists(DB_PATH)
    total     = len(peers)
    active    = sum(1 for p in peers if p["status"] == 1)

    return render_template("index.html",
        peers=peers,
        total=total,
        active=active,
        db_exists=db_exists,
        db_path=DB_PATH,
    )

@app.route("/peer/<peer_id>")
@login_required
def peer_detail(peer_id):
    rows = query(
        "SELECT id, info, status, created_at, note FROM peer WHERE id = ?",
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
        "info_raw":   json.dumps(info, indent=2, ensure_ascii=False),
    }
    audit("peer_visualizado", f"id={peer_id} hostname={peer['hostname']}")
    return render_template("peer.html", peer=peer)

@app.route("/peer/<peer_id>/note", methods=["POST"])
@login_required
def update_note(peer_id):
    note = request.form.get("note", "")[:300]
    db   = get_db()
    if db:
        db.execute("UPDATE peer SET note=? WHERE id=?", (note, peer_id))
        db.commit()
    audit("nota_atualizada", f"id={peer_id}")
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
    recs = _list_recordings()
    peer_filter = request.args.get("peer", "").strip()
    dir_filter  = request.args.get("direction", "").strip()
    if peer_filter:
        recs = [r for r in recs if peer_filter.lower() in r["peer_id"].lower()]
    if dir_filter in ("incoming", "outgoing"):
        recs = [r for r in recs if r["direction"] == dir_filter]
    peers = sorted({r["peer_id"] for r in _list_recordings()})
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

@app.route("/api/record", methods=["POST"])
def api_record():
    """Recebe chunks de gravação enviados pelo cliente Ubuntu Desk."""
    api_key = request.headers.get("X-Api-Key", "")
    if hashlib.sha256(api_key.encode()).hexdigest() != hashlib.sha256(ADMIN_PASS.encode()).hexdigest():
        abort(401)
    action   = request.form.get("action", "")
    filename = os.path.basename(request.form.get("filename", "unknown.webm"))
    os.makedirs(RECORDING_DIR, exist_ok=True)
    fpath = os.path.join(RECORDING_DIR, filename)
    if action == "new":
        open(fpath, "wb").close()
    elif action in ("part", "tail"):
        chunk = request.files.get("data")
        if chunk:
            with open(fpath, "ab") as f:
                f.write(chunk.read())
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
                    import re as _re
                    m = _re.search(r'"([^"]+)"', line)
                    if m:
                        server_ip = m.group(1)
                elif "RS_PUB_KEY" in line and '= "' in line:
                    import re as _re
                    m = _re.search(r'"([^"]+)"', line)
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
    os.makedirs(os.path.dirname(API_DB), exist_ok=True)
    conn = sqlite3.connect(API_DB, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_tokens (
            token      TEXT PRIMARY KEY,
            created_at REAL NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS address_books (
            id   INTEGER PRIMARY KEY,
            data TEXT    NOT NULL DEFAULT '{}'
        )
    """)
    conn.commit()
    return conn

def _api_token_valid(token: str) -> bool:
    """Token expira após 30 dias."""
    try:
        conn = _get_api_db()
        row = conn.execute(
            "SELECT created_at FROM api_tokens WHERE token = ?", (token,)
        ).fetchone()
        conn.close()
        if not row:
            return False
        return (time.time() - row[0]) < 30 * 86400
    except Exception:
        return False

def api_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        if not _api_token_valid(auth[7:]):
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/api/login-options", methods=["GET"])
def api_login_options():
    return jsonify(["password"])

@app.route("/api/login", methods=["POST"])
def api_login():
    body = request.get_json(silent=True) or {}
    username = body.get("username") or body.get("id") or ""
    password = body.get("password") or ""
    if username == "admin" and check_password(password):
        token = secrets.token_hex(32)
        conn = _get_api_db()
        conn.execute(
            "INSERT OR REPLACE INTO api_tokens (token, created_at) VALUES (?, ?)",
            (token, time.time()),
        )
        conn.commit()
        conn.close()
        audit("api_login_ok", f"user={username}")
        return jsonify({
            "type": "access_token",
            "access_token": token,
            "user": {
                "name": "admin",
                "email": "admin@ubuntudesk.app",
                "note": "Administrator",
                "status": 1,
                "grp": "",
                "is_admin": True,
            },
        })
    audit("api_login_falha", f"user={username}")
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/api/currentUser", methods=["GET", "POST"])
@api_auth_required
def api_current_user():
    return jsonify({
        "name": "admin",
        "email": "admin@ubuntudesk.app",
        "note": "Administrator",
        "status": 1,
        "grp": "",
        "is_admin": True,
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
    conn = _get_api_db()
    if request.method == "GET":
        row = conn.execute(
            "SELECT data FROM address_books WHERE id = 1"
        ).fetchone()
        conn.close()
        if not row:
            return "null", 200
        return jsonify({"data": row[0], "licensed_devices": 0})
    else:
        body = request.get_json(silent=True) or {}
        data = body.get("data", "{}")
        conn.execute(
            "INSERT OR REPLACE INTO address_books (id, data) VALUES (1, ?)", (data,)
        )
        conn.commit()
        conn.close()
        return "", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
