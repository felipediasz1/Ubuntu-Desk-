# Multi-User Address Book Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-user address books + a shared address book to the Ubuntu Desk admin panel, with role-based access (user/manager/admin) and a web UI for user management.

**Architecture:** All changes are in `admin/app.py` and two new/modified templates. A new `users` table is added to `api.db`. The `address_books` table is migrated from `id INTEGER` to `owner TEXT`. The `api_tokens` table gains a `username` column. The Flask API is updated to authenticate against the `users` table instead of the hardcoded `ADMIN_PASS`. Zero changes to the Flutter client.

**Tech Stack:** Python 3, Flask, SQLite3, pytest, Jinja2. No new dependencies required.

---

## File Map

| File | Action | What changes |
|---|---|---|
| `admin/app.py` | Modify | All backend logic: migration, auth, address book, user management routes |
| `admin/templates/users.html` | Create | New page: list/create/edit/delete users |
| `admin/templates/base.html` | Modify | Add "Usuários" link to sidebar |
| `admin/tests/conftest.py` | Create | pytest fixtures: Flask test client, in-memory SQLite |
| `admin/tests/test_users_db.py` | Create | Tests: migration, password hashing, user CRUD |
| `admin/tests/test_api_auth.py` | Create | Tests: login, token, is_active check |
| `admin/tests/test_address_book.py` | Create | Tests: per-user book, shared book, permissions |
| `admin/tests/test_users_panel.py` | Create | Tests: web panel CRUD routes |

---

## Task 1: Test infrastructure

**Files:**
- Create: `admin/tests/__init__.py`
- Create: `admin/tests/conftest.py`

- [ ] **Step 1: Create test package**

```bash
mkdir -p "/c/Users/felip/OneDrive/Documentos/projeto 2/admin/tests"
touch "/c/Users/felip/OneDrive/Documentos/projeto 2/admin/tests/__init__.py"
```

- [ ] **Step 2: Install pytest if not present**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
pip install pytest flask 2>/dev/null | tail -1
```

- [ ] **Step 3: Create conftest.py**

```python
# admin/tests/conftest.py
import os
import sys
import re
import pytest

# Ensure the admin package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("ADMIN_PASSWORD", "test-admin-pass")
os.environ.setdefault("HTTPS_ONLY", "0")

import app as flask_app


@pytest.fixture
def tmp_dbs(tmp_path):
    """Override API_DB and AUDIT_DB to temporary files for each test."""
    api_db   = str(tmp_path / "api.db")
    audit_db = str(tmp_path / "audit.db")
    flask_app.API_DB   = api_db
    flask_app.AUDIT_DB = audit_db
    flask_app._api_db_initialized   = False
    flask_app._audit_db_initialized = False
    flask_app._audit_purged         = False
    yield {"api_db": api_db, "audit_db": audit_db}


@pytest.fixture
def client(tmp_dbs):
    flask_app.app.config["TESTING"] = True
    # Force DB initialization so admin user is seeded before any test calls /api/login
    flask_app._get_api_db().close()
    with flask_app.app.test_client() as c:
        yield c


def _get_csrf(client):
    rv = client.get("/login")
    m = re.search(r'name="csrf_token" value="([^"]+)"', rv.data.decode())
    return m.group(1) if m else ""
```

- [ ] **Step 4: Run (expect no errors — no tests yet)**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/ -v 2>&1 | head -20
```

Expected: `no tests ran` or similar.

- [ ] **Step 5: Commit**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2"
git add admin/tests/
git commit -m "test: setup pytest infrastructure for admin"
```

---

## Task 2: Per-user password hashing helpers

The existing `_pbkdf2()` uses a fixed app-wide salt. For multiple users we need a random salt stored per-user as `salt_hex$hash_hex` in the `password_hash` column.

**Files:**
- Modify: `admin/app.py` — add `_hash_user_password()`, `_verify_user_password()` after line ~214
- Create: `admin/tests/test_users_db.py`

- [ ] **Step 1: Write failing tests**

```python
# admin/tests/test_users_db.py
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("ADMIN_PASSWORD", "test-admin-pass")
os.environ.setdefault("HTTPS_ONLY", "0")
import app as flask_app


def test_hash_and_verify_password():
    h = flask_app._hash_user_password("mypassword")
    assert "$" in h
    assert flask_app._verify_user_password("mypassword", h) is True
    assert flask_app._verify_user_password("wrongpass", h) is False


def test_two_hashes_are_different():
    h1 = flask_app._hash_user_password("same")
    h2 = flask_app._hash_user_password("same")
    assert h1 != h2  # different salts
```

- [ ] **Step 2: Run — expect FAIL**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/test_users_db.py::test_hash_and_verify_password -v
```

Expected: `AttributeError: module 'app' has no attribute '_hash_user_password'`

- [ ] **Step 3: Implement in app.py — add after the `check_password()` function (around line 214)**

```python
# ── Per-user password hashing (random salt per user) ─────────────────────────
def _hash_user_password(pwd: str) -> str:
    """Hash password with random per-user salt. Returns 'salt_hex$hash_hex'."""
    import os as _os
    salt = _os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 260_000)
    return salt.hex() + "$" + h.hex()

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
```

- [ ] **Step 4: Run — expect PASS**

```bash
python -m pytest tests/test_users_db.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2"
git add admin/app.py admin/tests/test_users_db.py
git commit -m "feat: per-user password hashing with random salt"
```

---

## Task 3: DB schema migration

Replace the `_get_api_db()` initializer with a proper `_init_api_db()` that handles all migrations idempotently.

**Files:**
- Modify: `admin/app.py` — replace body of `_get_api_db()` (lines 692–720)

- [ ] **Step 1: Write failing tests (append to test_users_db.py)**

```python
def test_init_creates_users_table(tmp_dbs):
    conn = flask_app._get_api_db()
    cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
    conn.close()
    assert "username" in cols
    assert "role" in cols
    assert "is_active" in cols


def test_init_creates_admin_user(tmp_dbs):
    conn = flask_app._get_api_db()
    row = conn.execute("SELECT username, role FROM users WHERE username='admin'").fetchone()
    conn.close()
    assert row is not None
    assert row[1] == "admin"


def test_init_address_books_owner_schema(tmp_dbs):
    conn = flask_app._get_api_db()
    cols = [r[1] for r in conn.execute("PRAGMA table_info(address_books)").fetchall()]
    conn.close()
    assert "owner" in cols
    assert "id" not in cols


def test_init_api_tokens_has_username(tmp_dbs):
    conn = flask_app._get_api_db()
    cols = [r[1] for r in conn.execute("PRAGMA table_info(api_tokens)").fetchall()]
    conn.close()
    assert "username" in cols


def test_migration_from_old_address_books(tmp_dbs):
    """Old schema (id INTEGER) is migrated to owner TEXT, preserving id=1 as __shared__."""
    import sqlite3
    conn = sqlite3.connect(flask_app.API_DB)
    conn.execute("CREATE TABLE address_books (id INTEGER PRIMARY KEY, data TEXT NOT NULL DEFAULT '{}')")
    conn.execute("INSERT INTO address_books (id, data) VALUES (1, '{\"peers\":[]}')")
    conn.commit()
    conn.close()
    flask_app._api_db_initialized = False  # force re-init
    conn = flask_app._get_api_db()
    row = conn.execute("SELECT data FROM address_books WHERE owner='__shared__'").fetchone()
    conn.close()
    assert row is not None
    assert "peers" in row[0]


def test_init_is_idempotent(tmp_dbs):
    flask_app._get_api_db().close()
    flask_app._api_db_initialized = False
    flask_app._get_api_db().close()  # second init — should not raise
```

Note: these tests need the `tmp_dbs` fixture — add `from .conftest import *` or rely on pytest auto-discovery (conftest.py in same package).

- [ ] **Step 2: Run — expect FAIL**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/test_users_db.py -v
```

Expected: `test_init_creates_users_table` FAIL (table doesn't exist yet).

- [ ] **Step 3: Replace `_get_api_db()` body in app.py**

Find the `_get_api_db()` function (around line 692) and replace it entirely with:

```python
def _get_api_db():
    global _api_db_initialized
    os.makedirs(os.path.dirname(API_DB), exist_ok=True)
    conn = sqlite3.connect(API_DB, check_same_thread=False)
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
    # add username column if missing (existing installs)
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
        # fresh install — create new schema directly
        conn.execute("""
            CREATE TABLE address_books (
                owner TEXT PRIMARY KEY,
                data  TEXT NOT NULL DEFAULT '{}'
            )
        """)
    elif ab_cols[0] == "id":
        # old schema exists — migrate
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
    # else: already new schema — nothing to do

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
    # seed admin user from ADMIN_PASS if table is empty
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
            ("admin", _hash_user_password(ADMIN_PASS), "admin", time.time()),
        )

    conn.commit()
```

- [ ] **Step 4: Run — expect PASS**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/test_users_db.py -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2"
git add admin/app.py admin/tests/test_users_db.py
git commit -m "feat: db migration — users table, address_books owner schema, api_tokens username"
```

---

## Task 4: Update `api_auth_required` to populate `g.api_user`

**Files:**
- Modify: `admin/app.py` — `_api_token_valid()`, `_api_key_valid()`, `api_auth_required`
- Create: `admin/tests/test_api_auth.py`

- [ ] **Step 1: Write failing tests**

```python
# admin/tests/test_api_auth.py
import pytest, os, sys, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("ADMIN_PASSWORD", "test-admin-pass")
os.environ.setdefault("HTTPS_ONLY", "0")
import app as flask_app


def _login(client, username="admin", password=None):
    password = password or os.environ["ADMIN_PASSWORD"]
    rv = client.post("/api/login", json={"username": username, "password": password})
    return rv


def test_api_login_admin_success(client):
    rv = _login(client)
    assert rv.status_code == 200
    data = rv.get_json()
    assert data["user"]["name"] == "admin"
    assert "access_token" in data


def test_api_login_wrong_password(client):
    rv = _login(client, password="wrong")
    assert rv.status_code == 401


def test_api_login_nonexistent_user(client):
    rv = _login(client, username="ghost", password="anything")
    assert rv.status_code == 401


def test_bearer_token_sets_api_user(client):
    rv = _login(client)
    token = rv.get_json()["access_token"]
    rv2 = client.get("/api/currentUser", headers={"Authorization": f"Bearer {token}"})
    assert rv2.status_code == 200
    data = rv2.get_json()
    assert data["name"] == "admin"


def test_deactivated_user_token_rejected(client):
    # Create a user, log in, deactivate, then re-use token
    conn = flask_app._get_api_db()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES (?,?,?,1,?)",
        ("techjoao", flask_app._hash_user_password("pass12345"), "user", time.time()),
    )
    conn.commit()
    conn.close()
    rv = _login(client, username="techjoao", password="pass12345")
    token = rv.get_json()["access_token"]
    # Deactivate
    conn = flask_app._get_api_db()
    conn.execute("UPDATE users SET is_active=0 WHERE username='techjoao'")
    conn.commit()
    conn.close()
    # Token must now be rejected
    rv2 = client.get("/api/currentUser", headers={"Authorization": f"Bearer {token}"})
    assert rv2.status_code == 401


def test_xapikey_gets_admin_role(client, tmp_dbs):
    # Create a named API key directly in DB
    conn = flask_app._get_api_db()
    conn.execute(
        "INSERT INTO api_keys (name, key, created_at) VALUES (?,?,?)",
        ("mykey", "test-api-key-value", time.time()),
    )
    conn.commit()
    conn.close()
    rv = client.get("/api/currentUser", headers={"X-Api-Key": "test-api-key-value"})
    assert rv.status_code == 200
```

- [ ] **Step 2: Run — expect FAIL**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/test_api_auth.py -v
```

Expected: `test_api_login_admin_success` FAIL (still uses hardcoded admin check).

- [ ] **Step 3: Update `_api_token_valid()` to return username or None, and check is_active**

Replace `_api_token_valid()` (around line 722) with:

```python
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
        return False
```

- [ ] **Step 4: Update `api_auth_required` to populate `g.api_user`**

Replace `api_auth_required` decorator (around line 749):

```python
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
```

- [ ] **Step 5: Run — expect most tests pass (login still fails)**

```bash
python -m pytest tests/test_api_auth.py -v
```

- [ ] **Step 6: Commit** (do NOT include `test_api_auth.py` yet — some tests still fail until Task 5 updates `api_login`. Apply Tasks 4 and 5 code changes first, then commit both together in Task 5 Step 5.)

> **Note:** `_api_token_valid` now returns a username string instead of bool. Apply both Step 3 (new `_api_token_valid`) and Step 4 (new `api_auth_required`) atomically — applying only Step 3 would break the old decorator which expects a bool.

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2"
git add admin/app.py
git commit -m "feat: api_auth_required populates g.api_user, checks is_active"
```

---

## Task 5: Multi-user `api_login()` and `api_current_user()`

**Files:**
- Modify: `admin/app.py` — `api_login()`, `api_current_user()`

- [ ] **Step 1: Replace `api_login()` (around line 767)**

```python
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
```

- [ ] **Step 2: Replace `api_current_user()` (around line 804)**

```python
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
```

- [ ] **Step 3: Run all auth tests — expect PASS**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/test_api_auth.py -v
```

Expected: all pass.

- [ ] **Step 4: Run full auth test suite — all must pass before committing**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/test_api_auth.py -v
```

Expected: all tests pass (Tasks 4+5 changes are now complete together).

- [ ] **Step 5: Commit** (include test file — only commit when all tests pass)

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2"
git add admin/app.py admin/tests/test_api_auth.py
git commit -m "feat: api_login and api_current_user use users table"
```

---

## Task 6: Per-user + shared address book

**Files:**
- Modify: `admin/app.py` — `api_ab()`
- Create: `admin/tests/test_address_book.py`

- [ ] **Step 1: Write failing tests**

```python
# admin/tests/test_address_book.py
import pytest, os, sys, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("ADMIN_PASSWORD", "test-admin-pass")
os.environ.setdefault("HTTPS_ONLY", "0")
import app as flask_app


def _create_user(client, username, password="pass12345", role="user"):
    conn = flask_app._get_api_db()
    conn.execute(
        "INSERT OR REPLACE INTO users (username, password_hash, role, is_active, created_at)"
        " VALUES (?,?,?,1,?)",
        (username, flask_app._hash_user_password(password), role, time.time()),
    )
    conn.commit()
    conn.close()


def _token(client, username, password="pass12345"):
    rv = client.post("/api/login", json={"username": username, "password": password})
    return rv.get_json()["access_token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_user_gets_own_empty_book(client):
    _create_user(client, "alice")
    tok = _token(client, "alice")
    rv = client.get("/api/ab", headers=_auth(tok))
    assert rv.status_code == 200


def test_user_saves_own_book(client):
    _create_user(client, "bob")
    tok = _token(client, "bob")
    client.post("/api/ab", json={"data": '{"peers":[{"id":"123"}]}'}, headers=_auth(tok))
    rv = client.get("/api/ab", headers=_auth(tok))
    data = rv.get_json()
    assert "123" in data["data"]


def test_books_are_isolated(client):
    _create_user(client, "alice2")
    _create_user(client, "bob2")
    tok_a = _token(client, "alice2")
    tok_b = _token(client, "bob2")
    client.post("/api/ab", json={"data": '{"peers":[{"id":"aaa"}]}'}, headers=_auth(tok_a))
    rv = client.get("/api/ab", headers=_auth(tok_b))
    # bob should not see alice's data
    assert "aaa" not in (rv.get_json() or {}).get("data", "")


def test_user_can_read_shared_book(client):
    _create_user(client, "carol", role="user")
    tok = _token(client, "carol")
    rv = client.get("/api/ab?type=shared", headers=_auth(tok))
    assert rv.status_code == 200


def test_user_cannot_write_shared_book(client):
    _create_user(client, "dave", role="user")
    tok = _token(client, "dave")
    rv = client.post("/api/ab?type=shared", json={"data": "{}"}, headers=_auth(tok))
    assert rv.status_code == 403


def test_manager_can_write_shared_book(client):
    _create_user(client, "mgr", role="manager")
    tok = _token(client, "mgr")
    rv = client.post("/api/ab?type=shared", json={"data": '{"shared":1}'}, headers=_auth(tok))
    assert rv.status_code == 200


def test_admin_can_write_shared_book(client):
    tok = _token(client, "admin", password=os.environ["ADMIN_PASSWORD"])
    rv = client.post("/api/ab?type=shared", json={"data": '{"admin":1}'}, headers=_auth(tok))
    assert rv.status_code == 200


def test_unknown_type_returns_400(client):
    tok = _token(client, "admin", password=os.environ["ADMIN_PASSWORD"])
    rv = client.get("/api/ab?type=garbage", headers=_auth(tok))
    assert rv.status_code == 400
```

- [ ] **Step 2: Run — expect FAIL**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/test_address_book.py -v
```

- [ ] **Step 3: Replace `api_ab()` (around line 835)**

```python
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
```

- [ ] **Step 4: Run — expect PASS**

```bash
python -m pytest tests/test_address_book.py -v
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2"
git add admin/app.py admin/tests/test_address_book.py
git commit -m "feat: per-user and shared address book with role-based access"
```

---

## Task 7: User management web routes

**Files:**
- Modify: `admin/app.py` — add `/users` and sub-routes
- Create: `admin/tests/test_users_panel.py`

- [ ] **Step 1: Write failing tests**

```python
# admin/tests/test_users_panel.py
import pytest, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("ADMIN_PASSWORD", "test-admin-pass")
os.environ.setdefault("HTTPS_ONLY", "0")
import app as flask_app


def _admin_session(client):
    """Return client with valid admin web session."""
    rv = client.get("/login")
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', rv.data.decode())
    csrf = m.group(1) if m else ""
    client.post("/login", data={"password": os.environ["ADMIN_PASSWORD"], "csrf_token": csrf},
                follow_redirects=True)
    return client


def test_users_page_requires_login(client):
    rv = client.get("/users")
    assert rv.status_code in (302, 401)


def test_users_page_accessible_when_logged_in(client):
    _admin_session(client)
    rv = client.get("/users")
    assert rv.status_code == 200
    assert b"admin" in rv.data


def test_create_user(client):
    _admin_session(client)
    rv = client.get("/users")
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', rv.data.decode())
    csrf = m.group(1) if m else ""
    rv = client.post("/users/new", data={
        "username": "techtest",
        "password": "securepwd1",
        "role": "user",
        "csrf_token": csrf,
    }, follow_redirects=True)
    assert rv.status_code == 200
    conn = flask_app._get_api_db()
    row = conn.execute("SELECT username FROM users WHERE username='techtest'").fetchone()
    conn.close()
    assert row is not None


def test_create_user_reserved_username_rejected(client):
    _admin_session(client)
    rv = client.get("/users")
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', rv.data.decode())
    csrf = m.group(1) if m else ""
    rv = client.post("/users/new", data={
        "username": "__shared__", "password": "validpass1",
        "role": "user", "csrf_token": csrf,
    }, follow_redirects=True)
    assert rv.status_code in (400, 200)  # either error page or redirect with flash
    conn = flask_app._get_api_db()
    row = conn.execute("SELECT username FROM users WHERE username='__shared__'").fetchone()
    conn.close()
    assert row is None


def test_create_user_short_password_rejected(client):
    _admin_session(client)
    rv = client.get("/users")
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', rv.data.decode())
    csrf = m.group(1) if m else ""
    rv = client.post("/users/new", data={
        "username": "shortpwd", "password": "short",
        "role": "user", "csrf_token": csrf,
    }, follow_redirects=True)
    conn = flask_app._get_api_db()
    row = conn.execute("SELECT username FROM users WHERE username='shortpwd'").fetchone()
    conn.close()
    assert row is None


def test_cannot_assign_admin_role(client):
    _admin_session(client)
    rv = client.get("/users")
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', rv.data.decode())
    csrf = m.group(1) if m else ""
    rv = client.post("/users/new", data={
        "username": "badactor", "password": "validpass1",
        "role": "admin", "csrf_token": csrf,
    }, follow_redirects=True)
    conn = flask_app._get_api_db()
    row = conn.execute("SELECT role FROM users WHERE username='badactor'").fetchone()
    conn.close()
    assert row is None or row[0] != "admin"


def test_reset_password_invalidates_old_token(client):
    _admin_session(client)
    # create user and log in via API
    conn = flask_app._get_api_db()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES (?,?,?,1,?)",
        ("resetme", flask_app._hash_user_password("oldpass12"), "user", time.time()),
    )
    conn.commit(); conn.close()
    rv = client.post("/api/login", json={"username": "resetme", "password": "oldpass12"})
    old_token = rv.get_json()["access_token"]
    # reset via panel
    rv = client.get("/users")
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', rv.data.decode())
    csrf = m.group(1) if m else ""
    client.post("/users/resetme/password", data={
        "password": "newpass12345", "csrf_token": csrf
    }, follow_redirects=True)
    # old token must be invalid
    rv2 = client.get("/api/currentUser",
                     headers={"Authorization": f"Bearer {old_token}"})
    assert rv2.status_code == 401


def test_delete_user_preserves_shared_ab(client):
    """Deleting a user must not touch the shared address book."""
    _admin_session(client)
    # Put something in the shared AB via API
    tok = client.post("/api/login",
                      json={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]}
                      ).get_json()["access_token"]
    client.post("/api/ab?type=shared",
                json={"data": '{"shared_sentinel":1}'},
                headers={"Authorization": f"Bearer {tok}"})
    # Create user and delete via panel
    conn = flask_app._get_api_db()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, is_active, created_at) VALUES (?,?,?,1,?)",
        ("todelete", flask_app._hash_user_password("delpass12"), "user", time.time()),
    )
    conn.commit(); conn.close()
    rv = client.get("/users")
    import re
    m = re.search(r'name="csrf_token" value="([^"]+)"', rv.data.decode())
    csrf = m.group(1) if m else ""
    client.post("/users/todelete/delete", data={"csrf_token": csrf}, follow_redirects=True)
    # Shared AB must still exist
    conn = flask_app._get_api_db()
    row = conn.execute("SELECT data FROM address_books WHERE owner='__shared__'").fetchone()
    conn.close()
    assert row is not None
    assert "shared_sentinel" in row[0]
    # User must be gone
    conn = flask_app._get_api_db()
    user = conn.execute("SELECT username FROM users WHERE username='todelete'").fetchone()
    conn.close()
    assert user is None
```

- [ ] **Step 2: Run — expect FAIL**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/test_users_panel.py -v
```

- [ ] **Step 3: Add user management routes to app.py (append before `if __name__ == "__main__"`)**

```python
# ── User management (web panel — admin only) ──────────────────────────────────

@app.route("/users")
@login_required
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
            # created_at is REAL (Unix epoch float) — fmt_dt expects a string, format directly
            "created_at": datetime.fromtimestamp(r[3], tz=timezone.utc).strftime("%Y-%m-%d %H:%M"),
        }
        for r in rows
    ]
    return render_template("users.html", users=user_list)


@app.route("/users/new", methods=["POST"])
@login_required
def users_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role     = request.form.get("role", "user")
    if username == "__shared__" or not username:
        return render_template("users.html",
            error="Username inválido.", users=_users_list_data()), 400
    if len(password) < 8:
        return render_template("users.html",
            error="Senha deve ter ao menos 8 caracteres.", users=_users_list_data()), 400
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
    return redirect(url_for("users_list"))


@app.route("/users/<username>/role", methods=["POST"])
@login_required
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
    return redirect(url_for("users_list"))


@app.route("/users/<username>/password", methods=["POST"])
@login_required
def users_reset_password(username):
    password = request.form.get("password", "")
    if len(password) < 8:
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
    return redirect(url_for("users_list"))


@app.route("/users/<username>/toggle", methods=["POST"])
@login_required
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
    conn.close()
    return redirect(url_for("users_list"))


@app.route("/users/<username>/delete", methods=["POST"])
@login_required
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
    return redirect(url_for("users_list"))


@app.route("/users/<username>/ab")
@login_required
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
            # created_at is REAL (Unix epoch float) — fmt_dt expects a string, so format directly
            "created_at": datetime.fromtimestamp(r[3], tz=timezone.utc).strftime("%Y-%m-%d %H:%M"),
        }
        for r in rows
    ]
```

- [ ] **Step 4: Run — expect PASS**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/test_users_panel.py -v
```

- [ ] **Step 5: Run full test suite**

```bash
python -m pytest tests/ -v
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2"
git add admin/app.py admin/tests/test_users_panel.py
git commit -m "feat: user management web routes (create, role, password, toggle, delete, view ab)"
```

---

## Task 8: `users.html` template

**Files:**
- Create: `admin/templates/users.html`

- [ ] **Step 1: Create template**

```html
{% extends "base.html" %}
{% block title %}Ubuntu Desk — Usuários{% endblock %}
{% block page_title %}Usuários{% endblock %}

{% block content %}
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
  <div></div>
  <button class="btn btn-cyan" data-action="open-modal" data-target="modal-new-user">+ Novo Usuário</button>
</div>

{% if error %}
<div class="alert alert-warn">{{ error }}</div>
{% endif %}

{% if view_ab %}
<div class="card" style="margin-bottom:20px;">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
    <h3 style="font-size:15px;">Address Book — {{ view_ab.username }}</h3>
    <a href="{{ url_for('users_list') }}" class="btn btn-ghost" style="font-size:12px;">Fechar</a>
  </div>
  <pre style="background:var(--bg);padding:14px;border-radius:8px;font-size:12px;overflow-x:auto;color:var(--muted);max-height:300px;">{{ view_ab.data }}</pre>
</div>
{% endif %}

<div class="card">
  {% if users %}
  <table>
    <thead>
      <tr>
        <th>Usuário</th>
        <th>Role</th>
        <th>Status</th>
        <th>Criado em</th>
        <th>Ações</th>
      </tr>
    </thead>
    <tbody>
      {% for u in users %}
      <tr>
        <td style="font-weight:600;">{{ u.username }}</td>
        <td>
          {% if u.role == 'admin' %}
            <span class="badge" style="background:rgba(6,182,212,0.15);color:var(--cyan);">admin</span>
          {% elif u.role == 'manager' %}
            <span class="badge" style="background:rgba(251,191,36,0.15);color:#FCD34D;">manager</span>
          {% else %}
            <span class="badge badge-offline">user</span>
          {% endif %}
        </td>
        <td>
          {% if u.is_active %}
            <span class="badge badge-online">Ativo</span>
          {% else %}
            <span class="badge" style="background:rgba(248,113,113,0.15);color:var(--red);">Inativo</span>
          {% endif %}
        </td>
        <td style="color:var(--muted);">{{ u.created_at }}</td>
        <td>
          <div style="display:flex;gap:6px;flex-wrap:wrap;">
            {% if u.username != 'admin' %}
            <!-- Role -->
            <form method="POST" action="{{ url_for('users_set_role', username=u.username) }}" style="display:inline;">
              <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
              <select name="role" class="btn btn-ghost" style="padding:4px 8px;font-size:12px;cursor:pointer;"
                      data-action="submit-on-change">
                <option value="user"    {% if u.role=='user' %}selected{% endif %}>user</option>
                <option value="manager" {% if u.role=='manager' %}selected{% endif %}>manager</option>
              </select>
            </form>
            <!-- Reset senha -->
            <button class="btn btn-ghost" style="font-size:12px;"
                    data-action="open-modal" data-target="modal-reset-{{ u.username }}">Senha</button>
            <!-- Toggle -->
            <form method="POST" action="{{ url_for('users_toggle', username=u.username) }}" style="display:inline;">
              <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
              <button class="btn btn-ghost" style="font-size:12px;">
                {% if u.is_active %}Desativar{% else %}Reativar{% endif %}
              </button>
            </form>
            <!-- Delete -->
            <form method="POST" action="{{ url_for('users_delete', username=u.username) }}" style="display:inline;"
                  data-action="confirm-delete" data-name="{{ u.username }}">
              <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
              <button class="btn" style="background:rgba(248,113,113,0.15);color:var(--red);font-size:12px;">Excluir</button>
            </form>
            {% endif %}
            <!-- Ver AB -->
            <a href="{{ url_for('users_view_ab', username=u.username) }}"
               class="btn btn-ghost" style="font-size:12px;">Ver AB</a>
          </div>

          <!-- Modal reset senha inline -->
          {% if u.username != 'admin' %}
          <div id="modal-reset-{{ u.username }}" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:100;align-items:center;justify-content:center;">
            <div class="card" style="width:360px;margin:0;">
              <h3 style="margin-bottom:16px;">Resetar senha — {{ u.username }}</h3>
              <form method="POST" action="{{ url_for('users_reset_password', username=u.username) }}">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <input type="password" name="password" placeholder="Nova senha (mín. 8 caracteres)"
                       style="width:100%;padding:10px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--text);margin-bottom:12px;">
                <div style="display:flex;gap:8px;justify-content:flex-end;">
                  <button type="button" class="btn btn-ghost" data-action="close-modal" data-target="modal-reset-{{ u.username }}">Cancelar</button>
                  <button type="submit" class="btn btn-cyan">Salvar</button>
                </div>
              </form>
            </div>
          </div>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">
    <div class="icon">👤</div>
    <p>Nenhum usuário cadastrado.</p>
  </div>
  {% endif %}
</div>

<!-- Modal criar usuário -->
<div id="modal-new-user" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:100;align-items:center;justify-content:center;">
  <div class="card" style="width:400px;margin:0;">
    <h3 style="margin-bottom:16px;">Novo Usuário</h3>
    <form method="POST" action="{{ url_for('users_create') }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <input type="text" name="username" placeholder="Username"
             style="width:100%;padding:10px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--text);margin-bottom:10px;">
      <input type="password" name="password" placeholder="Senha (mín. 8 caracteres)"
             style="width:100%;padding:10px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--text);margin-bottom:10px;">
      <select name="role" style="width:100%;padding:10px;border-radius:8px;border:1px solid var(--border);background:var(--bg);color:var(--text);margin-bottom:16px;">
        <option value="user">user</option>
        <option value="manager">manager</option>
      </select>
      <div style="display:flex;gap:8px;justify-content:flex-end;">
        <button type="button" class="btn btn-ghost" data-action="close-modal" data-target="modal-new-user">Cancelar</button>
        <button type="submit" class="btn btn-cyan">Criar</button>
      </div>
    </form>
  </div>
</div>

<script nonce="{{ csp_nonce }}">
document.addEventListener('click', function(e) {
  var btn = e.target.closest('[data-action]');
  if (!btn) return;
  var action = btn.dataset.action;
  if (action === 'open-modal') {
    var modal = document.getElementById(btn.dataset.target);
    if (modal) { modal.style.display = 'flex'; }
  }
  if (action === 'close-modal') {
    var modal = document.getElementById(btn.dataset.target);
    if (modal) { modal.style.display = 'none'; }
  }
  if (action === 'confirm-delete') {
    if (!confirm('Excluir usuário "' + btn.closest('form').dataset.name + '"?')) e.preventDefault();
  }
});
document.addEventListener('change', function(e) {
  if (e.target.dataset.action === 'submit-on-change') {
    e.target.closest('form').submit();
  }
});
</script>
{% endblock %}
```

- [ ] **Step 2: Run template rendering test**

Start the app locally and open `http://localhost:8088/users` (or run the panel tests again):

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/test_users_panel.py::test_users_page_accessible_when_logged_in -v
```

Expected: PASS.

- [ ] **Step 3: Commit**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2"
git add admin/templates/users.html
git commit -m "feat: users.html template — list, create, role, password reset, toggle, delete, view AB"
```

---

## Task 9: Add "Usuários" to sidebar + final test run

**Files:**
- Modify: `admin/templates/base.html`

- [ ] **Step 1: Add sidebar link to base.html**

In `base.html`, after the API REST link (around line 248), add:

```html
      <a href="{{ url_for('users_list') }}" class="nav-item {% if request.endpoint and (request.endpoint == 'users_list' or request.endpoint.startswith('users_')) %}active{% endif %}">
        👤 &nbsp;Usuários
      </a>
```

- [ ] **Step 2: Run full test suite**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2/admin"
python -m pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 3: Update `_ACTION_CATEGORY` mapping in app.py** — add new audit actions so they categorize correctly:

Find the `_ACTION_CATEGORY` dict (around line 83) and add:

```python
    "user_created":        "admin",
    "user_role_changed":   "admin",
    "user_password_reset": "security",
    "user_deactivated":    "security",
    "user_reactivated":    "admin",
    "user_deleted":        "security",
    "ab_shared_written":   "admin",
    "ab_viewed":           "access",
```

- [ ] **Step 4: Run full test suite again**

```bash
python -m pytest tests/ -v
```

- [ ] **Step 5: Final commit**

```bash
cd "/c/Users/felip/OneDrive/Documentos/projeto 2"
git add admin/templates/base.html admin/app.py
git commit -m "feat: multi-user address book — complete implementation"
```

---

## Acceptance Criteria Checklist

After all tasks complete, verify against the spec:

- [ ] `admin` (from `.env`) can login via `/api/login`
- [ ] New `user` can login and get/save their own address book
- [ ] `user` gets 403 on `POST /api/ab?type=shared`
- [ ] `manager` can read and write shared address book
- [ ] Creating/promoting user to role `admin` returns 400
- [ ] Creating user with username `__shared__` returns 400
- [ ] Creating user with password < 8 chars is rejected
- [ ] `GET /api/ab?type=invalid` returns 400
- [ ] After deactivating user, existing token returns 401
- [ ] After password reset, previous token is invalidated
- [ ] Delete user: tokens + personal AB removed, shared AB intact
- [ ] Panel `/users` lists users with correct role and status
- [ ] Existing install migration: `address_books id=1` → `owner='__shared__'`
- [ ] All management actions appear in audit log
