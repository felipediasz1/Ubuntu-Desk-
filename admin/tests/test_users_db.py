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


@pytest.fixture
def tmp_dbs(tmp_path, monkeypatch):
    monkeypatch.setattr(flask_app, "API_DB", str(tmp_path / "api.db"))
    monkeypatch.setattr(flask_app, "_api_db_initialized", False)
    yield
    monkeypatch.setattr(flask_app, "_api_db_initialized", False)


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
