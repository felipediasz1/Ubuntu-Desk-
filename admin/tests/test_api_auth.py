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
    data = rv.get_json()
    assert data["name"] == "admin"
    assert data["is_admin"] is True


def test_expired_token_rejected(client):
    """Token older than 30 days must be rejected."""
    rv = _login(client)
    token = rv.get_json()["access_token"]
    # Manually backdate the token's created_at to 31 days ago
    conn = flask_app._get_api_db()
    conn.execute(
        "UPDATE api_tokens SET created_at = ? WHERE token = ?",
        (time.time() - 31 * 86400, token),
    )
    conn.commit()
    conn.close()
    rv2 = client.get("/api/currentUser", headers={"Authorization": f"Bearer {token}"})
    assert rv2.status_code == 401
