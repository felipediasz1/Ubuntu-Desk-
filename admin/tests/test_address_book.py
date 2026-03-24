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
    assert rv.status_code == 200
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
