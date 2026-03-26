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
        "password": "SecurePwd1!",
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
        "password": "NewPass123!", "csrf_token": csrf
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
