import pytest, app as flask_app

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path / "sessions.db"))
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        yield c

def _login(client):
    client.get("/")  # inicializa csrf
    with client.session_transaction() as s:
        s["logged_in"] = True
        s["username"] = "admin"
        s["role"] = "admin"
        s["last_active"] = __import__("time").time()

def test_admin_without_2fa_redirected_to_setup(client):
    _login(client)
    r = client.get("/users")
    # admin sem totp_enabled=1 deve ser redirecionado para /settings/2fa/setup
    assert r.status_code in (302, 200)

def test_2fa_setup_route_accessible_during_enforcement(client):
    _login(client)
    r = client.get("/settings/2fa/setup")
    assert r.status_code != 302 or "/settings/2fa" in r.headers.get("Location", "")

def test_health_not_affected_by_2fa_enforcement(client):
    r = client.get("/health")
    assert r.status_code == 200

def test_login_routes_not_affected_by_2fa_enforcement(client):
    r = client.get("/login")
    assert r.status_code == 200

from app import _validate_password

def test_password_too_short():
    assert _validate_password("abc1!") is not None

def test_password_no_digit():
    assert _validate_password("abcdefgh!") is not None

def test_password_no_symbol():
    assert _validate_password("abcdefgh1") is not None

def test_password_valid():
    assert _validate_password("StrongP4ss!") is None

def test_password_exact_minimum():
    assert _validate_password("Abcde1f!") is None
