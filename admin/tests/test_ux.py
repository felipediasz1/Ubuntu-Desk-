import pytest, app as flask_app

@pytest.fixture
def auth_client(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path / "sessions.db"))
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        with c.session_transaction() as s:
            s["logged_in"] = True
            s["username"] = "admin"
            s["role"] = "admin"
            s["last_active"] = __import__("time").time()
        yield c

def test_sort_invalid_column_ignored(auth_client):
    r = auth_client.get("/?sort=DROP+TABLE--&dir=asc")
    assert r.status_code == 200

def test_sort_valid_column_returns_200(auth_client):
    r = auth_client.get("/?sort=status&dir=asc")
    assert r.status_code == 200

def test_sort_dir_invalid_defaults_asc(auth_client):
    r = auth_client.get("/?sort=status&dir=DROP")
    assert r.status_code == 200
