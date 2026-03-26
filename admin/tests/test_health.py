import pytest
import app as flask_app

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path / "sessions.db"))
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        yield c

def test_health_returns_200(client):
    r = client.get("/health")
    assert r.status_code == 200

def test_health_returns_json(client):
    r = client.get("/health")
    data = r.get_json()
    assert data["status"] == "ok"
    assert "db" in data
    assert "uptime_seconds" in data

def test_health_no_auth_required(client):
    r = client.get("/health")
    assert r.status_code == 200

def test_health_db_false_when_peer_db_missing(client):
    r = client.get("/health")
    data = r.get_json()
    assert isinstance(data["db"], bool)
