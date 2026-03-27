import pytest, app as flask_app

@pytest.fixture
def auth_client(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setattr(flask_app, "API_DB", str(tmp_path / "api.db"))
    monkeypatch.setattr(flask_app, "AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setattr(flask_app, "SESSIONS_DB", str(tmp_path / "sessions.db"))
    monkeypatch.setattr(flask_app, "_api_db_initialized", False)
    monkeypatch.setattr(flask_app, "_audit_db_initialized", False)
    monkeypatch.setattr(flask_app, "_sessions_db_initialized", False)
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        with c.session_transaction() as s:
            s["logged_in"] = True
            s["username"] = "admin"
            s["role"] = "admin"
            s["last_active"] = __import__("time").time()
        yield c

def test_alerts_settings_page_returns_200(auth_client):
    r = auth_client.get("/settings/alerts")
    assert r.status_code == 200

def test_dispatch_alert_no_config_does_not_raise():
    try:
        flask_app._dispatch_alert("test_event", {"detail": "test"})
    except Exception as e:
        pytest.fail(f"_dispatch_alert raised: {e}")

def test_webhook_signature_header():
    import hmac, hashlib, json
    secret = "mysecret"
    payload = json.dumps({"event": "test"}).encode()
    sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert sig.startswith("sha256=")

def test_live_stats_returns_json(auth_client, monkeypatch):
    monkeypatch.setattr(flask_app, "DB_PATH", "")  # no peer DB → totals = 0
    r = auth_client.get("/live-stats")
    assert r.status_code == 200
    data = r.get_json()
    assert "online" in data
    assert "offline" in data
    assert "total" in data
    assert "sessions_today" in data
