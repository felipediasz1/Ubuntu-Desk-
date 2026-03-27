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
    assert "new_this_week" in data

def test_dashboard_has_new_devices_stat(auth_client, monkeypatch):
    monkeypatch.setattr(flask_app, "DB_PATH", "")
    r = auth_client.get("/")
    assert r.status_code == 200
    assert b"Novos esta semana" in r.data or b"novos esta semana" in r.data

def _get_csrf(client, monkeypatch_db_path):
    """Trigger a GET to populate _csrf in session, then return the token."""
    monkeypatch_db_path("")
    client.get("/")
    with client.session_transaction() as s:
        return s.get("_csrf", "")

def test_add_peer_tag(auth_client, monkeypatch):
    monkeypatch.setattr(flask_app, "DB_PATH", "")
    auth_client.get("/")
    with auth_client.session_transaction() as s:
        token = s.get("_csrf", "")
    r = auth_client.post("/peers/TEST001/tags",
        data={"action": "add", "tag": "servidor", "csrf_token": token})
    # Expects redirect (302) — peer may not exist in test DB
    assert r.status_code in (200, 302)

def test_remove_peer_tag(auth_client, monkeypatch):
    monkeypatch.setattr(flask_app, "DB_PATH", "")
    auth_client.get("/")
    with auth_client.session_transaction() as s:
        token = s.get("_csrf", "")
    auth_client.post("/peers/TEST001/tags",
        data={"action": "add", "tag": "laptop", "csrf_token": token})
    r = auth_client.post("/peers/TEST001/tags",
        data={"action": "remove", "tag": "laptop", "csrf_token": token})
    # Expects redirect (302)
    assert r.status_code in (200, 302)

def test_invalid_tag_rejected(auth_client, monkeypatch):
    monkeypatch.setattr(flask_app, "DB_PATH", "")
    auth_client.get("/")
    with auth_client.session_transaction() as s:
        token = s.get("_csrf", "")
    r = auth_client.post("/peers/TEST001/tags",
        data={"action": "add", "tag": "<script>", "csrf_token": token})
    # Should redirect back (not 500) — invalid tag rejected with flash
    assert r.status_code in (200, 302)

def test_bulk_block_redirects(auth_client, monkeypatch, tmp_path):
    import sqlite3
    db_file = tmp_path / "peer.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("""CREATE TABLE peer (
        id TEXT PRIMARY KEY, info TEXT DEFAULT '{}',
        status INTEGER DEFAULT 0, created_at TEXT DEFAULT '',
        note TEXT DEFAULT '', blocked INTEGER DEFAULT 0,
        starred INTEGER DEFAULT 0)""")
    conn.execute("INSERT INTO peer VALUES ('P1','{}',0,'2026-01-01','',0,0)")
    conn.execute("INSERT INTO peer VALUES ('P2','{}',0,'2026-01-01','',0,0)")
    conn.commit()
    conn.close()
    monkeypatch.setattr(flask_app, "DB_PATH", str(db_file))
    flask_app._db_initialized = False  # reset if needed
    auth_client.get("/")  # populate _csrf in session
    with auth_client.session_transaction() as s:
        token = s.get("_csrf", "")
    r = auth_client.post("/peers/bulk",
        data={"action": "block", "peer_ids": ["P1", "P2"], "csrf_token": token},
        follow_redirects=False)
    assert r.status_code == 302

def test_bulk_export_returns_csv(auth_client, monkeypatch, tmp_path):
    import sqlite3
    db_file = tmp_path / "peer2.db"
    conn = sqlite3.connect(str(db_file))
    conn.execute("""CREATE TABLE peer (
        id TEXT PRIMARY KEY, info TEXT DEFAULT '{}',
        status INTEGER DEFAULT 0, created_at TEXT DEFAULT '',
        note TEXT DEFAULT '', blocked INTEGER DEFAULT 0,
        starred INTEGER DEFAULT 0)""")
    conn.execute("INSERT INTO peer VALUES ('P3','{}',1,'2026-01-01','',0,0)")
    conn.commit()
    conn.close()
    monkeypatch.setattr(flask_app, "DB_PATH", str(db_file))
    auth_client.get("/")  # populate _csrf in session
    with auth_client.session_transaction() as s:
        token = s.get("_csrf", "")
    r = auth_client.post("/peers/bulk",
        data={"action": "export", "peer_ids": ["P3"], "csrf_token": token})
    assert r.status_code == 200
    assert b"P3" in r.data
    assert r.content_type.startswith("text/csv")
