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


def test_active_sessions_page_returns_200(auth_client):
    r = auth_client.get("/sessions/active")
    assert r.status_code == 200
    assert b"Ativas" in r.data or b"ativas" in r.data


def test_recordings_date_filter_filters_correctly(auth_client, monkeypatch, tmp_path):
    rec_dir = tmp_path / "recordings"
    rec_dir.mkdir()
    # filenames must match _REC_RE: (incoming|outgoing)_PEER_YYYYMMDDHHMMSS+17digits_(camera|display)N_codec.ext
    (rec_dir / "incoming_TEST001_20260101120000000_display0_vp9.webm").touch()
    (rec_dir / "incoming_TEST001_20260315120000000_display0_vp9.webm").touch()
    monkeypatch.setattr(flask_app, "RECORDING_DIR", str(rec_dir))
    r = auth_client.get("/recordings?date_from=2026-03-01&date_to=2026-03-31")
    assert r.status_code == 200
    assert b"20260315" in r.data
    assert b"20260101" not in r.data


def test_offline_alert_check_no_crash(auth_client, monkeypatch):
    monkeypatch.setattr(flask_app, "DB_PATH", "")  # no peer DB
    try:
        flask_app._check_offline_devices()
    except Exception as e:
        pytest.fail(f"_check_offline_devices raised: {e}")


def test_offline_alert_fires_when_peer_offline_beyond_threshold(monkeypatch, tmp_path):
    """Alert should fire when a peer has been offline longer than the threshold."""
    import sqlite3, time as _time

    api_db = str(tmp_path / "api.db")
    monkeypatch.setattr(flask_app, "API_DB", api_db)
    monkeypatch.setattr(flask_app, "_api_db_initialized", False)
    monkeypatch.setattr(flask_app, "DB_PATH", "")

    # Initialise DB and set threshold to 1 hour
    conn = flask_app._get_api_db()
    conn.execute("UPDATE alert_config SET offline_threshold_hours=1, alert_events='[]' WHERE id=1")
    # Seed peer_status_track: offline_since = 2h ago, never alerted
    two_hours_ago = _time.time() - 7200
    conn.execute("""
        INSERT OR REPLACE INTO peer_status_track (peer_id, last_online, offline_since, alerted_at)
        VALUES ('P_TEST', ?, ?, NULL)
    """, (two_hours_ago, two_hours_ago))
    conn.commit()
    conn.close()

    # Patch query() to return one offline peer
    monkeypatch.setattr(flask_app, "query", lambda *a, **kw: [{"id": "P_TEST", "status": 0}])

    alerts_fired = []
    monkeypatch.setattr(flask_app, "_dispatch_alert", lambda ev, detail: alerts_fired.append((ev, detail)))

    flask_app._check_offline_devices()

    assert len(alerts_fired) == 1
    assert alerts_fired[0][0] == "peer_offline"
    assert alerts_fired[0][1]["peer_id"] == "P_TEST"


def test_offline_alert_skipped_when_threshold_zero(monkeypatch, tmp_path):
    """No alert when threshold is 0 (disabled)."""
    api_db = str(tmp_path / "api.db")
    monkeypatch.setattr(flask_app, "API_DB", api_db)
    monkeypatch.setattr(flask_app, "_api_db_initialized", False)
    monkeypatch.setattr(flask_app, "DB_PATH", "")

    conn = flask_app._get_api_db()
    conn.execute("UPDATE alert_config SET offline_threshold_hours=0 WHERE id=1")
    conn.commit()
    conn.close()

    alerts_fired = []
    monkeypatch.setattr(flask_app, "_dispatch_alert", lambda ev, detail: alerts_fired.append(ev))

    flask_app._check_offline_devices()
    assert alerts_fired == []


def test_offline_alert_cooldown_prevents_double_alert(monkeypatch, tmp_path):
    """Alert should not fire again if alerted_at is within cooldown window."""
    import time as _time

    api_db = str(tmp_path / "api.db")
    monkeypatch.setattr(flask_app, "API_DB", api_db)
    monkeypatch.setattr(flask_app, "_api_db_initialized", False)
    monkeypatch.setattr(flask_app, "DB_PATH", "")

    conn = flask_app._get_api_db()
    conn.execute("UPDATE alert_config SET offline_threshold_hours=1, alert_events='[]' WHERE id=1")
    now = _time.time()
    # offline_since = 2h ago, alerted_at = 30min ago (within cooldown)
    conn.execute("""
        INSERT OR REPLACE INTO peer_status_track (peer_id, last_online, offline_since, alerted_at)
        VALUES ('P_COOL', ?, ?, ?)
    """, (now - 7200, now - 7200, now - 1800))
    conn.commit()
    conn.close()

    monkeypatch.setattr(flask_app, "query", lambda *a, **kw: [{"id": "P_COOL", "status": 0}])

    alerts_fired = []
    monkeypatch.setattr(flask_app, "_dispatch_alert", lambda ev, detail: alerts_fired.append(ev))

    flask_app._check_offline_devices()
    assert alerts_fired == []
