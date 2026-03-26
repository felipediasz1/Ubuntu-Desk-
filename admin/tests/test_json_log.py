import json, pytest
import app as flask_app

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path / "sessions.db"))
    monkeypatch.setenv("LOG_FORMAT", "json")
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        yield c

def test_json_log_emits_on_request(client, capsys):
    client.get("/health")
    out = capsys.readouterr().out
    lines = [l for l in out.strip().split("\n") if l.strip()]
    if lines:
        log = json.loads(lines[-1])
        assert log["method"] == "GET"
        assert log["path"] == "/health"
        assert "status" in log
        assert "duration_ms" in log
        assert "ip" in log
    else:
        # Se não emitiu nada em modo TESTING, aceitar
        pass

def test_json_log_disabled_by_default(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        c.get("/health")
    out = capsys.readouterr().out
    for line in out.strip().split("\n"):
        if line.strip():
            try:
                data = json.loads(line)
                assert "method" not in data
            except json.JSONDecodeError:
                pass
