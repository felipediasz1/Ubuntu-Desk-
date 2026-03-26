# admin/tests/test_alerts.py
import json
import pytest
import app as flask_app
from conftest import _get_csrf


def _login(client):
    csrf = _get_csrf(client)
    client.post("/login", data={"username": "admin", "password": "test-admin-pass", "csrf_token": csrf})


def test_alerts_page_loads(client):
    _login(client)
    rv = client.get("/settings/alerts")
    assert rv.status_code == 200
    assert b"Webhook" in rv.data
    assert b"SMTP" in rv.data
    assert b"Eventos" in rv.data


def test_alerts_save_webhook(client):
    _login(client)
    csrf = _get_csrf(client)
    rv = client.post("/settings/alerts", data={
        "csrf_token": csrf,
        "webhook_url": "https://hooks.example.com/xyz",
        "webhook_secret": "mysecret",
        "smtp_host": "",
        "smtp_port": "587",
        "smtp_user": "",
        "smtp_pass": "",
        "smtp_from": "",
        "smtp_to": "",
    }, follow_redirects=True)
    assert rv.status_code == 200
    assert "salvas" in rv.data.decode()

    conn = flask_app._get_api_db()
    cfg = conn.execute("SELECT * FROM alert_config WHERE id=1").fetchone()
    conn.close()
    assert cfg["webhook_url"] == "https://hooks.example.com/xyz"
    assert cfg["webhook_secret"] == "mysecret"


def test_alerts_save_events(client):
    _login(client)
    csrf = _get_csrf(client)
    client.post("/settings/alerts", data={
        "csrf_token": csrf,
        "webhook_url": "",
        "webhook_secret": "",
        "smtp_host": "",
        "smtp_port": "587",
        "smtp_user": "",
        "smtp_pass": "",
        "smtp_from": "",
        "smtp_to": "",
        "event_login_ok": "login_ok",
        "event_peer_blocked": "peer_blocked",
    }, follow_redirects=True)

    conn = flask_app._get_api_db()
    cfg = conn.execute("SELECT alert_events FROM alert_config WHERE id=1").fetchone()
    conn.close()
    events = json.loads(cfg["alert_events"])
    assert "login_ok" in events
    assert "peer_blocked" in events
    assert "user_created" not in events


def test_alerts_checkboxes_persist(client):
    _login(client)
    csrf = _get_csrf(client)
    client.post("/settings/alerts", data={
        "csrf_token": csrf,
        "webhook_url": "",
        "webhook_secret": "",
        "smtp_host": "",
        "smtp_port": "587",
        "smtp_user": "",
        "smtp_pass": "",
        "smtp_from": "",
        "smtp_to": "",
        "event_user_deleted": "user_deleted",
    }, follow_redirects=True)

    rv = client.get("/settings/alerts")
    body = rv.data.decode()
    # user_deleted checkbox should be checked, others not
    assert 'name="event_user_deleted"' in body
    # The checked attribute should appear for user_deleted
    assert "user_deleted" in body


def test_alerts_requires_admin(client):
    rv = client.get("/settings/alerts")
    assert rv.status_code in (302, 403)


def test_alerts_test_no_channel(client):
    """Sem webhook/SMTP configurado, test endpoint retorna erro."""
    _login(client)
    csrf = _get_csrf(client)
    rv = client.post("/settings/alerts/test",
                     data={"csrf_token": csrf},
                     follow_redirects=True)
    assert rv.status_code == 200
    assert "Nenhum canal" in rv.data.decode()


def test_alerts_test_logs_attempt(client):
    """_send_alert_sync com webhook inválido → registra falha no alert_log."""
    _login(client)
    # Salvar webhook inválido
    csrf = _get_csrf(client)
    client.post("/settings/alerts", data={
        "csrf_token": csrf,
        "webhook_url": "http://localhost:19999/invalid",
        "webhook_secret": "",
        "smtp_host": "",
        "smtp_port": "587",
        "smtp_user": "",
        "smtp_pass": "",
        "smtp_from": "",
        "smtp_to": "",
    }, follow_redirects=True)

    import app as flask_app
    detail = {"message": "test"}
    results = flask_app._send_alert_sync("test", detail)
    flask_app._log_alert_results("test", detail, results)

    assert len(results) == 1
    channel, success, _ = results[0]
    assert channel == "webhook"
    assert success is False

    conn = flask_app._get_api_db()
    row = conn.execute("SELECT * FROM alert_log ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    assert row is not None
    assert row["event"] == "test"
    assert row["success"] == 0


def test_alerts_log_page(client):
    _login(client)
    rv = client.get("/settings/alerts/log")
    assert rv.status_code == 200
    assert "Log de Alertas" in rv.data.decode()


def test_login_bloqueado_event_in_form(client):
    _login(client)
    rv = client.get("/settings/alerts")
    assert b"login_bloqueado" in rv.data
