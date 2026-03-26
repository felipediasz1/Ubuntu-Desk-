# admin/tests/test_dashboard.py
import pytest
import app as flask_app
from conftest import _get_csrf


def _login(client):
    csrf = _get_csrf(client)
    client.post("/login", data={"username": "admin", "password": "test-admin-pass", "csrf_token": csrf})


def test_dashboard_loads_empty(client_with_sessions):
    _login(client_with_sessions)
    rv = client_with_sessions.get("/")
    assert rv.status_code == 200
    assert b"Registrados" in rv.data
    assert b"Online" in rv.data


def test_dashboard_sessions_today_count(client_with_sessions):
    _login(client_with_sessions)
    from datetime import date
    today = date.today().isoformat()
    conn = flask_app._get_sessions_db()
    conn.execute("INSERT INTO sessions (peer_from, peer_to, started_at) VALUES (?,?,?)", ("A", "B", f"{today} 10:00:00"))
    conn.execute("INSERT INTO sessions (peer_from, peer_to, started_at) VALUES (?,?,?)", ("C", "D", f"{today} 11:00:00"))
    conn.commit()
    conn.close()
    rv = client_with_sessions.get("/")
    assert rv.status_code == 200
    # Os 2 contadores devem aparecer na página (stat cards)
    assert b"2" in rv.data


def test_dashboard_chart_data_in_response(client_with_sessions):
    _login(client_with_sessions)
    from datetime import date
    today = date.today().isoformat()
    conn = flask_app._get_sessions_db()
    conn.execute("INSERT INTO sessions (peer_from, peer_to, started_at) VALUES (?,?,?)", ("X", "Y", f"{today} 09:00:00"))
    conn.commit()
    conn.close()
    rv = client_with_sessions.get("/")
    # Chart.js data deve estar na resposta como JSON embutido
    assert today.encode() in rv.data
