# admin/tests/test_history.py
import pytest
from conftest import _get_csrf
import app as flask_app


def _login(client):
    csrf = _get_csrf(client)
    client.post("/login", data={"username": "admin", "password": "test-admin-pass", "csrf_token": csrf})


def test_history_requires_login(client_with_sessions):
    rv = client_with_sessions.get("/history")
    assert rv.status_code == 302
    assert "/login" in rv.headers["Location"]


def test_history_empty(client_with_sessions):
    _login(client_with_sessions)
    rv = client_with_sessions.get("/history")
    assert rv.status_code == 200
    assert "Nenhuma sessão" in rv.data.decode()


def test_history_shows_session(client_with_sessions):
    _login(client_with_sessions)
    conn = flask_app._get_sessions_db()
    conn.execute("INSERT INTO sessions (peer_from, peer_to, started_at) VALUES (?,?,?)",
                 ("111111", "999999", "2026-03-24 10:00:00"))
    conn.commit()
    conn.close()
    rv = client_with_sessions.get("/history")
    assert b"111111" in rv.data
    assert b"999999" in rv.data


def test_history_filter_by_peer(client_with_sessions):
    _login(client_with_sessions)
    conn = flask_app._get_sessions_db()
    conn.execute("INSERT INTO sessions (peer_from, peer_to, started_at) VALUES (?,?,?)", ("AAA", "BBB", "2026-03-24 10:00:00"))
    conn.execute("INSERT INTO sessions (peer_from, peer_to, started_at) VALUES (?,?,?)", ("CCC", "DDD", "2026-03-24 11:00:00"))
    conn.commit()
    conn.close()
    rv = client_with_sessions.get("/history?peer=AAA")
    assert b"AAA" in rv.data
    assert b"CCC" not in rv.data


def test_history_pagination(client_with_sessions):
    _login(client_with_sessions)
    conn = flask_app._get_sessions_db()
    for i in range(55):
        conn.execute("INSERT INTO sessions (peer_from, peer_to, started_at) VALUES (?,?,?)",
                     (f"{i:06d}", "000000", "2026-03-24 10:00:00"))
    conn.commit()
    conn.close()
    rv = client_with_sessions.get("/history")
    assert "Próxima".encode() in rv.data
