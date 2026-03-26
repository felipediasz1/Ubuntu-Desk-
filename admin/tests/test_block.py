# admin/tests/test_block.py
import pytest
import app as flask_app
from conftest import _get_csrf


def _login(client):
    csrf = _get_csrf(client)
    client.post("/login", data={"username": "admin", "password": "test-admin-pass", "csrf_token": csrf})


def _insert_peer(peer_id="test001"):
    import sqlite3, os
    db_path = flask_app.DB_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS peer (guid TEXT, id TEXT, uuid TEXT, pk TEXT, created_at TEXT, user TEXT, status INTEGER, note TEXT, info TEXT, blocked INTEGER DEFAULT 0)")
    conn.execute("INSERT OR IGNORE INTO peer (guid, id, status, note, info) VALUES (?,?,0,'','')", (peer_id, peer_id))
    conn.commit()
    conn.close()


def test_block_peer(client, tmp_path):
    flask_app.DB_PATH = str(tmp_path / "db_v2.sqlite3")
    _insert_peer("test001")
    _login(client)
    csrf = _get_csrf(client)
    rv = client.post("/peers/test001/block",
                     data={"csrf_token": csrf},
                     follow_redirects=True)
    assert rv.status_code == 200
    import sqlite3
    conn = sqlite3.connect(flask_app.DB_PATH)
    row = conn.execute("SELECT blocked FROM peer WHERE id=?", ("test001",)).fetchone()
    conn.close()
    assert row[0] == 1


def test_unblock_peer(client, tmp_path):
    flask_app.DB_PATH = str(tmp_path / "db_v2.sqlite3")
    _insert_peer("test001")
    _login(client)
    csrf = _get_csrf(client)
    # Bloquear primeiro
    client.post("/peers/test001/block", data={"csrf_token": csrf})
    csrf2 = _get_csrf(client)
    rv = client.post("/peers/test001/unblock",
                     data={"csrf_token": csrf2},
                     follow_redirects=True)
    import sqlite3
    conn = sqlite3.connect(flask_app.DB_PATH)
    row = conn.execute("SELECT blocked FROM peer WHERE id=?", ("test001",)).fetchone()
    conn.close()
    assert row[0] == 0
