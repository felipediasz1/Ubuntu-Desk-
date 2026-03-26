# admin/tests/test_2fa.py
import pytest
import pyotp
import app as flask_app
from conftest import _get_csrf


def _login(client, password="test-admin-pass"):
    csrf = _get_csrf(client)
    return client.post("/login", data={"username": "admin", "password": password, "csrf_token": csrf}, follow_redirects=True)


def test_2fa_not_shown_when_disabled(client):
    rv = _login(client)
    # Sem 2FA ativo, login vai direto para o dashboard
    assert rv.status_code == 200
    assert b"totp" not in rv.data.lower()


def test_setup_2fa_returns_qr(client):
    _login(client)
    rv = client.get("/settings/2fa/setup")
    assert rv.status_code == 200
    assert b"data:image/png;base64" in rv.data


def test_enable_2fa_with_valid_code(client):
    _login(client)
    # Gerar secret e código válido
    secret = pyotp.random_base32()
    # Simular que o painel gerou esse secret e colocou na sessão
    with client.session_transaction() as sess:
        sess["pending_totp_secret"] = secret
    totp = pyotp.TOTP(secret)
    csrf = _get_csrf(client)
    rv = client.post("/settings/2fa/enable",
                     data={"code": totp.now(), "csrf_token": csrf},
                     follow_redirects=True)
    assert rv.status_code == 200
    # Verificar que totp_enabled=1 no DB
    conn = flask_app._get_api_db()
    row = conn.execute("SELECT totp_enabled FROM users WHERE username=?", ("admin",)).fetchone()
    conn.close()
    assert row["totp_enabled"] == 1


def test_login_requires_totp_when_enabled(client):
    _login(client)
    secret = pyotp.random_base32()
    with client.session_transaction() as sess:
        sess["pending_totp_secret"] = secret
    totp = pyotp.TOTP(secret)
    csrf = _get_csrf(client)
    client.post("/settings/2fa/enable", data={"code": totp.now(), "csrf_token": csrf})
    # Fazer logout e tentar login novamente
    client.get("/logout")
    csrf2 = _get_csrf(client)
    rv = client.post("/login", data={"username": "admin", "password": "test-admin-pass", "csrf_token": csrf2})
    # Deve redirecionar para tela TOTP, não para o dashboard
    assert rv.status_code == 302
    assert "totp" in rv.headers["Location"]
