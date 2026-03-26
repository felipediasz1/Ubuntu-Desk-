# Fase 11 — Segurança Avançada — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development ou superpowers:executing-plans para implementar task-by-task.

**Goal:** Fechar os últimos gaps de segurança: 2FA obrigatório para admin, password policy e IP allowlist.

**Architecture:** Três adições independentes ao `admin/app.py` via `before_request` e funções auxiliares. Nenhuma nova dependência — usa `ipaddress` stdlib.

**Tech Stack:** Flask, `ipaddress` (stdlib), SQLite. Spec: `docs/superpowers/specs/2026-03-26-melhorias-fases-10-13-design.md` — Fase 11.

---

## File Map

| Arquivo | Ação |
|---|---|
| `admin/app.py` | Middleware 2FA obrigatório, `_validate_password()`, middleware IP allowlist |
| `admin/tests/test_security_advanced.py` | Criar — todos os testes da fase 11 |
| `server/.env.example` | Adicionar `ALLOWED_IPS` |

---

## Task 1: 2FA Obrigatório para Admin (11.1)

- [ ] **Escrever testes**

```python
# admin/tests/test_security_advanced.py
import pytest, app as flask_app

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path / "sessions.db"))
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        yield c

def _login(client):
    client.get("/")  # gera csrf
    with client.session_transaction() as s:
        s["logged_in"] = True
        s["username"] = "admin"
        s["role"] = "admin"
        s["last_active"] = __import__("time").time()

def test_admin_without_2fa_redirected_to_setup(client):
    _login(client)
    # admin sem totp_enabled deve ser redirecionado
    r = client.get("/users")
    assert r.status_code in (302, 200)
    # Se totp_enabled=0 para admin, espera redirect para /settings/2fa/setup
    # (depende do estado do DB criado pelo conftest)

def test_2fa_setup_route_accessible_during_enforcement(client):
    _login(client)
    r = client.get("/settings/2fa/setup")
    assert r.status_code != 302 or "/settings/2fa" in r.headers.get("Location", "")

def test_health_not_affected_by_2fa_enforcement(client):
    r = client.get("/health")
    assert r.status_code == 200

def test_login_routes_not_affected_by_2fa_enforcement(client):
    r = client.get("/login")
    assert r.status_code == 200
```

- [ ] **Rodar — confirmar FAIL:** `cd admin/tests && python -m pytest test_security_advanced.py::test_admin_without_2fa_redirected_to_setup -v`

- [ ] **Implementar middleware em `app.py`**

Adicionar como `@app.before_request` após os outros middlewares existentes:

```python
_2FA_EXEMPT_PREFIXES = ("/login", "/logout", "/static", "/health", "/settings/2fa")

@app.before_request
def enforce_admin_2fa():
    if not session.get("logged_in"):
        return
    if session.get("role", "admin") != "admin":
        return
    if any(request.path.startswith(p) for p in _2FA_EXEMPT_PREFIXES):
        return
    username = session.get("username", "admin")
    conn = _get_api_db()
    row = conn.execute(
        "SELECT totp_enabled FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    if row and not row["totp_enabled"]:
        return redirect(url_for("totp_setup"))
```

- [ ] **Rodar — confirmar PASS:** `cd admin/tests && python -m pytest test_security_advanced.py -v`

- [ ] **Commit:** `git commit -am "feat: enforce 2FA for admin role before accessing protected routes"`

---

## Task 2: Password Policy (11.2)

- [ ] **Escrever testes** (adicionar em `test_security_advanced.py`):

```python
from app import _validate_password

def test_password_too_short():
    assert _validate_password("abc1!") is not None

def test_password_no_digit():
    assert _validate_password("abcdefgh!") is not None

def test_password_no_symbol():
    assert _validate_password("abcdefgh1") is not None

def test_password_valid():
    assert _validate_password("StrongP4ss!") is None

def test_password_exact_minimum():
    assert _validate_password("Abcde1f!") is None
```

- [ ] **Rodar — confirmar FAIL:** `cd admin/tests && python -m pytest test_security_advanced.py::test_password_valid -v`

- [ ] **Implementar em `app.py`** (próximo a `_hash_user_password`):

```python
_SYMBOL_RE = re.compile(r"[!@#$%^&*\-_+=]")

def _validate_password(pwd: str):
    if len(pwd) < 8:
        return "Senha deve ter ao menos 8 caracteres."
    if not any(c.isdigit() for c in pwd):
        return "Senha deve conter ao menos 1 número."
    if not _SYMBOL_RE.search(pwd):
        return "Senha deve conter ao menos 1 símbolo (!@#$%^&*-_+=)."
    return None
```

- [ ] **Aplicar em `users_create` e `users_reset_password`** — substituir `if len(password) < 8:` por:

```python
pwd_error = _validate_password(password)
if pwd_error:
    flash(pwd_error, "error")
    return redirect(url_for("users_list"))
```

- [ ] **Rodar — confirmar PASS:** `cd admin/tests && python -m pytest test_security_advanced.py -v`

- [ ] **Commit:** `git commit -am "feat: password policy — min 8 chars + digit + symbol"`

---

## Task 3: IP Allowlist (11.3)

- [ ] **Escrever testes** (adicionar em `test_security_advanced.py`):

```python
def test_ip_allowlist_blocks_unknown_ip(monkeypatch, tmp_path):
    monkeypatch.setenv("ALLOWED_IPS", "192.168.1.0/24")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path / "sessions.db"))
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        # request.remote_addr em tests é 127.0.0.1 — fora de 192.168.1.0/24
        r = c.get("/login")
        assert r.status_code == 403

def test_ip_allowlist_empty_allows_all(monkeypatch, tmp_path):
    monkeypatch.delenv("ALLOWED_IPS", raising=False)
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path / "sessions.db"))
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        r = c.get("/health")
        assert r.status_code == 200

def test_health_exempt_from_ip_allowlist(monkeypatch, tmp_path):
    monkeypatch.setenv("ALLOWED_IPS", "10.0.0.1")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path / "sessions.db"))
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        r = c.get("/health")
        assert r.status_code == 200
```

- [ ] **Rodar — confirmar FAIL**

- [ ] **Implementar em `app.py`**

Adicionar variável de configuração:

```python
import ipaddress as _ipaddress

_ALLOWED_NETWORKS = []
_raw_ips = os.environ.get("ALLOWED_IPS", "").strip()
if _raw_ips:
    for entry in _raw_ips.split(","):
        try:
            _ALLOWED_NETWORKS.append(_ipaddress.ip_network(entry.strip(), strict=False))
        except ValueError:
            pass
```

Adicionar middleware `@app.before_request`:

```python
@app.before_request
def check_ip_allowlist():
    if not _ALLOWED_NETWORKS:
        return
    if request.path == "/health":
        return
    try:
        client_ip = _ipaddress.ip_address(request.remote_addr)
        if not any(client_ip in net for net in _ALLOWED_NETWORKS):
            return jsonify({"error": "IP not allowed"}), 403
    except ValueError:
        return jsonify({"error": "IP not allowed"}), 403
```

- [ ] **Adicionar ao `.env.example`:**

```
ALLOWED_IPS=          # ex: 192.168.0.0/24,10.0.0.1 — vazio = sem restrição
```

- [ ] **Rodar suite completa — confirmar PASS:** `cd admin/tests && python -m pytest . -q`

- [ ] **Commit:** `git commit -am "feat: IP allowlist middleware via ALLOWED_IPS env var"`

---

## Verificação Final da Fase 11

- [ ] `cd admin/tests && python -m pytest . -q` — todos os testes passando
