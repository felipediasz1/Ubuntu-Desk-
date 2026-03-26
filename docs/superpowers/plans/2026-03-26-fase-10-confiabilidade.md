# Fase 10 — Confiabilidade & Ops — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tornar o painel admin observável, recuperável e auditável em produção com health check, backup automático e logs estruturados.

**Architecture:** Três adições independentes ao `admin/app.py`: uma rota pública `/health`, uma thread daemon de backup SQLite com conexões isoladas, e um middleware de log JSON opcional.

**Tech Stack:** Flask, SQLite (`sqlite3.backup()`), `threading`, `logging` — tudo stdlib, sem novas dependências.

**Spec:** `docs/superpowers/specs/2026-03-26-melhorias-fases-10-13-design.md` — Fase 10

---

## File Map

| Arquivo | Ação | O que muda |
|---|---|---|
| `admin/app.py` | Modificar | Rota `/health`, thread de backup, middleware JSON log |
| `admin/tests/test_health.py` | Criar | Testes da rota /health |
| `admin/tests/test_backup.py` | Criar | Testes do backup automático |
| `admin/tests/test_json_log.py` | Criar | Testes do middleware de log |
| `server/.env.example` | Modificar | Novas vars: `LOG_FORMAT`, `BACKUP_RETENTION_DAYS`, `BACKUP_INTERVAL_HOURS` |
| `server/docker-compose.yml` | Modificar | `HEALTHCHECK` aponta para `/health` |

---

## Task 1: Health Check Endpoint (`GET /health`)

**Files:**
- Modify: `admin/app.py`
- Create: `admin/tests/test_health.py`

- [ ] **Step 1: Escrever os testes**

```python
# admin/tests/test_health.py
import pytest
import app as flask_app

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path / "sessions.db"))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "db_v2.sqlite3"))
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        yield c

def test_health_returns_200(client):
    r = client.get("/health")
    assert r.status_code == 200

def test_health_returns_json(client):
    r = client.get("/health")
    data = r.get_json()
    assert data["status"] == "ok"
    assert "db" in data
    assert "uptime_seconds" in data

def test_health_no_auth_required(client):
    # Sem cookies de sessão — deve retornar 200 mesmo assim
    r = client.get("/health")
    assert r.status_code == 200

def test_health_db_false_when_peer_db_missing(client):
    # DB_PATH não existe — campo db deve ser False mas status ainda ok
    r = client.get("/health")
    data = r.get_json()
    assert isinstance(data["db"], bool)
```

- [ ] **Step 2: Rodar — confirmar FAIL**

```bash
cd admin/tests && python -m pytest test_health.py -v
```
Esperado: `ImportError` ou `404`

- [ ] **Step 3: Implementar a rota em `app.py`**

Adicionar após a linha `_app_start_time = time.time()` (adicionar essa linha próxima ao topo, após `PORT = int(...)`):

```python
_app_start_time = time.time()

@app.route("/health")
def health():
    results = {}
    for name, path in [("api", API_DB), ("audit", AUDIT_DB), ("sessions", SESSIONS_DB)]:
        try:
            conn = sqlite3.connect(path, timeout=2)
            conn.execute("SELECT 1")
            conn.close()
            results[name] = True
        except Exception:
            results[name] = False
    # peer db é opcional (gerenciado pelo hbbs)
    peer_ok = os.path.exists(DB_PATH)
    all_ok = all(results.values())
    return jsonify({
        "status": "ok" if all_ok else "degraded",
        "db": all_ok,
        "db_detail": {**results, "peer": peer_ok},
        "uptime_seconds": int(time.time() - _app_start_time),
    }), 200 if all_ok else 503
```

- [ ] **Step 4: Garantir que `/health` é isento de todos os `before_request`**

Nos middlewares `check_session_timeout`, `check_csrf` e (futuramente) `generate_csp_nonce`, adicionar no início:

```python
if request.path == "/health":
    return
```

- [ ] **Step 5: Rodar — confirmar PASS**

```bash
cd admin/tests && python -m pytest test_health.py -v
```
Esperado: 4 testes passando

- [ ] **Step 6: Adicionar HEALTHCHECK ao docker-compose.yml**

```yaml
  admin:
    ...
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8088/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

- [ ] **Step 7: Commit**

```bash
git add admin/app.py admin/tests/test_health.py server/docker-compose.yml
git commit -m "feat: health check endpoint GET /health with DB status"
```

---

## Task 2: Backup Automático SQLite

**Files:**
- Modify: `admin/app.py`
- Create: `admin/tests/test_backup.py`
- Modify: `server/.env.example`

- [ ] **Step 1: Escrever os testes**

```python
# admin/tests/test_backup.py
import os, time, sqlite3, pytest
import app as flask_app
from app import _backup_databases, _cleanup_old_backups

def test_backup_creates_files(tmp_path, monkeypatch):
    api_db = tmp_path / "api.db"
    audit_db = tmp_path / "audit.db"
    sessions_db = tmp_path / "sessions.db"
    # criar bancos vazios
    for p in [api_db, audit_db, sessions_db]:
        sqlite3.connect(str(p)).close()
    backup_dir = tmp_path / "backups"
    monkeypatch.setattr(flask_app, "API_DB", str(api_db))
    monkeypatch.setattr(flask_app, "AUDIT_DB", str(audit_db))
    monkeypatch.setattr(flask_app, "SESSIONS_DB", str(sessions_db))
    _backup_databases(str(backup_dir))
    today = time.strftime("%Y-%m-%d")
    assert (backup_dir / today / "api.db").exists()
    assert (backup_dir / today / "audit.db").exists()
    assert (backup_dir / today / "sessions.db").exists()

def test_cleanup_removes_old_backups(tmp_path):
    # criar 10 pastas de backup fake
    for i in range(10):
        day = f"2026-01-{i+1:02d}"
        (tmp_path / day).mkdir()
    _cleanup_old_backups(str(tmp_path), retention_days=7)
    remaining = list(tmp_path.iterdir())
    assert len(remaining) <= 7

def test_backup_handles_missing_db_gracefully(tmp_path):
    # DB inexistente não deve lançar exceção
    backup_dir = tmp_path / "backups"
    try:
        _backup_databases(str(backup_dir))
    except Exception as e:
        pytest.fail(f"backup raised exception: {e}")
```

- [ ] **Step 2: Rodar — confirmar FAIL**

```bash
cd admin/tests && python -m pytest test_backup.py -v
```
Esperado: `ImportError` (funções não existem)

- [ ] **Step 3: Implementar as funções de backup em `app.py`**

Adicionar antes do bloco `if __name__ == "__main__"`:

```python
# ── Backup automático SQLite ───────────────────────────────────────────────────
BACKUP_DIR            = os.environ.get("BACKUP_DIR", os.path.join(os.path.dirname(__file__), "data", "backups"))
BACKUP_RETENTION_DAYS = int(os.environ.get("BACKUP_RETENTION_DAYS", 7))
BACKUP_INTERVAL_HOURS = int(os.environ.get("BACKUP_INTERVAL_HOURS", 24))

def _backup_databases(backup_dir: str = BACKUP_DIR):
    today = time.strftime("%Y-%m-%d")
    dest = os.path.join(backup_dir, today)
    os.makedirs(dest, exist_ok=True)
    for name, path in [("api.db", API_DB), ("audit.db", AUDIT_DB), ("sessions.db", SESSIONS_DB)]:
        if not os.path.exists(path):
            continue
        try:
            src  = sqlite3.connect(path)
            dst  = sqlite3.connect(os.path.join(dest, name))
            src.backup(dst)
            src.close()
            dst.close()
        except Exception as e:
            # Log isolado — conexão própria, nunca compartilhada com request handlers
            try:
                conn = sqlite3.connect(AUDIT_DB)
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                conn.execute(
                    "INSERT INTO audit_log (ts, action, detail, ip, category) VALUES (?,?,?,?,?)",
                    (ts, "backup_erro", f"db={name} err={e}", "system", "system")
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

def _cleanup_old_backups(backup_dir: str = BACKUP_DIR, retention_days: int = BACKUP_RETENTION_DAYS):
    if not os.path.isdir(backup_dir):
        return
    dirs = sorted(
        [d for d in os.listdir(backup_dir) if os.path.isdir(os.path.join(backup_dir, d))],
        reverse=True
    )
    for old_dir in dirs[retention_days:]:
        import shutil
        shutil.rmtree(os.path.join(backup_dir, old_dir), ignore_errors=True)

def _backup_loop():
    interval = BACKUP_INTERVAL_HOURS * 3600
    while True:
        time.sleep(interval)
        _backup_databases()
        _cleanup_old_backups()
```

- [ ] **Step 4: Iniciar a thread no startup**

No bloco `if __name__ == "__main__":`:

```python
import threading
t = threading.Thread(target=_backup_loop, daemon=True)
t.start()
```

- [ ] **Step 5: Adicionar vars ao `.env.example`**

```
BACKUP_RETENTION_DAYS=7
BACKUP_INTERVAL_HOURS=24
BACKUP_DIR=         # opcional: caminho absoluto para a pasta de backups
```

- [ ] **Step 6: Rodar — confirmar PASS**

```bash
cd admin/tests && python -m pytest test_backup.py -v
```
Esperado: 3 testes passando

- [ ] **Step 7: Commit**

```bash
git add admin/app.py admin/tests/test_backup.py server/.env.example
git commit -m "feat: automatic daily SQLite backup with configurable retention"
```

---

## Task 3: Logs Estruturados JSON

**Files:**
- Modify: `admin/app.py`
- Create: `admin/tests/test_json_log.py`
- Modify: `server/.env.example`

- [ ] **Step 1: Escrever os testes**

```python
# admin/tests/test_json_log.py
import json, io, pytest
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
    log = json.loads(out.strip().split("\n")[-1])
    assert log["method"] == "GET"
    assert log["path"] == "/health"
    assert "status" in log
    assert "duration_ms" in log
    assert "ip" in log

def test_json_log_disabled_by_default(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        c.get("/health")
    out = capsys.readouterr().out
    # Não deve ter JSON de log quando LOG_FORMAT não está configurado
    for line in out.strip().split("\n"):
        if line.strip():
            try:
                data = json.loads(line)
                assert "method" not in data
            except json.JSONDecodeError:
                pass  # texto normal, ok
```

- [ ] **Step 2: Rodar — confirmar FAIL**

```bash
cd admin/tests && python -m pytest test_json_log.py -v
```

- [ ] **Step 3: Implementar o middleware em `app.py`**

Adicionar variável de configuração após as outras constantes:

```python
LOG_FORMAT = os.environ.get("LOG_FORMAT", "").lower()
```

Adicionar no `set_security_headers` (já existente como `@app.after_request`) OU criar um after_request separado:

```python
@app.after_request
def structured_log(response):
    if LOG_FORMAT == "json":
        duration_ms = int((time.time() - g.get("req_start", time.time())) * 1000)
        import sys, json as _json
        print(_json.dumps({
            "ts":          time.strftime("%Y-%m-%d %H:%M:%S"),
            "method":      request.method,
            "path":        request.path,
            "status":      response.status_code,
            "duration_ms": duration_ms,
            "ip":          request.remote_addr,
        }), file=sys.stdout, flush=True)
    return response
```

Adicionar `g.req_start = time.time()` no `generate_csp_nonce` (já é um `before_request`):

```python
@app.before_request
def generate_csp_nonce():
    g.csp_nonce = secrets.token_hex(16)
    g.req_start  = time.time()
```

- [ ] **Step 4: Adicionar var ao `.env.example`**

```
LOG_FORMAT=          # json para logs estruturados (compatível com Grafana Loki/Datadog)
```

- [ ] **Step 5: Rodar todos os testes**

```bash
cd admin/tests && python -m pytest . -v
```
Esperado: todos passando (incluindo os 45 anteriores)

- [ ] **Step 6: Commit**

```bash
git add admin/app.py admin/tests/test_json_log.py server/.env.example
git commit -m "feat: optional JSON structured logging via LOG_FORMAT=json"
```

---

## Verificação Final da Fase 10

- [ ] Rodar suite completa: `cd admin/tests && python -m pytest . -q`
- [ ] Esperado: 45 + novos testes, todos passando
- [ ] Testar manualmente: `curl http://localhost:8088/health` deve retornar JSON sem precisar de login
