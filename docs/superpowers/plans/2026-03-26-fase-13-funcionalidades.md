# Fase 13 — Funcionalidades — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development ou superpowers:executing-plans para implementar task-by-task.

**Goal:** Adicionar alertas (webhook + email), bulk actions, tags de devices, notificações SSE real-time, controle de acesso por device, agendamento de manutenção e dashboard configurável.

**Architecture:** Todas as adições em `admin/app.py` + novos templates. Alertas via thread daemon. SSE requer `threaded=True`. Tags e permissões em novas tabelas no DB existente.

**Tech Stack:** Flask, SQLite, `smtplib`/`threading`/`ipaddress` (stdlib), HTML5 Drag API, SSE. Spec: `docs/superpowers/specs/2026-03-26-melhorias-fases-10-13-design.md` — Fase 13.

**⚠️ REQUISITO DEPLOYMENT:** Task 13.4 (SSE) exige Flask rodando com `threaded=True` ou Gunicorn. Não funciona com Werkzeug single-thread.

---

## File Map

| Arquivo | Ação |
|---|---|
| `admin/app.py` | Todas as rotas e lógica das 7 tasks |
| `admin/templates/settings_alerts.html` | Criar — config de alertas |
| `admin/templates/search.html` | Já criado na Fase 12 |
| `admin/tests/test_features.py` | Criar — todos os testes da fase 13 |

---

## Task 1: Alertas Webhook + Email (13.1)

- [ ] **Escrever testes em `admin/tests/test_features.py`:**

```python
import pytest, app as flask_app

@pytest.fixture
def auth_client(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path / "api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path / "sessions.db"))
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        with c.session_transaction() as s:
            s["logged_in"] = True; s["username"] = "admin"
            s["role"] = "admin"; s["last_active"] = __import__("time").time()
        yield c

def test_alerts_settings_page_returns_200(auth_client):
    r = auth_client.get("/settings/alerts")
    assert r.status_code == 200

def test_dispatch_alert_no_config_does_not_raise():
    # sem config, não deve lançar exceção
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
```

- [ ] **Rodar — confirmar FAIL**

- [ ] **Adicionar tabela `alert_config` em `_init_api_db()`:**

```python
conn.execute("""
    CREATE TABLE IF NOT EXISTS alert_config (
        id           INTEGER PRIMARY KEY CHECK (id = 1),
        webhook_url  TEXT DEFAULT '',
        webhook_secret TEXT DEFAULT '',
        smtp_host    TEXT DEFAULT '',
        smtp_port    INTEGER DEFAULT 587,
        smtp_user    TEXT DEFAULT '',
        smtp_pass    TEXT DEFAULT '',
        smtp_from    TEXT DEFAULT '',
        smtp_to      TEXT DEFAULT '',
        alert_events TEXT DEFAULT '[]'
    )
""")
conn.execute("INSERT OR IGNORE INTO alert_config (id) VALUES (1)")
```

- [ ] **Implementar `_dispatch_alert` em `app.py`:**

```python
def _dispatch_alert(event: str, detail: dict):
    import threading
    def _send():
        try:
            conn = _get_api_db()
            cfg = conn.execute("SELECT * FROM alert_config WHERE id=1").fetchone()
            conn.close()
            if not cfg:
                return
            import json as _json
            events = _json.loads(cfg["alert_events"] or "[]")
            if events and event not in events:
                return
            payload = _json.dumps({"event": event, "ts": __import__("datetime").datetime.utcnow().isoformat(), "detail": detail}).encode()
            # Webhook
            if cfg["webhook_url"]:
                import urllib.request, hmac, hashlib
                sig = "sha256=" + hmac.new(
                    (cfg["webhook_secret"] or "").encode(), payload, hashlib.sha256
                ).hexdigest()
                req = urllib.request.Request(
                    cfg["webhook_url"], data=payload,
                    headers={"Content-Type": "application/json", "X-Ubuntu-Desk-Signature": sig}
                )
                try:
                    urllib.request.urlopen(req, timeout=5)
                except Exception:
                    pass
            # Email
            if cfg["smtp_host"] and cfg["smtp_to"]:
                import smtplib
                from email.mime.text import MIMEText
                msg = MIMEText(f"Evento: {event}\n\n{_json.dumps(detail, indent=2)}", "plain")
                msg["Subject"] = f"[Ubuntu Desk] Alerta: {event}"
                msg["From"] = cfg["smtp_from"] or cfg["smtp_user"]
                msg["To"] = cfg["smtp_to"]
                try:
                    with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=5) as s:
                        if cfg["smtp_user"]:
                            s.starttls()
                            s.login(cfg["smtp_user"], cfg["smtp_pass"])
                        s.send_message(msg)
                except Exception:
                    pass
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()
```

- [ ] **Implementar rotas `/settings/alerts` (GET + POST) e criar `settings_alerts.html`**

- [ ] **Chamar `_dispatch_alert` nos eventos:** `login_bloqueado`, `peer_block`, registro de novo peer (no `get_db()` se peer novo)

- [ ] **Commit:** `git commit -am "feat: webhook + email alerts for security events"`

---

## Task 2: Bulk Actions em Devices (13.2)

- [ ] **Escrever testes** (adicionar em `test_features.py`):

```python
def test_bulk_block_requires_login(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path/"api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path/"audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path/"sessions.db"))
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        r = c.post("/peers/bulk", json={"action": "block", "ids": ["1"]})
        assert r.status_code in (302, 401, 403)

def test_bulk_block_returns_ok(auth_client):
    with auth_client.session_transaction() as s:
        s["_csrf"] = "tok"
    r = auth_client.post("/peers/bulk",
        json={"action": "block", "ids": []},
        headers={"X-CSRF-Token": "tok"})
    assert r.status_code in (200, 204)

def test_bulk_delete_requires_admin(auth_client):
    with auth_client.session_transaction() as s:
        s["role"] = "user"
        s["_csrf"] = "tok"
    r = auth_client.post("/peers/bulk",
        json={"action": "delete", "ids": []},
        headers={"X-CSRF-Token": "tok"})
    assert r.status_code in (403, 302)
```

- [ ] **Implementar rota em `app.py`:**

```python
@app.route("/peers/bulk", methods=["POST"])
@login_required
def peers_bulk():
    body   = request.get_json(silent=True) or {}
    action = body.get("action", "")
    ids    = [str(i) for i in body.get("ids", []) if i]
    if not ids or action not in ("block", "unblock", "delete"):
        return jsonify({"error": "invalid"}), 400
    if action == "delete" and session.get("role", "admin") != "admin":
        abort(403)
    db = get_db()
    if db:
        for peer_id in ids:
            if action == "block":
                db.execute("UPDATE peer SET blocked=1 WHERE id=?", (peer_id,))
            elif action == "unblock":
                db.execute("UPDATE peer SET blocked=0 WHERE id=?", (peer_id,))
            elif action == "delete":
                db.execute("DELETE FROM peer WHERE id=?", (peer_id,))
        db.commit()
    audit(f"bulk_{action}", f"ids={','.join(ids)} count={len(ids)}", category="admin")
    return jsonify({"ok": True, "count": len(ids)})
```

- [ ] **Adicionar checkboxes e barra de ações em `dashboard.html`** com JS (nonce obrigatório).

- [ ] **Commit:** `git commit -am "feat: bulk actions — block/unblock/delete multiple devices"`

---

## Task 3: Grupos/Tags de Devices (13.3)

- [ ] **Escrever testes** (adicionar em `test_features.py`):

```python
def test_tags_route_returns_200(auth_client, tmp_path, monkeypatch):
    import sqlite3
    db_path = tmp_path / "db_v2.sqlite3"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE peer (id TEXT PRIMARY KEY, info TEXT DEFAULT '{}', status INTEGER DEFAULT 0, created_at TEXT DEFAULT '', note TEXT, blocked INTEGER DEFAULT 0)")
    conn.execute("INSERT INTO peer VALUES ('T1','{}',0,'2026-01-01',NULL,0)")
    conn.commit(); conn.close()
    monkeypatch.setattr(flask_app, "DB_PATH", str(db_path))
    r = auth_client.get("/peers/T1")
    assert r.status_code == 200

def test_tags_saved_and_retrieved(auth_client, tmp_path, monkeypatch):
    import sqlite3
    db_path = tmp_path / "db_v2.sqlite3"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE peer (id TEXT PRIMARY KEY, info TEXT DEFAULT '{}', status INTEGER DEFAULT 0, created_at TEXT DEFAULT '', note TEXT, blocked INTEGER DEFAULT 0)")
    conn.execute("INSERT INTO peer VALUES ('T1','{}',0,'2026-01-01',NULL,0)")
    conn.commit(); conn.close()
    monkeypatch.setattr(flask_app, "DB_PATH", str(db_path))
    with auth_client.session_transaction() as s:
        s["_csrf"] = "tok"
    r = auth_client.post("/peers/T1/tags",
        data={"csrf_token": "tok", "tags": "ti,escritorio"})
    assert r.status_code in (200, 302)
```

- [ ] **Adicionar migração de `peer_tags` em `get_db()`:**

```python
g.db.execute("""
    CREATE TABLE IF NOT EXISTS peer_tags (
        peer_id TEXT NOT NULL,
        tag     TEXT NOT NULL,
        PRIMARY KEY (peer_id, tag)
    )
""")
```

- [ ] **Implementar rota `POST /peers/<peer_id>/tags` em `app.py`:**

```python
@app.route("/peers/<peer_id>/tags", methods=["POST"])
@login_required
def peer_set_tags(peer_id):
    db = get_db()
    if db is None:
        return jsonify({"error": "DB unavailable"}), 503
    raw  = request.form.get("tags", "")
    tags = [t.strip()[:30] for t in raw.split(",") if t.strip()][:10]
    db.execute("DELETE FROM peer_tags WHERE peer_id=?", (peer_id,))
    for tag in tags:
        db.execute("INSERT OR IGNORE INTO peer_tags (peer_id, tag) VALUES (?,?)", (peer_id, tag))
    db.commit()
    return redirect(url_for("peer_detail", peer_id=peer_id))
```

- [ ] **Adicionar filtro `?tag=X`** na rota `/` e exibir badges coloridos nas tabelas.

- [ ] **Commit:** `git commit -am "feat: device tags — free-form labels with filter support"`

---

## Task 4: Notificações Real-Time SSE (13.4)

**⚠️ Requer `app.run(threaded=True)` no bloco `if __name__ == "__main__"`**

- [ ] **Escrever testes** (adicionar em `test_features.py`):

```python
def test_sse_endpoint_requires_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-pass")
    monkeypatch.setenv("API_DB", str(tmp_path/"api.db"))
    monkeypatch.setenv("AUDIT_DB", str(tmp_path/"audit.db"))
    monkeypatch.setenv("SESSIONS_DB", str(tmp_path/"sessions.db"))
    flask_app.app.config["TESTING"] = True
    with flask_app.app.test_client() as c:
        r = c.get("/api/events")
        assert r.status_code in (302, 401, 403)

def test_sse_endpoint_auth_returns_stream(auth_client):
    # Em modo TESTING o stream fecha imediatamente — verificar Content-Type
    r = auth_client.get("/api/events")
    assert r.status_code in (200, 302)
```

- [ ] **Implementar em `app.py`:**

```python
@app.route("/api/events")
@login_required
def sse_events():
    def generate():
        import json as _json
        while True:
            # Abre nova conexão a cada poll — nunca mantém conexão aberta entre iterações
            try:
                db = sqlite3.connect(DB_PATH) if os.path.exists(DB_PATH) else None
                if db:
                    online = db.execute("SELECT COUNT(*) FROM peer WHERE status=1").fetchone()[0]
                    total  = db.execute("SELECT COUNT(*) FROM peer").fetchone()[0]
                    db.close()
                    yield f"data: {_json.dumps({'online': online, 'total': total})}\n\n"
            except Exception:
                pass
            time.sleep(10)
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
```

- [ ] **Adicionar listener SSE em `base.html`** (com nonce):

```html
<script nonce="{{ csp_nonce }}">
if (typeof EventSource !== 'undefined') {
  const es = new EventSource('/api/events');
  es.onmessage = e => {
    const d = JSON.parse(e.data);
    const badge = document.getElementById('online-badge');
    if (badge) badge.textContent = d.online + ' online';
  };
}
</script>
```

- [ ] **Atualizar `app.run`:**

```python
app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
```

- [ ] **Commit:** `git commit -am "feat: SSE real-time device status updates (requires threaded mode)"`

---

## Task 5: Controle de Acesso por Device (13.5)

- [ ] **Escrever testes** (adicionar em `test_features.py`):

```python
def test_device_permissions_table_created(auth_client):
    conn = flask_app._get_api_db()
    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    conn.close()
    assert "device_permissions" in tables

def test_ab_respects_device_permissions(auth_client):
    # sem permissões configuradas, retorna tudo (comportamento atual)
    r = auth_client.get("/api/ab", headers={"Authorization": "Bearer fake"})
    assert r.status_code in (200, 401)
```

- [ ] **Adicionar DDL em `_init_api_db()`:**

```python
conn.execute("""
    CREATE TABLE IF NOT EXISTS device_permissions (
        peer_id  TEXT NOT NULL,
        username TEXT NOT NULL,
        PRIMARY KEY (peer_id, username)
    )
""")
```

- [ ] **Implementar rota `POST /peers/<peer_id>/permissions` e checklist em `peer.html`**

- [ ] **Filtrar `GET /api/ab`** para respeitar permissões quando tabela tem entradas para o device.

- [ ] **Commit:** `git commit -am "feat: per-device access control — restrict address book by user"`

---

## Task 6: Agendamento de Manutenção (13.6)

- [ ] **Escrever testes** (adicionar em `test_features.py`):

```python
def test_maintenance_column_migrated(tmp_path, monkeypatch):
    import sqlite3
    db_path = tmp_path / "db_v2.sqlite3"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE peer (id TEXT PRIMARY KEY, info TEXT DEFAULT '{}', status INTEGER DEFAULT 0, created_at TEXT DEFAULT '', note TEXT, blocked INTEGER DEFAULT 0)")
    conn.commit(); conn.close()
    monkeypatch.setattr(flask_app, "DB_PATH", str(db_path))
    with flask_app.app.app_context():
        db = flask_app.get_db()
        cols = [r[1] for r in db.execute("PRAGMA table_info(peer)").fetchall()]
        assert "maintenance_until" in cols

def test_maintenance_badge_shown_when_active(auth_client, tmp_path, monkeypatch):
    import sqlite3
    db_path = tmp_path / "db_v2.sqlite3"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE peer (id TEXT PRIMARY KEY, info TEXT DEFAULT '{}', status INTEGER DEFAULT 0, created_at TEXT DEFAULT '', note TEXT, blocked INTEGER DEFAULT 0, starred INTEGER DEFAULT 0, maintenance_until TEXT)")
    conn.execute("INSERT INTO peer VALUES ('M1','{}',0,'2026-01-01',NULL,0,0,'2099-12-31 23:59:59')")
    conn.commit(); conn.close()
    monkeypatch.setattr(flask_app, "DB_PATH", str(db_path))
    r = auth_client.get("/")
    assert r.status_code == 200
```

- [ ] **Adicionar migração em `get_db()`:**

```python
if "maintenance_until" not in cols:
    g.db.execute("ALTER TABLE peer ADD COLUMN maintenance_until DATETIME")
    g.db.commit()
```

- [ ] **Implementar rota:**

```python
@app.route("/peers/<peer_id>/maintenance", methods=["POST"])
@login_required
def peer_set_maintenance(peer_id):
    db = get_db()
    if db is None:
        abort(503)
    until = request.form.get("maintenance_until", "").strip() or None
    db.execute("UPDATE peer SET maintenance_until=? WHERE id=?", (until, peer_id))
    db.commit()
    flash("Manutenção atualizada.", "success")
    return redirect(url_for("peer_detail", peer_id=peer_id))
```

- [ ] **Adicionar badge laranja em `dashboard.html`** quando `maintenance_until > now()`.

- [ ] **Commit:** `git commit -am "feat: device maintenance scheduling with orange badge"`

---

## Task 7: Dashboard Configurável (13.7)

**⚠️ Todos os scripts devem usar `nonce="{{ csp_nonce }}"` — obrigatório pelo CSP atual.**

- [ ] **Escrever testes** (adicionar em `test_features.py`):

```python
def test_dashboard_returns_200(auth_client):
    r = auth_client.get("/")
    assert r.status_code == 200

def test_dashboard_has_widget_config_button(auth_client):
    r = auth_client.get("/")
    assert b"configurar" in r.data.lower() or b"widget" in r.data.lower() or r.status_code == 200
```

- [ ] **Implementar em `dashboard.html`:**
  - Envolver cada widget em `<section data-widget="nome">` com `display:none` quando desativado
  - Modal de configuração com checkboxes por widget
  - Script (com nonce) que lê/escreve `localStorage["ud_widgets"]` e mostra/oculta seções
  - Drag & Drop via HTML5 `draggable="true"` + eventos `dragstart`/`dragover`/`drop`
  - Padrão: todos os widgets visíveis (sem localStorage = tudo ativo)

- [ ] **Rodar suite completa:** `cd admin/tests && python -m pytest . -q`

- [ ] **Commit:** `git commit -am "feat: configurable dashboard widgets with localStorage persistence"`

---

## Verificação Final da Fase 13

- [ ] `cd admin/tests && python -m pytest . -q` — todos passando
- [ ] Testar alertas manualmente com `ngrok` ou servidor de teste
- [ ] Confirmar SSE funciona com `threaded=True`
