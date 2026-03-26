# Design — Melhorias Ubuntu Desk Admin (Fases 10–13)

**Data:** 2026-03-26
**Projeto:** Ubuntu Desk — Painel de Administração
**Arquivo:** `admin/app.py` + templates Flask
**Estado atual:** Fase 9 (hardening de produção) concluída — 45/45 testes passando

---

## Contexto

O painel admin do Ubuntu Desk está funcional e seguro para produção. Este documento descreve as melhorias organizadas em 4 fases por categoria: Confiabilidade, Segurança Avançada, UX/Interface e Funcionalidades.

---

## Fase 10 — Confiabilidade & Ops

**Objetivo:** garantir que o sistema seja observável, recuperável e auditável em produção.

### 10.1 — Health Check Endpoint

- Rota `GET /health` — pública, sem autenticação, GET apenas
- Totalmente isenta de todos os middlewares de `before_request`: `check_session_timeout`, `check_csrf`, `generate_csp_nonce`, e as guards futuras de 11.1 (2FA obrigatório) e 11.3 (IP allowlist)
- Resposta JSON: `{"status": "ok", "db": true, "version": "1.0.0", "uptime_seconds": 123}`
- Verifica conectividade com os 3 bancos SQLite (peer db, api.db, audit.db) — tentativa de SELECT simples
- HTTP 200 se tudo OK, HTTP 503 se algum banco inacessível
- Usado pelo Docker `HEALTHCHECK` e ferramentas de monitoramento externo

### 10.2 — Backup Automático SQLite

- Thread `daemon=True` iniciada no `if __name__ == "__main__"` e também via `@app.before_request` com flag de inicialização única
- Executa diariamente (configurável via `BACKUP_INTERVAL_HOURS`, padrão 24h)
- Copia os 3 bancos para `data/backups/YYYY-MM-DD/`: `api.db`, `audit.db`, `sessions.db`
- Usa `sqlite3.connect(src).backup(dst)` (hot backup — sem travar o banco)
- Retém os últimos N dias configurável via `BACKUP_RETENTION_DAYS` (padrão 7)
- **Isolamento de conexão:** a thread abre suas próprias conexões SQLite isoladas — nunca compartilha objetos de conexão com request handlers. Para logar o resultado no audit, a thread abre uma conexão dedicada diretamente com `sqlite3.connect(AUDIT_DB)` (não via `_get_audit_db()`), e envolve a escrita em `try/except` para evitar `OperationalError: database is locked` no journal mode padrão

### 10.3 — Logs Estruturados JSON

- Middleware `@app.after_request` emite linha JSON por request para stdout
- Campos: `{"ts", "method", "path", "status", "duration_ms", "ip"}`
- Ativado via `LOG_FORMAT=json` no `.env` (padrão: desativado — não quebra logs atuais)
- Compatível com Grafana Loki, Datadog, e qualquer ingestor JSON

---

## Fase 11 — Segurança Avançada

**Objetivo:** fechar os últimos gaps de segurança antes de escalar o uso.

### 11.1 — 2FA Obrigatório para Admin

- `@app.before_request`: se `session["role"] == "admin"` e `totp_enabled == 0`, redireciona para `/settings/2fa/setup`
- Lista completa de rotas isentas: `/login*`, `/logout`, `/static/*`, `/health`, `/settings/2fa/*`
  - Sem a isenção de `/settings/2fa/*`, o admin entraria em loop infinito incapaz de completar o setup
- Mensagem explicativa em `settings_2fa_setup.html`: "Administradores precisam configurar 2FA antes de continuar"
- Não afeta usuários com role `user` ou `manager`

### 11.2 — Password Policy

- Regra: mínimo 8 caracteres + ao menos 1 dígito + ao menos 1 símbolo (`!@#$%^&*-_+=`)
- Função `_validate_password(pwd) -> str | None` — retorna mensagem de erro ou None
- Aplicada **apenas na criação/reset de senha**: `users_create` e `users_reset_password`
- **Não** aplicada em `api_login` (verificação de credenciais existentes) — aplicar em login bloquearia usuários com senhas criadas antes da policy
- Mensagem de erro clara no frontend

### 11.3 — IP Allowlist

- Variável de ambiente `ALLOWED_IPS` — lista separada por vírgula de IPs/CIDRs
- Exemplos: `192.168.0.0/24`, `10.0.0.1`; vazio = sem restrição (comportamento atual preservado)
- Middleware `@app.before_request` — retorna 403 com JSON `{"error": "IP not allowed"}`
- Usa `ipaddress` stdlib — sem dependências externas
- Rota `/health` explicitamente isenta (monitoramento externo precisa acessar)

---

## Fase 12 — UX & Interface

**Objetivo:** melhorar a usabilidade diária do painel sem adicionar dependências externas.

### 12.1 — Ordenação por Coluna nas Tabelas

- Implementação via query string: `?sort=hostname&dir=asc`
- **Cada tabela tem um allowlist explícito de colunas ordenáveis** — qualquer valor não reconhecido cai no sort padrão, impedindo injeção SQL via `ORDER BY`
- O parâmetro `sort` é validado contra o allowlist antes de ser interpolado na query (colunas não podem ser parametrizadas em SQLite)
- **Atenção:** `hostname` na tabela `peer` não é coluna direta — requer `json_extract(info, '$.hostname')` na query ORDER BY
- Allowlists por tabela:
  - devices: `id`, `hostname` (via json_extract), `status`, `created_at`
  - usuários: `username`, `role`, `created_at`
  - histórico: `started_at`, `duration_secs`, `peer_from`
  - audit: `ts`, `category`, `action`
- Header clicável com indicador visual de direção (▲▼) via CSS puro

### 12.2 — Paginação na Lista de Devices

- 50 devices por página (constante `PEERS_PAGE_SIZE`)
- Query string `?page=N`
- Macro Jinja2 reutilizável em `base.html` para os controles de paginação
- Exibe: "Mostrando 1–50 de 234 devices"

### 12.3 — Player de Gravações Inline

- Tag `<video controls>` na página `/recordings` para cada arquivo
- Rota `GET /recordings/stream/<filename>` com suporte a **Range requests** para seek no player
- Implementação de Range: parsear `Range: bytes=X-Y`, responder `206 Partial Content` com `Content-Range` e `Content-Length` corretos; `send_file` do Flask não suporta Range nativamente — requer implementação manual (~30 linhas)
- Fallback para botão de download se formato não suportado pelo browser
- Player estilizado com o tema dark do painel

### 12.4 — Busca Global

- Campo de busca persistente no header (`base.html`)
- Rota `GET /search?q=<termo>` — busca em paralelo:
  - Devices: `hostname` (json_extract), `id`, `username` (json_extract), `note`
  - Usuários: `username`
  - Audit log: `action`, `detail`
- Resultados agrupados por categoria, limite de 5 por grupo
- Atalho de teclado `/` para focar o campo

### 12.5 — Favoritar Devices

- Coluna `starred INTEGER DEFAULT 0` na tabela `peer` (migração automática em `get_db()`)
- Rotas `POST /peers/<peer_id>/star` e `POST /peers/<peer_id>/unstar`
- Ícone de estrela na listagem e no detalhe
- Devices favoritados aparecem fixos no topo, separados por divisor visual

---

## Fase 13 — Funcionalidades

**Objetivo:** adicionar features que aumentam o valor operacional do produto.

### 13.1 — Alertas (Webhook + Email)

**Configuração** salva em tabela `alert_config` no `api.db`:
- DDL adicionado ao bloco existente em `_init_api_db()` — segue o padrão de migrações já estabelecido
- Campos: `webhook_url`, `webhook_secret`, `smtp_host`, `smtp_port`, `smtp_user`, `smtp_pass`, `smtp_from`, `smtp_to`, `alert_events` (JSON array)

**Eventos suportados:**
- `login_falha_5x` — 5 falhas consecutivas do mesmo IP
- `device_bloqueado` — admin bloqueia um device
- `novo_device` — device se registra pela primeira vez
- `2fa_desativado` — admin desativa 2FA

**Payload webhook:**
```json
{"event": "login_falha_5x", "ts": "...", "detail": {...}, "server": "ubuntudesk.app"}
```
Header: `X-Ubuntu-Desk-Signature: sha256=<hmac-sha256 do body com webhook_secret>`

**Email:** template HTML simples via `smtplib` (stdlib), assunto `[Ubuntu Desk] Alerta: <evento>`

**Envio:** função `_dispatch_alert(event, detail)` — tenta webhook e email em thread daemon separada (não bloqueia o request). Falhas logadas no audit.

**UI:** página `/settings/alerts` — formulário de configuração + botão "Testar alerta"

### 13.2 — Bulk Actions em Devices

- Checkboxes em cada linha da tabela de devices
- Barra de ações sticky ao selecionar 1+ devices: "Bloquear", "Desbloquear", "Adicionar tag", "Deletar"
- Rota `POST /peers/bulk` com body `{"action": "block|unblock|delete", "ids": ["id1", "id2"]}`
- **Autorização:** ações destrutivas (`delete`) requerem `@admin_required`; `block`/`unblock` requerem `@login_required` (consistente com as rotas individuais existentes)
- Confirmação modal antes de ações destrutivas
- "Selecionar todos" e "Limpar seleção"

### 13.3 — Grupos/Tags de Devices

- Tabela `peer_tags (peer_id TEXT, tag TEXT)` adicionada ao banco `db_v2.sqlite3` via migração em `get_db()` — mesmo padrão da coluna `blocked` já existente
- **Risco reconhecido:** `db_v2.sqlite3` é gerenciado pelo hbbs. A migração é aditiva (ADD TABLE) e não altera tabelas existentes, minimizando conflito. O admin panel já segue este padrão com a coluna `blocked`
- **Tratamento de DB ausente:** qualquer operação de tag deve verificar `get_db() is not None` antes de executar — retornar erro 503 claro se DB indisponível, nunca falhar silenciosamente
- Tags livres, máximo 10 por device, máximo 30 chars por tag
- Filtro por tag na listagem: `?tag=escritorio`
- Badge colorido por tag (cor derivada do hash da string para consistência visual)
- Rota `POST /peers/<peer_id>/tags` (substituição completa das tags do device)

### 13.4 — Notificações Real-Time (SSE)

- Endpoint `GET /api/events` — Server-Sent Events, autenticado via session cookie
- **Requisito de deployment:** SSE requer que o servidor Flask rode com `threaded=True` (Werkzeug) ou via Gunicorn. Em processo single-threaded, cada cliente SSE conectado bloquearia todos os demais requests
- **Isolamento de conexão:** o generator abre e fecha uma nova conexão SQLite a cada ciclo de poll (a cada 10s) — nunca mantém uma conexão aberta entre iterações
- Eventos: mudança de status online/offline de devices
- Frontend (`base.html`): `EventSource` atualiza badge de devices online no sidebar sem reload
- Timeout de 60s — cliente reconecta automaticamente (comportamento padrão SSE)
- Sem dependências externas

### 13.5 — Controle de Acesso por Device

- Tabela `device_permissions (peer_id TEXT, username TEXT)` no `api.db`
- DDL adicionado a `_init_api_db()`
- Configurável no detalhe do device: checklist de usuários
- Vazio = sem restrição (comportamento atual preservado)
- Filtra resultados do `GET /api/ab` para retornar apenas devices com permissão para o usuário autenticado

### 13.6 — Agendamento de Manutenção

- Coluna `maintenance_until DATETIME` na tabela `peer` (migração em `get_db()`)
- Campo datetime no detalhe do device
- Rota `POST /peers/<peer_id>/maintenance`
- Badge laranja "EM MANUTENÇÃO" na listagem quando `maintenance_until > now()`
- Limpeza automática via `@app.before_request` com flag de execução máxima 1x/hora

### 13.7 — Dashboard Configurável

- Widgets: métricas de sessão, gráfico 7 dias, devices online, alertas recentes, audit recente
- Preferência salva em `localStorage` como JSON array de widgets ativos
- Modal de toggle dos widgets
- Layout em grid responsivo; reordenação via HTML5 Drag API (sem biblioteca)
- **Todos os scripts inline devem usar o nonce CSP já estabelecido em `base.html`** — scripts sem nonce são bloqueados pelo CSP atual (`script-src 'self' 'nonce-...'`)
- Padrão: todos os widgets ativos (comportamento atual preservado)

---

## Arquitetura — Impacto no código

| Arquivo | Mudanças |
|---|---|
| `admin/app.py` | Novas rotas, middlewares, funções auxiliares |
| `admin/templates/` | Novos templates + modificações em existentes |
| `admin/templates/base.html` | Busca global, SSE listener, macro de paginação, nonce em novos scripts |
| `server/.env.example` | Novas vars: `LOG_FORMAT`, `BACKUP_RETENTION_DAYS`, `BACKUP_INTERVAL_HOURS`, `ALLOWED_IPS`, `RECORD_MAX_FILE_MB` |
| `server/docker-compose.yml` | `HEALTHCHECK: GET /health` |

Nenhuma nova dependência Python obrigatória. Dependências usadas: `smtplib`, `ipaddress`, `threading` (todas stdlib).

---

## Ordem de execução

```
Fase 10 → Fase 11 → Fase 12 → Fase 13
```

Cada fase é independente e pode ser commitada separadamente.

---

## Testes

Cada task deve ter ao menos 2 testes: happy path + edge case/erro esperado.
Meta: manter 100% dos testes existentes passando ao longo de todas as fases.

---

*Criado em: 2026-03-26 | Revisado: 2026-03-26 (11 issues do spec reviewer aplicados)*
