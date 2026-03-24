# Multi-User Address Book — Design Spec

**Projeto:** Ubuntu Desk
**Data:** 2026-03-23
**Status:** Aprovado

---

## Contexto

O painel admin e a API de address book do Ubuntu Desk hoje suportam apenas um único usuário (`admin`). Para uso em equipe, cada técnico precisa de conta própria com address book individual, além de uma address book compartilhada visível a todos. Este spec define a implementação de multi-user com roles no `api.db` sem quebrar a compatibilidade com clientes existentes.

---

## Objetivos

- Cada técnico faz login com credenciais próprias no cliente Ubuntu Desk
- Cada técnico tem address book individual sincronizada no servidor
- Existe uma address book compartilhada visível a todos
- Admin gerencia usuários pelo painel web (criar, editar role, resetar senha, desativar, excluir)
- Admin e managers podem ver a address book de outros usuários pelo painel

## Não está no escopo

- Login multi-usuário no painel web (permanece single-admin)
- Troca de senha pelo próprio usuário via cliente
- 2FA por usuário (segue sendo opcional via TOTP_SECRET global)
- Paginação ou limites de tamanho no JSON da address book
- SSL/TLS (item separado do backlog)

---

## Modelo de dados

Todas as mudanças ficam em `api.db`. Nenhum outro banco é afetado.

### Nova tabela `users`

```sql
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    REAL NOT NULL
)
```

**Roles:**
- `admin` — acesso total via API; único criado automaticamente pelo sistema
- `manager` — pode editar address book compartilhada e ver books de outros usuários
- `user` — acesso à própria address book + leitura da compartilhada

A role `admin` não pode ser criada via UI do painel — existe exatamente um admin (o do `.env`).

**Username reservado:** o username `__shared__` é proibido (conflita com o sentinel da `address_books`). A rota de criação de usuário deve rejeitar esse valor com HTTP 400.

**Email:** o campo `email` não é armazenado na tabela `users`. Na resposta de `/api/currentUser`, `email` retorna string vazia para todos os usuários, exceto `admin` que retorna `admin@ubuntudesk.app` (mantém comportamento atual).

**`created_at`:** usa `REAL` (Unix epoch float), formatado pelo painel da mesma forma que `peer.created_at` (função `fmt_dt` já existente).

### Alteração em `api_tokens`

```sql
ALTER TABLE api_tokens ADD COLUMN username TEXT NOT NULL DEFAULT 'admin'
```

Cada token gerado no login passa a ter o usuário associado.

**Idempotência:** a migration usa `PRAGMA table_info(api_tokens)` para verificar se a coluna já existe antes de executar o `ALTER TABLE`. Se existir, o comando é ignorado.

### Alteração em `address_books`

Schema anterior:
```sql
id   INTEGER PRIMARY KEY
data TEXT NOT NULL DEFAULT '{}'
```

Schema novo:
```sql
owner TEXT PRIMARY KEY,  -- username ou '__shared__'
data  TEXT NOT NULL DEFAULT '{}'
```

**Sequência de migração DDL** (executada no startup se a tabela antiga existir com coluna `id` inteira):

```sql
CREATE TABLE address_books_new (
    owner TEXT PRIMARY KEY,
    data  TEXT NOT NULL DEFAULT '{}'
);
INSERT INTO address_books_new (owner, data)
    SELECT '__shared__', data FROM address_books WHERE id = 1;
DROP TABLE address_books;
ALTER TABLE address_books_new RENAME TO address_books;
```

A detecção de "schema antigo" é feita via `PRAGMA table_info(address_books)` — se a primeira coluna se chama `id` (não `owner`), a migração é executada.

### Tabela `api_keys` (existente — sem alteração de schema)

A tabela `api_keys` (named permanent keys) não recebe coluna `username`. Requisições autenticadas via `X-Api-Key` são tratadas como `username='admin'` e `role='admin'` em `g.api_user`. Esse comportamento é documentado no código e pode ser estendido futuramente.

---

## Migração automática no startup

A função `_init_api_db()` executa no startup e garante, nesta ordem:

1. Cria tabela `users` se não existir
2. Cria tabela `address_books` com novo schema se não existir
3. Se `address_books` usa schema antigo (`id` inteiro): executa migração DDL acima
4. Adiciona coluna `username` em `api_tokens` se ausente (guarda com `PRAGMA table_info`)
5. Se `users` está vazia: insere `admin` com hash de `ADMIN_PASS` do `.env` e role `admin`

A migração é idempotente — detecta o estado atual antes de agir.

---

## Fluxo de autenticação (API)

### `POST /api/login`

Antes: verifica `username == "admin"` e compara com `ADMIN_PASS`.
Depois: busca `username` na tabela `users`, verifica `is_active=1`, valida password com PBKDF2-SHA256 (mesmo algoritmo já em uso).

Token gerado é salvo com `username` associado em `api_tokens`.

Resposta:
```json
{
  "type": "access_token",
  "access_token": "<token>",
  "user": {
    "name": "joao",
    "email": "",
    "note": "manager",
    "status": 1,
    "grp": "",
    "is_admin": false
  }
}
```

### Decorator `api_auth_required`

Passa a popular `g.api_user`:

```python
# Via Bearer token:
g.api_user = {"username": "joao", "role": "manager"}

# Via X-Api-Key (named permanent key):
g.api_user = {"username": "admin", "role": "admin"}
```

A função `_api_token_valid()` passa a verificar também `is_active=1` na tabela `users` para o username associado ao token — tokens de usuários desativados são rejeitados na requisição, sem necessidade de purgar tokens proativamente.

### `GET /api/currentUser`

Retorna dados reais do usuário logado buscados da tabela `users` via `g.api_user["username"]`.

### Token invalidation

- **Desativar usuário:** tokens existentes são bloqueados porque `_api_token_valid()` checa `is_active`. Não é necessário purgar tokens da tabela.
- **Resetar senha:** tokens existentes do usuário são **purgados** da tabela `api_tokens` (`DELETE FROM api_tokens WHERE username = ?`). Um atacante com token roubado perde acesso imediatamente após o reset.
- **Excluir usuário:** tokens do usuário, registro em `users` e address book pessoal são removidos em uma única transação (`BEGIN`/`COMMIT`). Se o processo crashar no meio, nenhuma deleção parcial persiste.

---

## Address Book — comportamento dos endpoints

O parâmetro `?type=` seleciona qual book operar. Sem parâmetro, opera na book pessoal do usuário logado.

| Método | URL | Quem pode | Comportamento |
|---|---|---|---|
| GET | `/api/ab` | todos | Retorna book pessoal do usuário logado |
| GET | `/api/ab?type=shared` | todos | Retorna book compartilhada |
| POST | `/api/ab` | todos | Salva na book pessoal do usuário logado |
| POST | `/api/ab?type=shared` | `manager`, `admin` | Salva na book compartilhada |

**`POST /api/ab?type=shared` por role `user`:** retorna HTTP 403 com body `{"error": "Permission denied"}`.

**`?type=` com valor desconhecido** (qualquer valor que não seja `shared` ou ausente): retorna HTTP 400 com body `{"error": "Invalid type"}`.

Clientes sem `?type=` continuam funcionando sem quebra.

---

## Painel admin — página `/users`

Acessível apenas pelo admin (session cookie). Link "Usuários" na sidebar.

### Listagem

Tabela: username, role (badge colorido), status (ativo/inativo), data de criação (`fmt_dt`).
Ações por linha: editar role, resetar senha, desativar/reativar, excluir.

### Criar usuário

Modal: username (texto, não pode ser `__shared__`), senha (mínimo 8 caracteres), role (`user` ou `manager`).
Role `admin` não é oferecida na UI, e o servidor rejeita qualquer tentativa de criar ou alterar um usuário para role `admin` via API com HTTP 400 (`{"error": "Role admin cannot be assigned"}`). Essa validação é server-side, independente da UI.

### Resetar senha

Admin digita nova senha. Não precisa saber a senha atual.
Validação server-side: mínimo 8 caracteres (retorna HTTP 400 se não atender).
Ao confirmar: purga todos os tokens ativos do usuário + salva novo hash.

### Desativar vs Excluir

- **Desativar** (`is_active=0`): bloqueia login e tokens em uso; preserva address book
- **Excluir**: purga tokens, remove usuário e sua address book pessoal; a book compartilhada permanece intacta

### Visualizar address book de um usuário

Botão "Ver Address Book" na linha de cada usuário.
Exibe view read-only do JSON — útil para suporte e auditoria.

---

## Audit trail

Todas as ações de gerenciamento de usuários são registradas no audit log existente:

| Ação | Categoria | Quando |
|---|---|---|
| `user_created` | admin | Admin cria novo usuário |
| `user_role_changed` | admin | Admin altera role |
| `user_password_reset` | security | Admin reseta senha |
| `user_deactivated` | security | Admin desativa usuário |
| `user_reactivated` | admin | Admin reativa usuário |
| `user_deleted` | security | Admin exclui usuário |
| `ab_shared_written` | admin | Escrita na address book compartilhada |
| `ab_viewed` | access | Admin/manager visualiza book de outro usuário no painel |

---

## Escopo de permissões por role via API

Rotas de peers, audit, recordings, WoL e deploy são acessíveis a qualquer role autenticada — **decisão intencional**: o Ubuntu Desk é uma ferramenta de suporte técnico onde todos os técnicos precisam de acesso operacional completo. Apenas as rotas de address book têm controle por role:

| Rota | `user` | `manager` | `admin` |
|---|---|---|---|
| `GET/POST /api/ab` (própria) | ✅ | ✅ | ✅ |
| `GET /api/ab?type=shared` | ✅ | ✅ | ✅ |
| `POST /api/ab?type=shared` | ❌ 403 | ✅ | ✅ |
| Todas as outras rotas `/api/` | ✅ | ✅ | ✅ |

---

## Critérios de aceitação

- [ ] Usuário `admin` (do `.env`) pode fazer login via `/api/login` após migração
- [ ] Novo usuário `user` pode fazer login e obter/salvar sua própria address book
- [ ] Usuário `user` recebe 403 ao tentar escrever na address book compartilhada
- [ ] Usuário `manager` pode ler e escrever na address book compartilhada
- [ ] Tentativa de criar ou promover usuário para role `admin` via API retorna 400
- [ ] Tentativa de criar usuário com username `__shared__` retorna 400
- [ ] Tentativa de criar usuário com senha < 8 chars retorna 400
- [ ] `GET /api/ab?type=invalido` retorna 400
- [ ] Após desativar usuário, token existente é rejeitado (401)
- [ ] Após resetar senha, token anterior é invalidado (401)
- [ ] Excluir usuário: tokens + address book pessoal removidos, book compartilhada intacta
- [ ] Painel `/users` lista usuários com role e status corretos
- [ ] Migração automática: instalação existente (com `address_books id=1`) roda sem erro e `owner='__shared__'` é criado
- [ ] Todas as ações de gerenciamento registram entrada no audit log

---

## Arquivos afetados

| Arquivo | Mudança |
|---|---|
| `admin/app.py` | `_init_api_db()`, `_api_token_valid()`, `api_auth_required`, `api_login()`, `api_current_user()`, `api_ab()`, novas rotas `/users` e sub-rotas |
| `admin/templates/users.html` | Nova página de gerenciamento de usuários |
| `admin/templates/base.html` | Link "Usuários" na sidebar |

Nenhum arquivo do cliente Flutter é alterado.

---

## Compatibilidade

- Clientes logados como `admin` continuam funcionando sem alteração
- A migração automática converte `address_books id=1` → `owner='__shared__'`
- O protocolo de API não muda — apenas o comportamento por token
- `X-Api-Key` mantém acesso total (role `admin`) sem alteração de schema
