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
- Impressão remota, SSL/TLS (outros itens do backlog)

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

### Alteração em `api_tokens`

```sql
ALTER TABLE api_tokens ADD COLUMN username TEXT NOT NULL DEFAULT 'admin'
```

Cada token gerado no login passa a ter o usuário associado, permitindo que rotas autenticadas saibam quem está fazendo a requisição.

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

O registro `id=1` existente (se houver) é migrado automaticamente para `owner='__shared__'` no startup.

---

## Migração automática no startup

A função `_init_api_db()` executa no startup e garante:

1. Criação das tabelas `users` e `address_books` com schema novo (se não existirem)
2. Adição da coluna `username` em `api_tokens` (se ausente) via `ALTER TABLE ... ADD COLUMN`
3. Migração de `address_books id=1` → `owner='__shared__'` (se a tabela antiga existir com formato inteiro)
4. Se a tabela `users` estiver vazia: inserir `admin` com o hash de `ADMIN_PASS` do `.env` e role `admin`

A migração é idempotente — pode rodar múltiplas vezes sem efeito colateral.

---

## Fluxo de autenticação (API)

### `POST /api/login`

Antes: verifica `username == "admin"` e compara com `ADMIN_PASS`.
Depois: busca `username` na tabela `users`, verifica `is_active=1`, valida password com PBKDF2-SHA256 (mesmo algoritmo já em uso).

Token gerado é salvo com `username` associado em `api_tokens`.

Resposta inclui o campo `user.note` com a role, compatível com o protocolo RustDesk:

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

Passa a popular `g.api_user` com o usuário logado:

```python
g.api_user = {"username": "joao", "role": "manager"}
```

### `GET /api/currentUser`

Retorna os dados reais do usuário logado (buscados da tabela `users` via token), não mais fixo como `admin`.

---

## Address Book — comportamento dos endpoints

O parâmetro `?type=` seleciona qual book operar. Sem parâmetro, opera na book pessoal do usuário logado.

| Método | URL | Quem pode | Comportamento |
|---|---|---|---|
| GET | `/api/ab` | todos | Retorna book pessoal do usuário logado |
| GET | `/api/ab?type=shared` | todos | Retorna book compartilhada |
| POST | `/api/ab` | todos | Salva na book pessoal do usuário logado |
| POST | `/api/ab?type=shared` | `manager`, `admin` | Salva na book compartilhada |

Clientes sem `?type=` continuam funcionando sem quebra (recebem a própria book).

---

## Painel admin — página `/users`

Acessível apenas pelo admin (session cookie). Link na sidebar.

### Listagem

Tabela com colunas: username, role (badge colorido), status (ativo/inativo), data de criação.
Ações por linha: editar role, resetar senha, desativar/reativar, excluir.

### Criar usuário

Modal com campos: username, senha, role (`user` ou `manager`).
Role `admin` não é oferecida na UI.

### Resetar senha

Admin digita nova senha diretamente. Não precisa saber a senha atual.

### Desativar vs Excluir

- **Desativar** (`is_active=0`): bloqueia login, preserva address book
- **Excluir**: remove usuário e sua address book pessoal; a book compartilhada permanece intacta

### Visualizar address book de um usuário

Botão "Ver Address Book" na linha de cada usuário.
Exibe view read-only do JSON — útil para suporte e auditoria.

---

## Permissões resumidas

| Ação | `user` | `manager` | `admin` |
|---|---|---|---|
| Login via API | ✅ | ✅ | ✅ |
| Ver/editar própria address book | ✅ | ✅ | ✅ |
| Ler address book compartilhada | ✅ | ✅ | ✅ |
| Editar address book compartilhada | ❌ | ✅ | ✅ |
| Ver address book de outro usuário (painel) | ❌ | ✅ | ✅ |
| Gerenciar usuários (painel web) | ❌ | ❌ | ✅ |

---

## Arquivos afetados

| Arquivo | Mudança |
|---|---|
| `admin/app.py` | `_init_api_db()`, `api_login()`, `api_auth_required`, `api_current_user()`, `api_ab()`, nova rota `/users` e sub-rotas |
| `admin/templates/users.html` | Nova página de gerenciamento de usuários |
| `admin/templates/base.html` | Link "Usuários" na sidebar |

Nenhum arquivo do cliente Flutter é alterado — a mudança é 100% no servidor/admin.

---

## Compatibilidade

- Clientes existentes (logados como `admin`) continuam funcionando sem alteração
- A migração automática garante que a address book existente (`id=1`) vira a compartilhada
- O protocolo de API não muda — apenas o comportamento por token
