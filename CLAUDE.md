# CLAUDE.md — Ubuntu Desk

## Obsidian
- Nota do projeto: `Projetos/Ubuntu Desk.md`
- Memórias: `Memoria/Ubuntu Desk - Icone do App.md`, `Memoria/Ubuntu Desk - Contexto Rebranding.md`

**Ler essas notas SEMPRE ao iniciar qualquer trabalho neste projeto.**

---

## Skill de Design (obrigatória)

Skill `ui-ux-pro-max` já instalada (v2.0.1). Ativar com `/ui-ux-pro-max` antes de qualquer tarefa de UI/UX.
Marketplace: `ui-ux-pro-max-skill` (GitHub: nextlevelbuilder/ui-ux-pro-max-skill)

---

## Contexto do projeto

Fork do RustDesk com rebranding completo para **Ubuntu Desk**.

- **Bundle ID:** `com.ubuntudesk.app`
- **Email:** `admin@ubuntudesk.app`
- **Site:** `ubuntudesk.app`
- **Cor principal:** `#06B6D4` (cyan) | **Fundo:** `#0F172A`
- **Ícone:** `projeto 2/icone do app e logo.png` → já em `client/res/icon.png`

---

## Regras específicas

- **Não perguntar** qual é o ícone — está em `client/res/icon.png` e `projeto 2/icone do app e logo.png`
- **Não renomear** `RustDeskIddDriver`, `RustDesk v4 Printer Driver`, `librustdesk`, `rustdesk_core_main` — drivers Windows assinados e símbolos FFI internos
- **Não alterar** translation keys como `'About RustDesk'` — são chaves de lookup, não texto visível
- **Não alterar** `kPlatformAdditionsRustDeskVirtualDisplays = "rustdesk_virtual_displays"` — deve coincidir com código Rust

---

## Estrutura do projeto

```
projeto 2/
├── client/          ← Fork do rustdesk (rebranding 100% concluído)
├── server/          ← Fork do rustdesk-server (rebranding concluído)
├── admin/           ← Painel Flask + SQLite (dark theme)
├── build/           ← Scripts build_windows.ps1, build_linux.sh
└── tasks/todo.md    ← Fonte de verdade do progresso
```

---

## Próximos passos (retomar aqui)

### Fase A — Concluída nesta sessão ✅
- lessons.md criado
- skill ui-ux-pro-max instalada
- CLAUDE.md criado
- Obsidian atualizado com memórias

### Fase B — Build Windows (próxima)
- Flutter ✅ instalado (desbloqueado)
- Rodar: `.\build\build_windows.ps1 -Release`
- Verificar saída: `dist/windows/ubuntu-desk.exe`

### Fase C — Servidor
- Subir Docker: `docker compose up -d` na pasta `server/`
- Capturar chave: `docker exec ubuntu-desk-hbbs cat /root/id_ed25519.pub`
- Preencher `RS_PUB_KEY` no `server/.env`
- Atualizar `RENDEZVOUS_SERVERS` em `client/libs/hbb_common/src/config.rs` com IP/domínio definitivo
- Testar conexão cliente → servidor

---

## Status das fases

| Fase | Status |
|---|---|
| 1 — Fork + Setup | 🔄 Flutter pendente |
| 2 — Rebranding | ✅ Concluído |
| 3 — Servidor | 🔄 3.1 ✅, resto adiado |
| 4 — Build | 🔄 4.2–4.4 ✅, 4.1 aguarda Flutter |
| 5 — Admin panel | ✅ Concluído |
| 6 — UI/UX | ✅ Concluído |
