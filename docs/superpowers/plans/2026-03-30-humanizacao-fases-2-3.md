# Humanização UI — Fases 2 e 3 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Completar a humanização da UI do cliente Flutter — tela de aceitar conexão (Fase 2) e labels visíveis em todos os botões da toolbar remota (Fase 3).

**Architecture:** Mudanças puramente de apresentação em dois arquivos Flutter. Não altera lógica de negócio nem modelos. As traduções vão em `ptbr.rs`. O `_IconSubmenuButton` precisa de suporte a `label` (igual ao `_IconMenuButton` existente).

**Tech Stack:** Flutter/Dart, `remote_toolbar.dart`, `server_page.dart`, `src/lang/ptbr.rs`

---

## Arquivos envolvidos

| Arquivo | O que muda |
|---|---|
| `client/src/lang/ptbr.rs` | Adicionar chave `incoming_conn_tip` |
| `client/flutter/lib/desktop/pages/server_page.dart` | `buildUnAuthorized` — nova hierarquia de botões + label "SOLICITANTE" |
| `client/flutter/lib/desktop/widgets/remote_toolbar.dart` | `_IconSubmenuButton` — adicionar `label` param; labels em todos os botões |

---

## Task 1: ptbr.rs — nova string incoming_conn_tip

**Files:**
- Modify: `client/src/lang/ptbr.rs`

- [ ] **Step 1: Adicionar a string**

Abrir `client/src/lang/ptbr.rs`. Localizar a linha com `("Decline", "Recusar")` (linha ~543) e adicionar logo após:

```rust
        ("incoming_conn_tip", "quer acessar este computador"),
```

- [ ] **Step 2: Verificar compilação**

```bash
cd client
cargo check --quiet 2>&1 | head -20
```

Saída esperada: sem erros em `src/lang/ptbr.rs`.

- [ ] **Step 3: Commit**

```bash
git add src/lang/ptbr.rs
git commit -m "feat(lang): add incoming_conn_tip pt-BR translation"
```

---

## Task 2: server_page.dart — hierarquia de botões em buildUnAuthorized

**Files:**
- Modify: `client/flutter/lib/desktop/pages/server_page.dart`

### Contexto

O método `buildUnAuthorized` (linha ~1023) mostra os botões Aceitar/Recusar quando uma conexão chega. O layout atual é:
- "Accept and Elevate" (opcional, verde, full-width)
- Row: [Aceitar (se showAccept), Recusar] — lado a lado

A spec quer:
1. "Permitir acesso" full-width com ícone de checkmark (accent color)
2. "Recusar" full-width abaixo (red outlined)
3. Label "SOLICITANTE" pequeno acima do nome do cliente no `_CmHeader`

O método `buildButton` já suporta `icon:`. As traduções "Permitir acesso" e "Recusar" já existem em ptbr.rs.

- [ ] **Step 1: Substituir o método buildUnAuthorized**

Localizar `buildUnAuthorized(BuildContext context) {` (~linha 1023). Substituir **todo o corpo do método** pelo seguinte:

```dart
  buildUnAuthorized(BuildContext context) {
    final bool canElevate = bind.cmCanElevate();
    final model = Provider.of<ServerModel>(context);
    final showElevation = canElevate &&
        model.showElevation &&
        client.type_() == ClientType.remote;
    final showAccept = model.approveMode != 'password';
    return Column(
      mainAxisAlignment: MainAxisAlignment.end,
      children: [
        // Rótulo "SOLICITANTE" + nome
        Padding(
          padding: const EdgeInsets.only(bottom: 6.0, left: 2.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                translate('Requester'),
                style: TextStyle(
                  fontSize: 9,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1.2,
                  color: MyTheme.accent,
                ),
              ),
              Text(
                '${client.name} ${translate("incoming_conn_tip")}',
                style: TextStyle(fontSize: 12, color: Colors.white70),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
              ),
            ],
          ),
        ),
        // Aceitar com elevação (opcional)
        Offstage(
          offstage: !showElevation || !showAccept,
          child: buildButton(context, color: Colors.green[700], onClick: () {
            handleAccept(context);
            handleElevate(context);
            windowManager.minimize();
          },
              text: 'Accept and Elevate',
              icon: Icon(
                Icons.security_rounded,
                color: Colors.white,
                size: 14,
              ),
              textColor: Colors.white,
              tooltip: 'accept_and_elevate_btn_tooltip'),
        ),
        // Permitir acesso — full-width, accent
        if (showAccept)
          buildButton(
            context,
            color: MyTheme.accent,
            onClick: () {
              handleAccept(context);
              windowManager.minimize();
            },
            icon: Icon(Icons.check_rounded, color: Colors.white, size: 14),
            text: 'Accept',
            textColor: Colors.white,
          ),
        const SizedBox(height: 6),
        // Recusar — full-width, red outlined
        buildButton(
          context,
          color: Colors.transparent,
          border: Border.all(color: Colors.red),
          onClick: handleDisconnect,
          icon: Icon(Icons.close_rounded, color: Colors.red, size: 14),
          text: 'Decline',
          textColor: Colors.red,
        ),
      ],
    ).marginOnly(bottom: buttonBottomMargin);
  }
```

- [ ] **Step 2: Adicionar tradução "Requester" em ptbr.rs**

Localizar linha com `("incoming_conn_tip", ...)` em `src/lang/ptbr.rs` e adicionar:

```rust
        ("Requester", "Solicitante"),
```

- [ ] **Step 3: Verificar que flutter analyze não tem erros nos arquivos modificados**

```bash
cd client
flutter analyze flutter/lib/desktop/pages/server_page.dart 2>&1 | head -30
```

Saída esperada: `No issues found!` ou apenas warnings pré-existentes — zero erros.

- [ ] **Step 4: Commit**

```bash
git add flutter/lib/desktop/pages/server_page.dart src/lang/ptbr.rs
git commit -m "feat(ui): humanize accept/decline connection screen — Fase 2"
```

---

## Task 3: remote_toolbar.dart — label no _IconSubmenuButton

**Files:**
- Modify: `client/flutter/lib/desktop/widgets/remote_toolbar.dart`

### Contexto

`_IconSubmenuButton` (~linha 2358) abre um submenu. Ele não tem `label` param. O `_IconMenuButton` já tem e renderiza `Column(icon + Text)`. Precisamos adicionar o mesmo suporte ao `_IconSubmenuButton`.

- [ ] **Step 1: Adicionar campo label na classe _IconSubmenuButton**

Localizar `class _IconSubmenuButton extends StatefulWidget {` (~linha 2358). Adicionar o campo `label` e atualizar o construtor:

```dart
class _IconSubmenuButton extends StatefulWidget {
  final String tooltip;
  final String? svg;
  final Widget? icon;
  final Color color;
  final Color hoverColor;
  final List<Widget> Function(_IconSubmenuButtonState state) menuChildrenGetter;
  final MenuStyle? menuStyle;
  final FFI? ffi;
  final double? width;
  final String? label;   // ← NOVO

  _IconSubmenuButton({
    Key? key,
    this.svg,
    this.icon,
    required this.tooltip,
    required this.color,
    required this.hoverColor,
    required this.menuChildrenGetter,
    this.ffi,
    this.menuStyle,
    this.width,
    this.label,            // ← NOVO
  }) : super(key: key);
```

- [ ] **Step 2: Atualizar o build de _IconSubmenuButtonState para renderizar o label**

Localizar `Widget build(BuildContext context)` dentro de `_IconSubmenuButtonState` (~linha 2388). Substituir o bloco completo do `final button = SizedBox(...)` e `return MenuBar(...)`:

```dart
  @override
  Widget build(BuildContext context) {
    assert(widget.svg != null || widget.icon != null);
    final icon = widget.icon ??
        SvgPicture.asset(
          widget.svg!,
          colorFilter: ColorFilter.mode(Colors.white, BlendMode.srcIn),
          width: _ToolbarTheme.buttonSize,
          height: _ToolbarTheme.buttonSize,
        );
    final iconInk = Ink(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(_ToolbarTheme.iconRadius),
        color: hover ? widget.hoverColor : widget.color,
      ),
      child: icon,
    );
    final buttonChild = widget.label != null
        ? Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              iconInk,
              Text(
                translate(widget.label!),
                style: TextStyle(fontSize: 9, color: Colors.white70),
              ),
            ],
          )
        : iconInk;
    final button = SizedBox(
        width: widget.width ?? _ToolbarTheme.buttonSize,
        height: widget.label != null
            ? _ToolbarTheme.buttonSize + 14
            : _ToolbarTheme.buttonSize,
        child: SubmenuButton(
            menuStyle:
                widget.menuStyle ?? _ToolbarTheme.defaultMenuStyle(context),
            style: _ToolbarTheme.defaultMenuButtonStyle,
            onHover: (value) => setState(() {
                  hover = value;
                }),
            child: Tooltip(
                message: translate(widget.tooltip),
                child: Material(
                    type: MaterialType.transparency,
                    child: buttonChild)),
            menuChildren: widget
                .menuChildrenGetter(this)
                .map((e) => _buildPointerTrackWidget(e, widget.ffi))
                .toList()));
    return MenuBar(children: [
      button.marginSymmetric(
          horizontal: _ToolbarTheme.buttonHMargin,
          vertical: _ToolbarTheme.buttonVMargin)
    ]);
  }
```

- [ ] **Step 3: flutter analyze no arquivo**

```bash
cd client
flutter analyze flutter/lib/desktop/widgets/remote_toolbar.dart 2>&1 | head -30
```

Saída esperada: zero erros novos.

- [ ] **Step 4: Commit**

```bash
git add flutter/lib/desktop/widgets/remote_toolbar.dart
git commit -m "feat(toolbar): add label support to _IconSubmenuButton"
```

---

## Task 4: remote_toolbar.dart — adicionar labels em todos os botões

**Files:**
- Modify: `client/flutter/lib/desktop/widgets/remote_toolbar.dart`
- Modify: `client/src/lang/ptbr.rs`

### Contexto

Com `_IconSubmenuButton` já suportando `label`, basta passar `label:` nos botões. As strings novas precisam de tradução em ptbr.rs.

Botões e seus labels:

| Classe | label a passar | Tradução pt-BR |
|---|---|---|
| `_PinMenu` | `'Pin Toolbar'` / `'Unpin Toolbar'` | `'Fixar barra'` / `'Soltar barra'` |
| `_MobileActionMenu` | `'Mobile Actions'` | `'Mobile'` |
| `_ControlMenu` (`_IconSubmenuButton`) | `'Control Actions'` | `'Controles'` |
| `_DisplayMenu` (`_IconSubmenuButton`) | `'Display'` | `'Exibição'` |
| `_KeyboardMenu` (`_IconSubmenuButton`) | `'Keyboard'` | `'Teclado'` |
| `_ChatMenu` (submenu path) | `'Chat'` | `'Chat'` |
| `_VoiceCallMenu` (submenu path) | `'Voice call'` | `'Voz'` |
| `_RecordMenu` | `'Start session recording'` / `'Stop session recording'` | `'Gravar'` / `'Parar'` |
| `_WhiteboardMenu` | `'Annotation whiteboard'` / `'Exit annotation'` | `'Quadro'` / `'Sair'` |
| `_CloseMenu` | `'Close'` | já existente ✅ |

- [ ] **Step 1: _PinMenu — adicionar label dinâmico**

Localizar `class _PinMenu extends StatelessWidget` (~linha 474). Substituir o `return Obx(...)`:

```dart
  @override
  Widget build(BuildContext context) {
    return Obx(
      () => _IconMenuButton(
        assetName: state.pin ? "assets/pinned.svg" : "assets/unpinned.svg",
        tooltip: state.pin ? 'Unpin Toolbar' : 'Pin Toolbar',
        label: state.pin ? 'Unpin Toolbar' : 'Pin Toolbar',
        onPressed: state.switchPin,
        color:
            state.pin ? _ToolbarTheme.blueColor : _ToolbarTheme.inactiveColor,
        hoverColor: state.pin
            ? _ToolbarTheme.hoverBlueColor
            : _ToolbarTheme.hoverInactiveColor,
      ),
    );
  }
```

- [ ] **Step 2: _MobileActionMenu — adicionar label**

Localizar `class _MobileActionMenu` (~linha 493). No `return Obx(() => _IconMenuButton(...)`, adicionar `label: 'Mobile Actions',` após `tooltip: 'Mobile Actions',`.

- [ ] **Step 3: _ControlMenu — adicionar label no _IconSubmenuButton**

Localizar `return _IconSubmenuButton(` dentro de `_ControlMenu.build` (~linha 758). Adicionar `label: 'Control Actions',` após `tooltip: 'Control Actions',`.

- [ ] **Step 4: _DisplayMenu — adicionar label**

Localizar `return _IconSubmenuButton(` dentro de `_DisplayMenuState.build` (~linha 1035). Adicionar `label: 'Display',` após `tooltip: 'Display',`.

- [ ] **Step 5: _KeyboardMenu — adicionar label**

Localizar `return _IconSubmenuButton(` dentro de `_KeyboardMenu.build` (~linha 1784). Adicionar `label: 'Keyboard',` após `tooltip: 'Keyboard',`.

- [ ] **Step 6: _ChatMenu — adicionar label no submenu path**

Localizar `return _IconSubmenuButton(` dentro de `_ChatMenuState.build` (~linha 2058). Adicionar `label: 'Chat',` após `tooltip: 'Chat',`.

- [ ] **Step 7: _VoiceCallMenu — adicionar label**

Localizar `return _IconSubmenuButton(` dentro de `_VoiceCallMenu.build` (~linha 2164). Adicionar `label: 'Voice call',` após `tooltip: 'Voice call',`.

Atenção: o método pode ter múltiplos retornos. Adicionar `label:` apenas no `_IconSubmenuButton` principal (o que tem `menuChildrenGetter`), não no `_IconMenuButton` de "Waiting".

- [ ] **Step 8: _RecordMenu — adicionar label dinâmico**

Localizar `class _RecordMenu extends StatelessWidget` (~linha 2190). Substituir o `return _IconMenuButton(...)`:

```dart
    return _IconMenuButton(
      assetName: 'assets/rec.svg',
      tooltip: recordingModel.start
          ? 'Stop session recording'
          : 'Start session recording',
      label: recordingModel.start
          ? 'Stop session recording'
          : 'Start session recording',
      onPressed: () => recordingModel.toggle(),
      color: recordingModel.start
          ? _ToolbarTheme.redColor
          : _ToolbarTheme.blueColor,
      hoverColor: recordingModel.start
          ? _ToolbarTheme.hoverRedColor
          : _ToolbarTheme.hoverBlueColor,
    );
```

- [ ] **Step 9: _WhiteboardMenu — adicionar label dinâmico**

Localizar `class _WhiteboardMenu extends StatelessWidget` (~linha 2218). Dentro do `return _IconMenuButton(...)`, adicionar:

```dart
      label: active ? 'Exit annotation' : 'Annotation whiteboard',
```

após `tooltip: active ? 'Exit annotation' : 'Annotation whiteboard',`.

- [ ] **Step 10: Adicionar traduções em ptbr.rs**

No arquivo `client/src/lang/ptbr.rs`, adicionar as novas chaves (agrupadas com as chaves existentes de toolbar):

```rust
        ("Pin Toolbar", "Fixar barra"),
        ("Unpin Toolbar", "Soltar barra"),
        ("Mobile Actions", "Mobile"),
        ("Control Actions", "Controles"),
        ("Keyboard", "Teclado"),
        ("Voice call", "Voz"),
        ("Start session recording", "Gravar"),
        ("Stop session recording", "Parar"),
        ("Annotation whiteboard", "Quadro"),
        ("Exit annotation", "Sair"),
```

Nota: `"Display"`, `"Chat"` e `"Close"` já têm tradução em ptbr.rs — não duplicar.

- [ ] **Step 11: flutter analyze**

```bash
cd client
flutter analyze flutter/lib/desktop/widgets/remote_toolbar.dart 2>&1 | head -30
```

Saída esperada: zero erros novos.

- [ ] **Step 12: Commit**

```bash
git add flutter/lib/desktop/widgets/remote_toolbar.dart src/lang/ptbr.rs
git commit -m "feat(toolbar): add visible labels to all toolbar buttons — Fase 3"
```

---

## Task 5: Dividir toolbar em 3 grupos com VerticalDivider

**Files:**
- Modify: `client/flutter/lib/desktop/widgets/remote_toolbar.dart`

### Contexto

Os `toolbarItems` são montados em `_RemoteToolbar.build` (~linha 375-412) e renderizados em `Row(children: [...toolbarItems])`. Precisamos inserir `VerticalDivider` entre os grupos lógicos.

Grupos:
- **Grupo 1** (navegação/controle): _PinMenu, _MobileActionMenu, _MonitorMenu, _ControlMenu, _DisplayMenu, _KeyboardMenu
- **Grupo 2** (comunicação/ferramentas): _ChatMenu, _VoiceCallMenu, _RecordMenu, _WhiteboardMenu
- **Grupo 3** (encerrar): _CloseMenu

O divider fica em `toolbarItems` no ponto certo, após _KeyboardMenu e após _WhiteboardMenu.

- [ ] **Step 1: Adicionar helper _toolbarDivider**

Localizar `ThemeData themeData() {` (~linha 443). Adicionar o método antes dele:

```dart
  Widget _toolbarDivider() {
    return SizedBox(
      height: _ToolbarTheme.buttonSize,
      child: VerticalDivider(
        width: 8,
        thickness: 1,
        color: _ToolbarTheme.dividerColor(context),
      ),
    );
  }
```

- [ ] **Step 2: Inserir dividers no build dos toolbarItems**

Localizar o bloco que monta `toolbarItems` (~linha 392-412):

```dart
    toolbarItems
        .add(_ControlMenu(id: widget.id, ffi: widget.ffi, state: widget.state));
    toolbarItems.add(_DisplayMenu(...));
    if (widget.ffi.connType == ConnType.defaultConn) {
      toolbarItems.add(_KeyboardMenu(id: widget.id, ffi: widget.ffi));
    }
    toolbarItems.add(_ChatMenu(id: widget.id, ffi: widget.ffi));
    if (!isWeb) {
      toolbarItems.add(_VoiceCallMenu(id: widget.id, ffi: widget.ffi));
    }
    if (!isWeb) toolbarItems.add(_RecordMenu());
    toolbarItems.add(_WhiteboardMenu(ffi: widget.ffi));
    toolbarItems.add(_CloseMenu(id: widget.id, ffi: widget.ffi));
```

Substituir por:

```dart
    toolbarItems
        .add(_ControlMenu(id: widget.id, ffi: widget.ffi, state: widget.state));
    toolbarItems.add(_DisplayMenu(
      id: widget.id,
      ffi: widget.ffi,
      state: widget.state,
      setFullscreen: _setFullscreen,
    ));
    if (widget.ffi.connType == ConnType.defaultConn) {
      toolbarItems.add(_KeyboardMenu(id: widget.id, ffi: widget.ffi));
    }
    // ── Divisor: grupo 1 → grupo 2 ──
    toolbarItems.add(_toolbarDivider());
    toolbarItems.add(_ChatMenu(id: widget.id, ffi: widget.ffi));
    if (!isWeb) {
      toolbarItems.add(_VoiceCallMenu(id: widget.id, ffi: widget.ffi));
    }
    if (!isWeb) toolbarItems.add(_RecordMenu());
    toolbarItems.add(_WhiteboardMenu(ffi: widget.ffi));
    // ── Divisor: grupo 2 → grupo 3 ──
    toolbarItems.add(_toolbarDivider());
    toolbarItems.add(_CloseMenu(id: widget.id, ffi: widget.ffi));
```

- [ ] **Step 3: Verificar que _ToolbarTheme.dividerColor existe**

```bash
cd client
grep -n "dividerColor" flutter/lib/desktop/widgets/remote_toolbar.dart | head -5
```

Se existir → próximo passo. Se não existir, adicionar em `_ToolbarTheme`:
```dart
  static Color dividerColor(BuildContext context) =>
      Theme.of(context).dividerColor.withOpacity(0.4);
```

- [ ] **Step 4: flutter analyze**

```bash
cd client
flutter analyze flutter/lib/desktop/widgets/remote_toolbar.dart 2>&1 | head -30
```

Saída esperada: zero erros novos.

- [ ] **Step 5: Commit**

```bash
git add flutter/lib/desktop/widgets/remote_toolbar.dart
git commit -m "feat(toolbar): add VerticalDivider between toolbar groups — Fase 3"
```

---

## Self-Review

**Spec coverage checklist:**

| Requisito da spec | Task |
|---|---|
| "Permitir acesso" full-width com ícone | Task 2 |
| "Recusar" red outlined | Task 2 |
| Label "SOLICITANTE" acima do nome | Task 2 |
| incoming_conn_tip em ptbr | Task 1 |
| Cada botão toolbar com ícone + label | Tasks 3 + 4 |
| 3 grupos com VerticalDivider | Task 5 |
| Traduções pt-BR novas | Tasks 1, 2, 4 |

**"Só visualizar" (View only) da spec:** não implementado — funcionalidade não existe no codebase (requer mudança no servidor). Anotado como gap consciente.
