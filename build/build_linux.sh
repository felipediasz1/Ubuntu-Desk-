#!/usr/bin/env bash
# Ubuntu Desk — Build Script Linux
# Uso: ./build/build_linux.sh [--release] [--deb]
# Requer: Rust, Flutter, vcpkg, Python3, deps do sistema

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENT="$ROOT/client"
DIST="$ROOT/dist/linux"
RELEASE=false
DEB=false

for arg in "$@"; do
  case $arg in
    --release) RELEASE=true ;;
    --deb)     DEB=true ;;
  esac
done

step() { echo -e "\n\033[36m==> $1\033[0m"; }
ok()   { echo -e "    \033[32m[OK]\033[0m $1"; }
fail() { echo -e "    \033[31m[ERRO]\033[0m $1"; exit 1; }

# ── 1. Verificar dependências ──────────────────────────────────────
step "Verificando dependências..."

command -v rustc   >/dev/null || fail "Rust não encontrado. Instale via rustup.rs"
command -v flutter >/dev/null || fail "Flutter não encontrado. Adicione ao PATH"
command -v python3 >/dev/null || fail "Python3 não encontrado"
command -v cargo   >/dev/null || fail "cargo não encontrado"

ok "rustc   $(rustc --version)"
ok "flutter $(flutter --version --machine 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("frameworkVersion","?"))' 2>/dev/null || echo 'ok')"
ok "python3 $(python3 --version)"

# ── 2. vcpkg ──────────────────────────────────────────────────────
step "Verificando vcpkg..."

VCPKG_ROOT="${VCPKG_ROOT:-/opt/vcpkg}"
if [ ! -f "$VCPKG_ROOT/vcpkg" ]; then
  fail "vcpkg não encontrado em $VCPKG_ROOT. Defina VCPKG_ROOT ou instale em /opt/vcpkg"
fi
export VCPKG_ROOT

PACKAGES=("libvpx:x64-linux" "libyuv:x64-linux" "opus:x64-linux" "aom:x64-linux")
VCPKG_LIST=$("$VCPKG_ROOT/vcpkg" list 2>/dev/null)  # chamada única — evita 4 subprocessos sequenciais
for pkg in "${PACKAGES[@]}"; do
  name="${pkg%%:*}"
  if echo "$VCPKG_LIST" | grep -q "^$name"; then
    ok "$pkg"
  else
    echo "    Instalando $pkg..."
    "$VCPKG_ROOT/vcpkg" install "$pkg"
  fi
done

# ── 3. Build ──────────────────────────────────────────────────────
step "Build Flutter ($( $RELEASE && echo 'release' || echo 'debug' ))..."

cd "$CLIENT"

BUILD_ARGS="--flutter"
$RELEASE && BUILD_ARGS="$BUILD_ARGS --release"

python3 build.py $BUILD_ARGS
ok "Build concluído"

# ── 4. Copiar artefatos ────────────────────────────────────────────
step "Copiando artefatos para dist/linux..."

FLUTTER_OUT="$CLIENT/flutter/build/linux/x64/release/bundle"
[ -d "$FLUTTER_OUT" ] || fail "Diretório de saída não encontrado: $FLUTTER_OUT"

rm -rf "$DIST" && mkdir -p "$DIST"
cp -r "$FLUTTER_OUT"/. "$DIST/"

# Fallback: renomear se o binário ainda sair com o nome antigo
if [ -f "$DIST/rustdesk" ]; then
  mv "$DIST/rustdesk" "$DIST/ubuntu-desk"
fi

chmod +x "$DIST/ubuntu-desk"
ok "Artefatos em: $DIST"

# ── 5. Gerar .deb (opcional) ──────────────────────────────────────
if $DEB; then
  step "Gerando pacote .deb..."

  command -v dpkg-deb >/dev/null || fail "dpkg-deb não encontrado (instale dpkg)"

  VERSION=$(grep '^version' "$CLIENT/Cargo.toml" | head -1 | sed 's/.*= *"\(.*\)"/\1/')
  PKG_DIR="/tmp/ubuntu-desk_${VERSION}_amd64"
  DEB_FILE="$ROOT/dist/ubuntu-desk_${VERSION}_amd64.deb"

  rm -rf "$PKG_DIR"
  mkdir -p "$PKG_DIR/DEBIAN"
  mkdir -p "$PKG_DIR/usr/bin"
  mkdir -p "$PKG_DIR/usr/share/applications"
  mkdir -p "$PKG_DIR/usr/share/icons/hicolor/128x128/apps"

  cp -r "$DIST"/. "$PKG_DIR/usr/bin/"

  cp "$CLIENT/res/128x128.png" \
     "$PKG_DIR/usr/share/icons/hicolor/128x128/apps/ubuntu-desk.png"

  cat > "$PKG_DIR/usr/share/applications/ubuntu-desk.desktop" << DESKTOP
[Desktop Entry]
Name=Ubuntu Desk
Comment=Remote Desktop Software
Exec=/usr/bin/ubuntu-desk
Icon=ubuntu-desk
Terminal=false
Type=Application
Categories=Network;RemoteAccess;
DESKTOP

  cat > "$PKG_DIR/DEBIAN/control" << CONTROL
Package: ubuntu-desk
Version: $VERSION
Architecture: amd64
Maintainer: Ubuntu Desk <admin@ubuntudesk.app>
Description: Ubuntu Desk Remote Desktop
 Fast and secure open source remote desktop solution.
Depends: libgtk-3-0, libglib2.0-0
CONTROL

  dpkg-deb --build "$PKG_DIR" "$DEB_FILE"
  ok "Pacote .deb: $DEB_FILE"
fi

# ── 6. Resumo ──────────────────────────────────────────────────────
echo ""
echo -e "  \033[32m✅ Ubuntu Desk build Linux concluído!\033[0m"
echo -e "  \033[36m📁 Saída: $DIST\033[0m"
echo -e "  \033[36m🚀 Executável: ubuntu-desk\033[0m"
$DEB && echo -e "  \033[36m📦 .deb: dist/\033[0m"
echo ""
