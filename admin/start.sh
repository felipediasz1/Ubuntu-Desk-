#!/usr/bin/env bash
# Ubuntu Desk — Admin Panel (Linux/macOS)
# Uso: ./start.sh
# Variaveis opcionais: ADMIN_PASSWORD, PORT, DB_PATH, SECRET_KEY

set -euo pipefail
cd "$(dirname "$0")"

# Verificar Python
command -v python3 >/dev/null || { echo "[ERRO] Python3 não encontrado."; exit 1; }

# Instalar Flask se necessário
if ! python3 -c "import flask" 2>/dev/null; then
  echo "Instalando Flask..."
  python3 -m pip install flask --quiet
fi

export ADMIN_PASSWORD="${ADMIN_PASSWORD:-ubuntu-desk-admin}"
export PORT="${PORT:-8088}"
export SECRET_KEY="${SECRET_KEY:-mude-esta-chave-em-producao}"
export DB_PATH="${DB_PATH:-../server/data/db_v2.sqlite3}"

echo ""
echo " ========================================"
echo "  Ubuntu Desk - Painel de Administração"
echo " ========================================"
echo "  URL:   http://localhost:$PORT"
echo "  Senha: $ADMIN_PASSWORD"
echo ""
echo " Pressione Ctrl+C para parar."
echo ""

python3 app.py
