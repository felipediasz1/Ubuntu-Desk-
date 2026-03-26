#!/usr/bin/env python3
"""
CLI de administração para o painel Ubuntu Desk.
Uso: python admin/cli.py disable-2fa <username>
"""
import sys
import os
import sqlite3


def disable_2fa(username: str):
    db_path = os.environ.get("API_DB", os.path.join(os.path.dirname(__file__), "data", "api.db"))
    if not os.path.exists(db_path):
        print(f"Erro: banco não encontrado em {db_path}", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(db_path)
    cur = conn.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE username=?", (username,))
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        print(f"Usuário '{username}' não encontrado.")
        sys.exit(1)
    print(f"2FA desativado para '{username}'.")


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] != "disable-2fa":
        print("Uso: python cli.py disable-2fa <username>")
        sys.exit(1)
    disable_2fa(sys.argv[2])
