import os, time, sqlite3, pytest
import app as flask_app
from app import _backup_databases, _cleanup_old_backups

def test_backup_creates_files(tmp_path, monkeypatch):
    api_db = tmp_path / "api.db"
    audit_db = tmp_path / "audit.db"
    sessions_db = tmp_path / "sessions.db"
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
    for i in range(10):
        day = f"2026-01-{i+1:02d}"
        (tmp_path / day).mkdir()
    _cleanup_old_backups(str(tmp_path), retention_days=7)
    remaining = list(tmp_path.iterdir())
    assert len(remaining) <= 7

def test_backup_handles_missing_db_gracefully(tmp_path):
    backup_dir = tmp_path / "backups"
    try:
        _backup_databases(str(backup_dir))
    except Exception as e:
        pytest.fail(f"backup raised exception: {e}")
