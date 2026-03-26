# admin/tests/conftest.py
import os
import sys
import re
import pytest

# Ensure the admin package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("ADMIN_PASSWORD", "test-admin-pass")
os.environ.setdefault("HTTPS_ONLY", "0")

import app as flask_app


@pytest.fixture
def tmp_dbs(tmp_path):
    """Override API_DB and AUDIT_DB to temporary files for each test."""
    api_db   = str(tmp_path / "api.db")
    audit_db = str(tmp_path / "audit.db")
    flask_app.API_DB   = api_db
    flask_app.AUDIT_DB = audit_db
    flask_app._api_db_initialized   = False
    flask_app._audit_db_initialized = False
    flask_app._audit_purged         = False
    yield {"api_db": api_db, "audit_db": audit_db}


@pytest.fixture
def client(tmp_dbs):
    flask_app.app.config["TESTING"] = True
    # Force DB initialization so admin user is seeded before any test calls /api/login
    flask_app._get_api_db().close()
    with flask_app.app.test_client() as c:
        yield c


@pytest.fixture
def client_with_sessions(tmp_path):
    """Client with sessions DB override."""
    api_db      = str(tmp_path / "api.db")
    audit_db    = str(tmp_path / "audit.db")
    sessions_db = str(tmp_path / "sessions.db")
    flask_app.API_DB      = api_db
    flask_app.AUDIT_DB    = audit_db
    flask_app.SESSIONS_DB = sessions_db
    flask_app._api_db_initialized      = False
    flask_app._audit_db_initialized    = False
    flask_app._sessions_db_initialized = False
    flask_app._audit_purged            = False
    flask_app.app.config["TESTING"] = True
    flask_app._get_api_db().close()
    with flask_app.app.test_client() as c:
        yield c


def _get_csrf(client):
    rv = client.get("/login")
    m = re.search(r'name="csrf_token" value="([^"]+)"', rv.data.decode())
    return m.group(1) if m else ""
