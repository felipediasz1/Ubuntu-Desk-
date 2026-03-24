# admin/tests/test_users_db.py
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("ADMIN_PASSWORD", "test-admin-pass")
os.environ.setdefault("HTTPS_ONLY", "0")
import app as flask_app


def test_hash_and_verify_password():
    h = flask_app._hash_user_password("mypassword")
    assert "$" in h
    assert flask_app._verify_user_password("mypassword", h) is True
    assert flask_app._verify_user_password("wrongpass", h) is False


def test_two_hashes_are_different():
    h1 = flask_app._hash_user_password("same")
    h2 = flask_app._hash_user_password("same")
    assert h1 != h2  # different salts
