"""Email shape validation for console account identities.

Regression context: the register endpoint previously accepted any 3-255 char
string as an account email, so malformed values such as ``http/l8000@qq.com``
could be stored as a real identity. These tests pin the accepted/rejected
shapes and the API-level behaviour.

Ordering does not matter here: the email check runs *before* the bootstrap
gate in ``register_console_user``, so malformed input yields 400 regardless of
whether the console admin already exists.
"""

from __future__ import annotations

import pytest

from app.utils import is_valid_email

VALID_EMAILS = [
    "name@example.com",
    "a.b+tag@sub.domain.co",
    "USER@EXAMPLE.COM",
    "x_y-z%1@a-b.io",
    "a@b.cn",
    "first.last@my-company.com.cn",
]

INVALID_EMAILS = [
    "http/l8000@qq.com",  # exact value from the bug report
    "notanemail",
    "a@b",  # no TLD
    "a@b.c",  # 1-char TLD
    "a@b.123",  # numeric TLD
    "a@.com",
    "a@b.",
    "a@b..com",
    "a@-b.com",
    "a@b-.com",
    ".a@b.com",
    "a.@b.com",
    "a..b@c.com",
    "a@@b.com",
    "a b@c.com",
    "@b.com",
    "a@b.com/",
    "中文@qq.com",
    "",
    "ab",
]


@pytest.mark.parametrize("email", VALID_EMAILS)
def test_valid_emails_accepted(email: str):
    assert is_valid_email(email) is True


@pytest.mark.parametrize("email", INVALID_EMAILS)
def test_invalid_emails_rejected(email: str):
    assert is_valid_email(email) is False


def test_longer_than_255_rejected():
    assert is_valid_email("a" * 250 + "@example.com") is False


def test_local_part_longer_than_64_rejected():
    assert is_valid_email("a" * 65 + "@example.com") is False


def test_non_string_rejected():
    assert is_valid_email(None) is False  # type: ignore[arg-type]


def test_whitespace_is_stripped_before_validation():
    assert is_valid_email("  name@example.com  ") is True


def test_register_rejects_malformed_email(client, unique_id: str):
    response = client.post(
        "/api/v1/auth/register",
        json={"name": "Pytest User", "email": "http/l8000@qq.com", "password": "pass-123456"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_email"


def test_register_rejects_email_without_at(client, unique_id: str):
    response = client.post(
        "/api/v1/auth/register",
        json={"name": "Pytest User", "email": "notanemail", "password": "pass-123456"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_email"


def test_login_with_malformed_email_is_401_not_500(client, unique_id: str):
    """Login stays permissive on shape: it must not crash, and accounts created
    before this validation was introduced must not be locked out by it."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "http/l8000@qq.com", "password": "pass-123456"},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["error"] == "invalid_credentials"
