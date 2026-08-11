"""Unit tests for oqtopus_auth/base.py."""

from __future__ import annotations

from oqtopus_auth.base import AuthContext, AuthenticationError, AuthUser


# ── AuthUser ──────────────────────────────────────────────────────────────────


class TestAuthUser:
    def test_role_returns_first_role(self) -> None:
        user = AuthUser(account="a@b.com", roles=["admin", "user"])
        assert user.role == "admin"

    def test_role_empty_returns_empty_string(self) -> None:
        user = AuthUser(account="a@b.com", roles=[])
        assert user.role == ""


# ── AuthenticationError ───────────────────────────────────────────────────────


class TestAuthenticationError:
    def test_stores_reason(self) -> None:
        err = AuthenticationError("missing JWT")
        assert err.reason == "missing JWT"
        assert str(err) == "missing JWT"


# ── AuthContext ───────────────────────────────────────────────────────────────


class TestAuthContext:
    def test_getitem_and_get(self) -> None:
        context = AuthContext(context={"authorization": "Bearer abc"})
        assert context["authorization"] == "Bearer abc"
        assert context.get("missing") is None

    def test_iter_and_len(self) -> None:
        context = AuthContext(context={"a": "1", "b": "2"})
        assert len(context) == 2
        assert set(context) == {"a", "b"}
