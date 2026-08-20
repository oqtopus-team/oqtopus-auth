"""Integration tests for oqtopus_auth/fastapi/middleware.py via HTTP."""

from __future__ import annotations

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from oqtopus_auth.base import (
    AuthContext,
    AuthenticationError,
    AuthorizationError,
    AuthProvider,
    AuthUser,
    InsufficientScopeError,
)
from oqtopus_auth.config import AuthConfig, HeaderProviderConfig
from oqtopus_auth.factory import register_provider
from oqtopus_auth.fastapi import AuthMiddleware, CurrentUser


def _make_header_app() -> FastAPI:
    auth_cfg = AuthConfig(
        provider="header",
        header=HeaderProviderConfig(
            jwt_header="authorization",
            user_claim="email",
            roles_claim="groups",
            allow_raw_roles=["test.*"],
        ),
        role_mappings={"test.admin": "operator"},
    )
    app = FastAPI()
    app.add_middleware(AuthMiddleware, auth_cfg=auth_cfg)

    @app.get("/protected")
    def protected(user: CurrentUser) -> dict:
        return {"account": user.account, "roles": user.roles} if user else {}

    return app


def _make_jwt(claims: dict) -> str:
    """Create an unsigned-verifiable HS256 JWT (signature verification disabled)."""
    return pyjwt.encode(claims, "test-secret", algorithm="HS256")


@pytest.fixture
def header_auth_client() -> TestClient:
    return TestClient(_make_header_app(), raise_server_exceptions=False)


# ── HeaderProvider via HTTP middleware ────────────────────────────────────────


class TestHeaderProviderViaMiddleware:
    def test_missing_jwt_returns_403(self, header_auth_client: TestClient) -> None:
        resp = header_auth_client.get("/protected")
        assert resp.status_code == 403

    def test_malformed_bearer_returns_403(self, header_auth_client: TestClient) -> None:
        resp = header_auth_client.get(
            "/protected", headers={"Authorization": "not-bearer-format"}
        )
        assert resp.status_code == 403

    def test_valid_jwt_with_allowed_role_passes(
        self, header_auth_client: TestClient
    ) -> None:
        token = _make_jwt({"email": "u@example.com", "groups": ["test.admin"]})
        resp = header_auth_client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["account"] == "u@example.com"
        assert body["roles"] == ["operator"]

    def test_jwt_with_no_matching_role_returns_403(
        self, header_auth_client: TestClient
    ) -> None:
        token = _make_jwt({"email": "u@example.com", "groups": ["other.role"]})
        resp = header_auth_client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403

    def test_jwt_with_empty_groups_returns_403(
        self, header_auth_client: TestClient
    ) -> None:
        token = _make_jwt({"email": "u@example.com", "groups": []})
        resp = header_auth_client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403


# ── JSON response format: 401 (authn) vs 403 (authz) ──────────────────────────


class _RaisingProvider(AuthProvider):
    def __init__(self, error: AuthenticationError) -> None:
        self._error = error

    async def authenticate(self, context: AuthContext) -> AuthUser | None:
        raise self._error


def _make_json_app(error: AuthenticationError) -> FastAPI:
    name = f"raise-{type(error).__name__}"
    register_provider(name, lambda _cfg: _RaisingProvider(error))
    app = FastAPI()
    app.add_middleware(
        AuthMiddleware, auth_cfg=AuthConfig(provider=name), response_format="json"
    )

    @app.get("/protected")
    def protected(user: CurrentUser) -> dict:
        return {"account": user.account if user else None}

    return app


class TestJsonResponseFormat:
    def test_authentication_error_is_401_json_with_challenge(self) -> None:
        client = TestClient(
            _make_json_app(AuthenticationError("missing bearer token")),
            raise_server_exceptions=False,
        )
        resp = client.get("/protected")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "missing bearer token"
        assert resp.headers["WWW-Authenticate"] == "Bearer"

    def test_insufficient_scope_is_403_json_with_scope_challenge(self) -> None:
        client = TestClient(
            _make_json_app(InsufficientScopeError("missing required scope 'x'")),
            raise_server_exceptions=False,
        )
        resp = client.get("/protected")
        assert resp.status_code == 403
        assert "scope" in resp.json()["detail"]
        assert "insufficient_scope" in resp.headers["WWW-Authenticate"]

    def test_generic_authorization_error_is_403_without_scope_challenge(self) -> None:
        # A role (RBAC) denial must NOT be labelled insufficient_scope.
        client = TestClient(
            _make_json_app(AuthorizationError("no allowed role")),
            raise_server_exceptions=False,
        )
        resp = client.get("/protected")
        assert resp.status_code == 403
        assert "insufficient_scope" not in resp.headers.get("WWW-Authenticate", "")


# ── HeaderProvider under JSON mode: authn=401, authz=403 ──────────────────────


def _make_header_json_app() -> FastAPI:
    auth_cfg = AuthConfig(
        provider="header",
        header=HeaderProviderConfig(
            jwt_header="authorization",
            user_claim="email",
            roles_claim="groups",
            allow_raw_roles=["test.*"],
        ),
    )
    app = FastAPI()
    app.add_middleware(AuthMiddleware, auth_cfg=auth_cfg, response_format="json")

    @app.get("/protected")
    def protected(user: CurrentUser) -> dict:
        return {"account": user.account if user else None}

    return app


class TestHeaderProviderJsonMode:
    def test_missing_jwt_is_401(self) -> None:
        client = TestClient(_make_header_json_app(), raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 401

    def test_no_matching_role_is_403(self) -> None:
        client = TestClient(_make_header_json_app(), raise_server_exceptions=False)
        token = _make_jwt({"email": "u@example.com", "groups": ["other.role"]})
        resp = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403
