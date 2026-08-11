"""Integration tests for oqtopus_auth/fastapi/middleware.py via HTTP."""

from __future__ import annotations

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from oqtopus_auth.config import AuthConfig, HeaderProviderConfig
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
