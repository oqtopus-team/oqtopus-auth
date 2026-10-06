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
from oqtopus_auth.config import (
    AuthConfig,
    HeaderProviderConfig,
    PublicIdentityConfig,
    PublicPathConfig,
    parse_auth_config,
)
from oqtopus_auth.factory import register_provider
from oqtopus_auth.fastapi import (
    AuthMiddleware,
    CurrentUser,
    FastAPIPermissions,
    PublicPath,
)


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
    return pyjwt.encode(claims, "test-secret-key-for-hs256-at-least-32-bytes", algorithm="HS256")


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
        resp = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403


# ── public_paths ───────────────────────────────────────────────────────────


def _make_app_with_public_paths(
    *,
    constructor_public_paths: list[PublicPath] | None = None,
    config_public_paths: list[PublicPathConfig] | None = None,
) -> FastAPI:
    auth_cfg = AuthConfig(
        provider="header",
        header=HeaderProviderConfig(jwt_header="authorization", user_claim="email"),
        public_paths=config_public_paths or [],
    )
    app = FastAPI()
    app.add_middleware(
        AuthMiddleware,
        auth_cfg=auth_cfg,
        public_paths=constructor_public_paths or [],
    )

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/health")
    def health_post() -> dict:
        return {"status": "ok"}

    @app.get("/devices/{device_id}")
    def device(device_id: str) -> dict:
        return {"device_id": device_id}

    @app.get("/protected")
    def protected(user: CurrentUser) -> dict:
        return {"account": user.account} if user else {}

    return app


class TestPublicPathsFromConstructor:
    def test_matching_method_and_path_skips_auth(self) -> None:
        client = TestClient(
            _make_app_with_public_paths(
                constructor_public_paths=[PublicPath("GET", "/health")]
            )
        )
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_non_matching_method_still_requires_auth(self) -> None:
        client = TestClient(
            _make_app_with_public_paths(
                constructor_public_paths=[PublicPath("GET", "/health")]
            ),
            raise_server_exceptions=False,
        )
        resp = client.post("/health")
        assert resp.status_code == 403

    def test_wildcard_method_matches_any_method(self) -> None:
        client = TestClient(
            _make_app_with_public_paths(
                constructor_public_paths=[PublicPath("*", "/health")]
            )
        )
        assert client.get("/health").status_code == 200
        assert client.post("/health").status_code == 200

    def test_path_parameter_is_matched_like_a_real_route(self) -> None:
        client = TestClient(
            _make_app_with_public_paths(
                constructor_public_paths=[PublicPath("GET", "/devices/{device_id}")]
            )
        )
        resp = client.get("/devices/abc123")
        assert resp.status_code == 200
        assert resp.json() == {"device_id": "abc123"}

    def test_other_paths_still_require_auth(self) -> None:
        client = TestClient(
            _make_app_with_public_paths(
                constructor_public_paths=[PublicPath("GET", "/health")]
            ),
            raise_server_exceptions=False,
        )
        resp = client.get("/protected")
        assert resp.status_code == 403


class TestPublicPathsFromConfig:
    def test_config_public_paths_skip_auth(self) -> None:
        client = TestClient(
            _make_app_with_public_paths(
                config_public_paths=[PublicPathConfig(method="GET", path="/health")]
            )
        )
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_config_and_constructor_public_paths_are_merged(self) -> None:
        client = TestClient(
            _make_app_with_public_paths(
                config_public_paths=[PublicPathConfig(method="GET", path="/health")],
                constructor_public_paths=[PublicPath("GET", "/devices/{device_id}")],
            )
        )
        assert client.get("/health").status_code == 200
        assert client.get("/devices/1").status_code == 200


# ── public_identity ──────────────────────────────────────────────────────────


def _make_app_with_public_identity(
    *, public_identity: PublicIdentityConfig | None
) -> FastAPI:
    auth_cfg = AuthConfig(
        provider="header",
        header=HeaderProviderConfig(jwt_header="authorization", user_claim="email"),
        public_paths=[
            PublicPathConfig(method="GET", path="/health"),
            PublicPathConfig(method="GET", path="/health-gated"),
        ],
        public_identity=public_identity,
    )
    permissions = FastAPIPermissions({"metrics-public": frozenset({"health.get"})})
    app = FastAPI()
    app.add_middleware(AuthMiddleware, auth_cfg=auth_cfg)
    app.state.permissions = permissions

    @app.get("/health")
    def health(user: CurrentUser) -> dict:
        return {"account": user.account, "roles": user.roles} if user else {}

    @app.get("/health-gated", dependencies=[permissions.require("health.get")])
    def health_gated() -> dict:
        return {"status": "ok"}

    return app


class TestPublicIdentity:
    def test_no_public_identity_leaves_user_none(self) -> None:
        client = TestClient(_make_app_with_public_identity(public_identity=None))
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_public_identity_empty_dict_in_yaml_sets_default_synthetic_user(
        self,
    ) -> None:
        """Regression test for github.com/oqtopus-team/oqtopus-auth/pull/5#discussion_r3921529535."""
        auth_cfg = parse_auth_config(
            {
                "provider": "header",
                "header": {"jwt_header": "authorization", "user_claim": "email"},
                "public_paths": [{"method": "GET", "path": "/health"}],
                "public_identity": {},
            }
        )
        app = FastAPI()
        app.add_middleware(AuthMiddleware, auth_cfg=auth_cfg)

        @app.get("/health")
        def health(user: CurrentUser) -> dict:
            return {"account": user.account, "roles": user.roles} if user else {}

        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"account": "public", "roles": []}

    def test_public_identity_sets_synthetic_user(self) -> None:
        client = TestClient(
            _make_app_with_public_identity(
                public_identity=PublicIdentityConfig(
                    default_account="anonymous", default_roles=["metrics-public"]
                )
            )
        )
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"account": "anonymous", "roles": ["metrics-public"]}

    def test_public_identity_account_defaults_to_public(self) -> None:
        client = TestClient(
            _make_app_with_public_identity(
                public_identity=PublicIdentityConfig(default_roles=["metrics-public"])
            )
        )
        resp = client.get("/health")
        assert resp.json()["account"] == "public"

    def test_no_public_identity_permission_gated_path_still_blocked(self) -> None:
        client = TestClient(
            _make_app_with_public_identity(public_identity=None),
            raise_server_exceptions=False,
        )
        resp = client.get("/health-gated")
        assert resp.status_code == 403

    def test_public_identity_unlocks_permission_gated_path(self) -> None:
        client = TestClient(
            _make_app_with_public_identity(
                public_identity=PublicIdentityConfig(default_roles=["metrics-public"])
            )
        )
        resp = client.get("/health-gated")
        assert resp.status_code == 200


def test_invalid_response_format_raises() -> None:
    # The Literal annotation is not enforced at runtime; a typo like "JSON" must
    # be rejected at construction, not silently fall back to HTML.
    auth_cfg = AuthConfig(
        provider="header",
        header=HeaderProviderConfig(jwt_header="authorization", user_claim="email"),
    )
    with pytest.raises(ValueError, match="response_format"):
        AuthMiddleware(
            lambda *_a, **_k: None,  # type: ignore[arg-type]
            auth_cfg,
            response_format="JSON",  # type: ignore[arg-type]
        )
