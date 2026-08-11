"""Unit tests for oqtopus_auth/fastapi/depends.py — require_roles and require_permission."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from oqtopus_auth.config import AuthConfig, NoneProviderConfig
from oqtopus_auth.fastapi import (
    AuthMiddleware,
    CurrentUser,
    FastAPIPermissions,
    FastAPIRoles,
    require_permission,
    require_roles,
)
from oqtopus_auth.permissions import parse_role_permissions


# ── get_current_user without AuthMiddleware ────────────────────────────────────


class TestGetCurrentUserWithoutMiddleware:
    def test_raises_runtime_error_as_500(self) -> None:
        app = FastAPI()

        @app.get("/whoami")
        def whoami(user: CurrentUser) -> dict:
            return {"account": user.account if user else None}

        client = TestClient(app, raise_server_exceptions=False)
        assert client.get("/whoami").status_code == 500


# ── require_roles / FastAPIRoles ──────────────────────────────────────────────


def _make_roles_test_app(required_roles: tuple[str, ...]) -> FastAPI:
    """Minimal app with a None provider and test routes using require_roles.

    NullProvider grants only the "operator" role.
    """
    auth_cfg = AuthConfig(
        provider="none",
        none=NoneProviderConfig(default_account="test_user", default_roles=["operator"]),
    )
    app = FastAPI()
    app.add_middleware(AuthMiddleware, auth_cfg=auth_cfg)

    roles = FastAPIRoles()

    @app.get("/require-roles-standalone", dependencies=[require_roles(*required_roles)])
    def protected_standalone() -> dict:
        return {"ok": True}

    @app.get("/require-roles-class", dependencies=[roles.require(*required_roles)])
    def protected_class() -> dict:
        return {"ok": True}

    return app


class TestRequireRoles:
    def test_single_matching_role_passes_standalone(self) -> None:
        # NullProvider gives "operator"; require_roles("operator") should pass
        app = _make_roles_test_app(("operator",))
        client = TestClient(app, raise_server_exceptions=True)
        assert client.get("/require-roles-standalone").status_code == 200

    def test_single_matching_role_passes_class(self) -> None:
        app = _make_roles_test_app(("operator",))
        client = TestClient(app, raise_server_exceptions=True)
        assert client.get("/require-roles-class").status_code == 200

    def test_single_non_matching_role_returns_403_standalone(self) -> None:
        # NullProvider gives "operator"; require_roles("admin") should fail
        app = _make_roles_test_app(("admin",))
        client = TestClient(app, raise_server_exceptions=False)
        assert client.get("/require-roles-standalone").status_code == 403

    def test_single_non_matching_role_returns_403_class(self) -> None:
        app = _make_roles_test_app(("admin",))
        client = TestClient(app, raise_server_exceptions=False)
        assert client.get("/require-roles-class").status_code == 403

    def test_multiple_roles_passes_when_user_holds_one(self) -> None:
        # user has "operator"; require_roles("admin", "operator") → OR logic → pass
        app = _make_roles_test_app(("admin", "operator"))
        client = TestClient(app, raise_server_exceptions=True)
        assert client.get("/require-roles-standalone").status_code == 200

    def test_multiple_roles_returns_403_when_user_holds_none(self) -> None:
        # user has "operator"; require_roles("admin", "superuser") → none match → 403
        app = _make_roles_test_app(("admin", "superuser"))
        client = TestClient(app, raise_server_exceptions=False)
        assert client.get("/require-roles-standalone").status_code == 403


# ── require_permission without permissions configured ─────────────────────────


def _make_no_permissions_app() -> FastAPI:
    """Minimal app with no app.state.permissions and a route using require_permission."""
    auth_cfg = AuthConfig(
        provider="none",
        none=NoneProviderConfig(default_account="test_user", default_roles=["operator"]),
    )
    app = FastAPI()
    app.add_middleware(AuthMiddleware, auth_cfg=auth_cfg)
    # app.state.permissions intentionally not set

    @app.get("/protected", dependencies=[require_permission("environment.get")])
    def protected() -> dict:
        return {"ok": True}

    return app


class TestRequirePermissionNotConfigured:
    def test_raises_runtime_error_as_500(self) -> None:
        # RuntimeError from require_permission → FastAPI returns 500
        app = _make_no_permissions_app()
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/protected")
        assert resp.status_code == 500


# ── FastAPIPermissions / require_permission with permissions configured ───────


def _make_permissions_app() -> FastAPI:
    """App with a None provider (roles=["operator"]) and permissions configured."""
    auth_cfg = AuthConfig(
        provider="none",
        none=NoneProviderConfig(default_account="test_user", default_roles=["operator"]),
    )
    app = FastAPI()
    app.add_middleware(AuthMiddleware, auth_cfg=auth_cfg)

    role_permissions = parse_role_permissions({"operator": ["environment.get"]})
    permissions = FastAPIPermissions(role_permissions)
    app.state.permissions = permissions

    @app.get("/via-instance", dependencies=[permissions.require("environment.get")])
    def via_instance() -> dict:
        return {"ok": True}

    @app.get("/via-instance-denied", dependencies=[permissions.require("app_settings.update")])
    def via_instance_denied() -> dict:
        return {"ok": True}

    @app.get("/via-function", dependencies=[require_permission("environment.get")])
    def via_function() -> dict:
        return {"ok": True}

    @app.get("/via-function-denied", dependencies=[require_permission("app_settings.update")])
    def via_function_denied() -> dict:
        return {"ok": True}

    return app


class TestFastAPIPermissionsConfigured:
    def test_instance_require_passes_when_permission_granted(self) -> None:
        client = TestClient(_make_permissions_app(), raise_server_exceptions=True)
        assert client.get("/via-instance").status_code == 200

    def test_instance_require_returns_403_when_permission_missing(self) -> None:
        client = TestClient(_make_permissions_app(), raise_server_exceptions=False)
        assert client.get("/via-instance-denied").status_code == 403

    def test_function_require_passes_when_permission_granted(self) -> None:
        client = TestClient(_make_permissions_app(), raise_server_exceptions=True)
        assert client.get("/via-function").status_code == 200

    def test_function_require_returns_403_when_permission_missing(self) -> None:
        client = TestClient(_make_permissions_app(), raise_server_exceptions=False)
        assert client.get("/via-function-denied").status_code == 403
