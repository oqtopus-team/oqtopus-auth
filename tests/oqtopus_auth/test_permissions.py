"""Unit tests for oqtopus_auth/permissions.py — parse_role_permissions and has_permission."""

from __future__ import annotations

from oqtopus_auth.base import AuthUser
from oqtopus_auth.permissions import Permissions, has_permission, parse_role_permissions


# ── parse_role_permissions ────────────────────────────────────────────────────


class TestParseRolePermissions:
    def test_basic_roles_without_inheritance(self) -> None:
        raw = {
            "operator": ["environment.get", "environment.create"],
            "admin": ["app_settings.update"],
        }
        result = parse_role_permissions(raw)
        assert result["operator"] == frozenset({"environment.get", "environment.create"})
        assert result["admin"] == frozenset({"app_settings.update"})

    def test_extends_child_inherits_parent_permissions(self) -> None:
        raw = {
            "_extends_": {"admin": "operator"},
            "operator": ["environment.get"],
            "admin": ["app_settings.update"],
        }
        result = parse_role_permissions(raw)
        # admin should hold its own + operator's permissions
        assert result["admin"] == frozenset({"app_settings.update", "environment.get"})

    def test_extends_parent_permissions_unchanged(self) -> None:
        raw = {
            "_extends_": {"admin": "operator"},
            "operator": ["environment.get"],
            "admin": ["app_settings.update"],
        }
        result = parse_role_permissions(raw)
        # operator must not gain admin's permissions
        assert result["operator"] == frozenset({"environment.get"})

    def test_extends_unknown_parent_gives_own_permissions_only(self) -> None:
        raw = {
            "_extends_": {"admin": "nonexistent"},
            "admin": ["app_settings.update"],
        }
        result = parse_role_permissions(raw)
        assert result["admin"] == frozenset({"app_settings.update"})

    def test_no_extends_key(self) -> None:
        raw = {"operator": ["environment.get"]}
        result = parse_role_permissions(raw)
        assert result["operator"] == frozenset({"environment.get"})

    def test_empty_extends(self) -> None:
        raw = {"_extends_": {}, "operator": ["environment.get"]}
        result = parse_role_permissions(raw)
        assert result["operator"] == frozenset({"environment.get"})

    def test_empty_permission_list(self) -> None:
        raw: dict = {"guest": []}
        result = parse_role_permissions(raw)
        assert result["guest"] == frozenset()

    def test_wildcard_permission_preserved(self) -> None:
        raw = {"superuser": ["*"]}
        result = parse_role_permissions(raw)
        assert "*" in result["superuser"]

    def test_extends_wildcard_inherited(self) -> None:
        raw = {
            "_extends_": {"admin": "superuser"},
            "superuser": ["*"],
            "admin": ["app_settings.update"],
        }
        result = parse_role_permissions(raw)
        assert "*" in result["admin"]


# ── has_permission ────────────────────────────────────────────────────────────


class TestHasPermission:
    def _rp(self, raw: dict) -> dict[str, frozenset[str]]:
        return parse_role_permissions(raw)

    def test_user_with_permission_returns_true(self) -> None:
        role_permissions = self._rp({"operator": ["environment.get"]})
        user = AuthUser(account="a@b.com", roles=["operator"])
        assert has_permission(user, "environment.get", role_permissions) is True

    def test_user_without_permission_returns_false(self) -> None:
        role_permissions = self._rp({"operator": ["environment.get"]})
        user = AuthUser(account="a@b.com", roles=["operator"])
        assert has_permission(user, "app_settings.update", role_permissions) is False

    def test_user_none_returns_false(self) -> None:
        role_permissions = self._rp({"operator": ["environment.get"]})
        assert has_permission(None, "environment.get", role_permissions) is False

    def test_wildcard_grants_any_permission(self) -> None:
        role_permissions = self._rp({"superuser": ["*"]})
        user = AuthUser(account="a@b.com", roles=["superuser"])
        assert has_permission(user, "anything.at.all", role_permissions) is True

    def test_user_with_multiple_roles_one_matches(self) -> None:
        role_permissions = self._rp(
            {"operator": ["environment.get"], "admin": ["app_settings.update"]}
        )
        user = AuthUser(account="a@b.com", roles=["operator", "admin"])
        assert has_permission(user, "app_settings.update", role_permissions) is True

    def test_unmapped_role_grants_nothing(self) -> None:
        role_permissions = self._rp({"operator": ["environment.get"]})
        user = AuthUser(account="a@b.com", roles=["unknown_role"])
        assert has_permission(user, "environment.get", role_permissions) is False

    def test_inherited_permission_via_extends(self) -> None:
        role_permissions = self._rp(
            {
                "_extends_": {"admin": "operator"},
                "operator": ["environment.get"],
                "admin": ["app_settings.update"],
            }
        )
        user = AuthUser(account="a@b.com", roles=["admin"])
        # admin inherits environment.get from operator
        assert has_permission(user, "environment.get", role_permissions) is True

    def test_empty_roles_returns_false(self) -> None:
        role_permissions = self._rp({"operator": ["environment.get"]})
        user = AuthUser(account="a@b.com", roles=[])
        assert has_permission(user, "environment.get", role_permissions) is False


# ── Permissions class ─────────────────────────────────────────────────────────


class TestPermissionsClass:
    def test_has_permission_delegates_correctly(self) -> None:
        role_permissions = parse_role_permissions({"operator": ["environment.get"]})
        checker = Permissions(role_permissions)
        user = AuthUser(account="a@b.com", roles=["operator"])
        assert checker.has_permission(user, "environment.get") is True
        assert checker.has_permission(user, "app_settings.update") is False

    def test_has_permission_with_none_user(self) -> None:
        role_permissions = parse_role_permissions({"operator": ["environment.get"]})
        checker = Permissions(role_permissions)
        assert checker.has_permission(None, "environment.get") is False
