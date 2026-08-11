"""Permission utilities.

Verb vocabulary: get / create / update / delete / manage
Format: <resource>.<action> or <resource>.<sub-resource>.<action>

Role-to-permission mappings are defined in the host application's own
configuration (e.g. under a ``permissions:`` key), not in this module. This
module only provides the ``has_permission`` helper and the ``Permissions``
class built on top of it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import AuthUser


def parse_role_permissions(raw: dict) -> dict[str, frozenset[str]]:
    """Parse a permissions config dict into a resolved role → permissions mapping.

    The ``_extends_`` key defines single-level inheritance: a role listed there
    inherits all permissions of its parent role in addition to its own.

    Returns:
        Mapping of role name to resolved frozenset of permission strings.

    """
    extends: dict[str, str] = raw.get("_extends_") or {}
    base: dict[str, set[str]] = {
        key: set(value)
        for key, value in raw.items()
        if key != "_extends_" and isinstance(value, list)
    }
    resolved: dict[str, frozenset[str]] = {}
    for role, perms in base.items():
        parent = extends.get(role)
        parent_perms = base.get(parent, set()) if parent else set()
        resolved[role] = frozenset(perms | parent_perms)
    return resolved


def has_permission(
    user: AuthUser | None,
    permission: str,
    role_permissions: dict[str, frozenset[str]],
) -> bool:
    """Return True if the user holds any role that grants the given permission.

    Returns:
        True if the user has the permission, False otherwise.

    """
    if user is None:
        return False
    for role in user.roles:
        role_perms = role_permissions.get(role, frozenset())
        if "*" in role_perms or permission in role_perms:
            return True
    return False


class Permissions:
    """Framework-agnostic permission checker bound to a role-permissions mapping.

    Instantiate once with the resolved mapping and use
    :meth:`has_permission` in route handlers or templates.

    For dependency-injection-based web frameworks, see the optional
    framework-specific extension modules (e.g. :mod:`oqtopus_auth.fastapi`
    for FastAPI), which extend this class with a :meth:`require` method.

    """

    def __init__(self, role_permissions: dict[str, frozenset[str]]) -> None:
        self._role_permissions = role_permissions

    def has_permission(self, user: AuthUser | None, permission: str) -> bool:
        """Return True if the user holds the given permission.

        Returns:
            True if the user has the permission, False otherwise.

        """
        return has_permission(user, permission, self._role_permissions)
