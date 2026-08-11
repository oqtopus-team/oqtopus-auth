"""FastAPI dependencies for authentication and authorization."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, HTTPException, Request

from ..base import AuthUser  # noqa: TID252
from ..permissions import Permissions, has_permission  # noqa: TID252

if TYPE_CHECKING:
    from fastapi.params import Depends as DependsType


# ── Authentication ────────────────────────────────────────────────────────────


_AUTH_MIDDLEWARE_NOT_CONFIGURED = (
    "get_current_user() called but request.state.user is not set. "
    "Did you forget app.add_middleware(AuthMiddleware, auth_cfg=...)?"
)


def get_current_user(request: Request) -> AuthUser | None:
    """Extract the authenticated user from request state (set by AuthMiddleware).

    Returns:
        The authenticated user, or None when no user is present.

    Raises:
        RuntimeError: If AuthMiddleware was never registered on the app.

    """
    if not hasattr(request.state, "user"):
        raise RuntimeError(_AUTH_MIDDLEWARE_NOT_CONFIGURED)
    return request.state.user


CurrentUser = Annotated[AuthUser | None, Depends(get_current_user)]


# ── Role-based access control ─────────────────────────────────────────────────
#
# Requires no configuration — roles come from the auth middleware.
# Use when ``permissions:`` is not needed and role membership is sufficient.


class FastAPIRoles:
    """FastAPI role checker that requires no configuration.

    Roles are read directly from the authenticated user set by AuthMiddleware.
    Use this when you need role-based access control without a permission mapping.

    ``require()`` is a static method, so instantiation is not required.
    Prefer the standalone :func:`require_roles` function for route decorators::

        @router.get("/admin", dependencies=[require_roles("admin")])
        async def admin_page(request: Request) -> HTMLResponse:
            ...

        # Multiple roles: pass if the user holds ANY of the specified roles
        @router.get("/ops", dependencies=[require_roles("admin", "operator")])
        async def ops_page(request: Request) -> HTMLResponse:
            ...

    ``FastAPIRoles`` is retained for cases where a class interface is preferred
    for consistency with :class:`FastAPIPermissions`.

    """

    @staticmethod
    def require(*roles: str) -> DependsType:
        """Return a dependency that raises 403 if the user holds none of the roles.

        Pass one or more role names.  Access is granted when the user holds
        **at least one** of them (OR logic).

        Returns:
            A ``Depends`` instance suitable for ``dependencies=[...]``.

        """
        return require_roles(*roles)


def require_roles(*roles: str) -> DependsType:
    """Return a FastAPI dependency that raises 403 if the user holds none of the roles.

    Pass one or more role names.  Access is granted when the user holds
    **at least one** of them (OR logic).

    Reads roles directly from the authenticated user — no permission mapping
    needed.  Use this when you want role-based access control without a
    ``permissions:`` config section.

    Returns:
        A ``Depends`` instance that raises 403 if the check fails.

    """

    def check(user: CurrentUser) -> AuthUser | None:
        if user is None or not any(role in user.roles for role in roles):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return Depends(check)


# ── Permission-based access control ──────────────────────────────────────────
#
# Requires a resolved role → permissions mapping (see parse_role_permissions).
# Maps roles to fine-grained permission strings (e.g. "environment.get").


class FastAPIPermissions(Permissions):
    """FastAPI-aware permission checker that extends :class:`Permissions`.

    Adds :meth:`require`, a FastAPI dependency factory, to the framework-agnostic
    :meth:`has_permission` inherited from the base class.

    Create one instance per application and use it as follows::

        permissions = FastAPIPermissions(role_permissions)

        @router.get("/settings", dependencies=[permissions.require("app_settings.get")])
        async def settings(request: Request) -> HTMLResponse:
            can_edit = permissions.has_permission(
                request.state.user, "app_settings.update"
            )

    """

    def require(self, permission: str) -> DependsType:
        """Return a FastAPI dependency that raises 403 if the permission is absent.

        Returns:
            A ``Depends`` instance suitable for ``dependencies=[...]``.

        """
        role_permissions = self._role_permissions

        def check(user: CurrentUser) -> AuthUser | None:
            if not has_permission(user, permission, role_permissions):
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return user

        return Depends(check)


_PERMISSIONS_NOT_CONFIGURED = (
    "require_permission() called but no permissions are configured. "
    "Set app.state.permissions to a FastAPIPermissions instance, "
    "or use require_roles() for role-based access control."
)


def require_permission(permission: str) -> DependsType:
    """Return a FastAPI dependency that enforces the given permission.

    Reads the :class:`FastAPIPermissions` instance from
    ``request.app.state.permissions``.  This is a convenience function for
    applications where route modules are imported before the
    ``FastAPIPermissions`` instance is constructed (e.g. when routes are
    registered inside an application factory).

    For new projects that control the import order, prefer
    ``FastAPIPermissions.require()`` instead.

    Returns:
        A ``Depends`` instance that raises 403 if the check fails, or 500
        if no permissions are configured.

    """

    def check(request: Request, user: CurrentUser) -> AuthUser | None:
        permissions: FastAPIPermissions | None = getattr(
            request.app.state, "permissions", None
        )
        if permissions is None:
            # Developer error: app.state.permissions was never set
            raise RuntimeError(_PERMISSIONS_NOT_CONFIGURED)
        if not permissions.has_permission(user, permission):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return Depends(check)
