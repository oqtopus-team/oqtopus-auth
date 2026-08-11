"""FastAPI integration for the auth package."""

from .depends import (
    CurrentUser,
    FastAPIPermissions,
    FastAPIRoles,
    get_current_user,
    require_permission,
    require_roles,
)
from .middleware import AuthMiddleware

__all__ = [
    "AuthMiddleware",
    "CurrentUser",
    "FastAPIPermissions",
    "FastAPIRoles",
    "get_current_user",
    "require_permission",
    "require_roles",
]
