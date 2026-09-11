"""FastAPI middleware that delegates authentication to the configured provider."""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from fastapi.responses import HTMLResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Match, Route

from ..base import AuthContext, AuthenticationError, AuthUser  # noqa: TID252
from ..factory import build_provider  # noqa: TID252

if TYPE_CHECKING:
    from collections.abc import Sequence

    from fastapi import Request
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.types import ASGIApp, Scope

    from ..config import AuthConfig  # noqa: TID252


def _noop_endpoint() -> None:  # pragma: no cover - only used for path matching
    """Serve as a placeholder endpoint; PublicPath never actually dispatches to it."""


class PublicPath:
    """A (method, path-template) pair that bypasses authentication.

    ``path`` uses Starlette's path-template syntax (e.g. ``"/health"`` or
    ``"/devices/{device_id}"``) and is matched the same way real routes are,
    so path parameters and type converters (``{p:uuid}``, ``{p:path}``, ...)
    work exactly as they would on an actual route.

    Only matches on method + path *template*; it cannot authorize based on
    a path parameter's *value*. Trailing slashes are not normalized: register
    both ``"/health"`` and ``"/health/"`` if both must be public.

    Pass ``method="*"`` to match any HTTP method.
    """

    __slots__ = ("_route", "method", "path")

    def __init__(self, method: str, path: str) -> None:
        self.method = method.upper()
        self.path = path
        self._route = Route(path, endpoint=_noop_endpoint)

    def matches(self, scope: Scope) -> bool:
        """Return True if the request scope matches this method and path.

        Returns:
            True when both the HTTP method (unless ``"*"``) and the path
            template match the given ASGI scope.

        """
        if self.method != "*" and scope["method"] != self.method:
            return False
        match, _ = self._route.matches(scope)
        return match is not Match.NONE


class AuthMiddleware(BaseHTTPMiddleware):
    """Delegates authentication to the configured provider on every request.

    Requests matching ``public_paths`` (from ``auth_cfg.public_paths`` and/or
    the ``public_paths`` constructor argument, with the two merged) skip
    authentication entirely. If ``auth_cfg.public_identity`` is set, such
    requests get a synthetic ``AuthUser`` built from it instead of ``None``,
    so that role/permission-based dependencies on the endpoint (e.g.
    ``FastAPIPermissions.require(...)``) can still pass without any code
    changes to the endpoint. See ``PublicIdentityConfig``.
    """

    def __init__(
        self,
        app: ASGIApp,
        auth_cfg: AuthConfig,
        public_paths: Sequence[PublicPath] = (),
    ) -> None:
        super().__init__(app)
        self._provider = build_provider(auth_cfg)
        config_paths = tuple(
            PublicPath(p.method, p.path) for p in auth_cfg.public_paths
        )
        self._public_paths = config_paths + tuple(public_paths)
        self._public_identity = (
            AuthUser(
                account=auth_cfg.public_identity.default_account,
                roles=auth_cfg.public_identity.default_roles,
            )
            if auth_cfg.public_identity is not None
            else None
        )

    @override
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Delegate to the provider and return 403 on AuthenticationError.

        Requests matching ``public_paths`` skip the provider entirely;
        ``request.state.user`` is set to the configured ``public_identity``
        (or ``None`` if none is configured) so downstream dependencies such
        as ``get_current_user`` keep working without raising.

        Returns:
            403 response if the provider raises ``AuthenticationError``; otherwise
            the downstream response with ``request.state.user`` set.

        """
        request.state.user = None
        if any(p.matches(request.scope) for p in self._public_paths):
            request.state.user = self._public_identity
            return await call_next(request)
        try:
            auth_context = AuthContext(context=request.headers)
            request.state.user = await self._provider.authenticate(auth_context)
        except AuthenticationError as e:
            return HTMLResponse(f"403 Forbidden: {e.reason}", status_code=403)
        return await call_next(request)
