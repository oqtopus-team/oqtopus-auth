"""FastAPI middleware that delegates authentication to the configured provider."""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ..base import (  # noqa: TID252
    AuthContext,
    AuthenticationError,
    AuthorizationError,
    InsufficientScopeError,
)
from ..factory import build_provider  # noqa: TID252

if TYPE_CHECKING:
    from fastapi import Request
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.types import ASGIApp

    from ..config import AuthConfig  # noqa: TID252

_HTTP_UNAUTHORIZED = 401
_HTTP_FORBIDDEN = 403


class AuthMiddleware(BaseHTTPMiddleware):
    """Delegates authentication to the configured provider on every request.

    ``response_format`` selects how rejections are rendered:

    - ``"html"`` (default): every rejection is a ``403`` HTML body, preserving
      the original server-rendered-app behavior.
    - ``"json"``: an :class:`AuthorizationError` becomes ``403`` and any other
      :class:`AuthenticationError` becomes ``401``, both as ``{"detail": ...}``
      JSON -- the right contract for an API.
    """

    def __init__(
        self, app: ASGIApp, auth_cfg: AuthConfig, response_format: str = "html"
    ) -> None:
        super().__init__(app)
        self._provider = build_provider(auth_cfg)
        self._response_format = response_format

    @override
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Delegate to the provider and reject on auth failure.

        Returns:
            The downstream response with ``request.state.user`` set, or an
            auth-failure response (401/403 per ``response_format``).

        """
        request.state.user = None
        try:
            auth_context = AuthContext(context=request.headers)
            request.state.user = await self._provider.authenticate(auth_context)
        except AuthenticationError as e:
            return self._reject(e)
        return await call_next(request)

    def _reject(self, error: AuthenticationError) -> Response:
        if self._response_format == "json":
            headers: dict[str, str] = {}
            if isinstance(error, InsufficientScopeError):
                # RFC 6750 §3.1: only a missing *scope* is insufficient_scope.
                status = _HTTP_FORBIDDEN
                headers["WWW-Authenticate"] = 'Bearer error="insufficient_scope"'
            elif isinstance(error, AuthorizationError):
                # Generic RBAC denial: 403 with no scope-specific challenge.
                status = _HTTP_FORBIDDEN
            else:
                status = _HTTP_UNAUTHORIZED
                headers["WWW-Authenticate"] = "Bearer"
            return JSONResponse(
                status_code=status,
                content={"detail": error.reason},
                headers=headers,
            )
        return HTMLResponse(
            f"403 Forbidden: {error.reason}", status_code=_HTTP_FORBIDDEN
        )
