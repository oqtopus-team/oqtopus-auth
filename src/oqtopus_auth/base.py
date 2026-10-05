"""Shared authentication base types used by all providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field


@dataclass
class AuthUser:
    """Authenticated principal extracted from a token or upstream proxy header.

    Represents both human users (``account`` = user id / email) and machine
    clients (``account`` = OAuth2 client id). ``scopes`` carries the granted
    OAuth2 scopes for machine-to-machine callers; it is empty for role-based
    human sessions.
    """

    account: str
    roles: list[str] = field(default_factory=list)
    raw_groups: list[str] = field(default_factory=list)
    scopes: frozenset[str] = frozenset()

    @property
    def role(self) -> str:
        """The primary role, for backward-compatible single-role display."""
        return self.roles[0] if self.roles else ""


class AuthenticationError(Exception):
    """The caller could not be authenticated (missing/invalid credentials).

    In an HTTP adapter this maps to **401 Unauthorized** for API (JSON)
    responses. The legacy HTML adapter renders every rejection as 403.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AuthorizationError(AuthenticationError):
    """The caller was authenticated but is not permitted (e.g. lacks a role).

    Subclasses :class:`AuthenticationError` so existing handlers that catch the
    latter keep working. In an HTTP adapter this maps to **403 Forbidden**.
    """


class InsufficientScopeError(AuthorizationError):
    """The caller's token lacks a required OAuth2 scope.

    A specialization of :class:`AuthorizationError` so an HTTP adapter can emit
    the RFC 6750 ``error="insufficient_scope"`` challenge, distinct from a
    generic RBAC (role) denial.
    """


class AuthContext(Mapping[str, str]):
    """Framework-agnostic authentication context passed to providers.

    Behaves as a read-only mapping so providers can call ``context.get(key)``
    without depending on any web framework.
    """

    def __init__(self, context: Mapping[str, str]) -> None:
        self._context = context

    def __getitem__(self, key: str) -> str:  # noqa: D105
        return self._context[key]

    def __iter__(self) -> Iterator[str]:  # noqa: D105
        return iter(self._context)

    def __len__(self) -> int:  # noqa: D105
        return len(self._context)


class AuthProvider(ABC):
    """Abstract base for authentication providers."""

    @abstractmethod
    async def authenticate(self, context: AuthContext) -> AuthUser | None:
        """Authenticate the request context.

        Returns:
            ``AuthUser`` on success, or ``None`` if an implementation chooses
            to let anonymous requests through without a user identity.
            ``NullProvider`` (``provider: none``) does not use this — it
            always returns a synthetic ``AuthUser`` built from its config.

        Raises:
            AuthenticationError: If the request should be rejected with 403.

        """
