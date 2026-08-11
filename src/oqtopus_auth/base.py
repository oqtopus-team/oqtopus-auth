"""Shared authentication base types used by all providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field


@dataclass
class AuthUser:
    """Authenticated user extracted from JWT claims."""

    account: str
    roles: list[str] = field(default_factory=list)
    raw_groups: list[str] = field(default_factory=list)

    @property
    def role(self) -> str:
        """The primary role, for backward-compatible single-role display."""
        return self.roles[0] if self.roles else ""


class AuthenticationError(Exception):
    """Raised by a provider when the request should be rejected with 403."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


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
