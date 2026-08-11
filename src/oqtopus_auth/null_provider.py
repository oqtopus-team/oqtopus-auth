"""Null Object provider that disables authentication."""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from .base import AuthContext, AuthProvider, AuthUser

if TYPE_CHECKING:
    from .config import NoneProviderConfig


class NullProvider(AuthProvider):
    """No-op provider for ``provider: none``; grants every request admin access."""

    def __init__(self, cfg: NoneProviderConfig) -> None:
        self._user = AuthUser(
            account=cfg.default_account,
            roles=cfg.default_roles,
            raw_groups=[],
        )

    @override
    async def authenticate(self, context: AuthContext) -> AuthUser | None:
        """Return a virtual user built from the ``auth.none`` config section.

        Returns:
            A synthetic ``AuthUser`` so that permission checks and
            template flags behave identically to a real session.

        """
        return self._user
