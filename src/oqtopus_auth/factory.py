"""Authentication provider factory."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .header_provider import HeaderProvider
from .null_provider import NullProvider

if TYPE_CHECKING:
    from .base import AuthProvider
    from .config import AuthConfig

__all__ = ["build_provider"]


def build_provider(cfg: AuthConfig) -> AuthProvider:
    """Instantiate the appropriate provider based on the configuration.

    Returns:
        The configured ``AuthProvider`` instance.

    Raises:
        ValueError: If the provider name is not recognized.

    """
    if cfg.provider == "none":
        if cfg.none is None:
            msg = "auth.none config is required when provider=none"
            raise ValueError(msg)
        return NullProvider(cfg.none)
    if cfg.provider == "header":
        if cfg.header is None:
            msg = "auth.header config is required when provider=header"
            raise ValueError(msg)
        return HeaderProvider(cfg.header, cfg.role_mappings)
    msg = f"Unknown auth provider: {cfg.provider!r}"
    raise ValueError(msg)
