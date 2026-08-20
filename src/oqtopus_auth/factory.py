"""Authentication provider factory / registry.

Providers are looked up by their ``provider`` string in an extensible registry.
The built-in ``none``/``header``/``oidc`` providers are pre-registered; hosts
can add their own with :func:`register_provider` without editing this module.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from .header_provider import HeaderProvider
from .null_provider import NullProvider
from .oidc_provider import OidcProvider

if TYPE_CHECKING:
    from .base import AuthProvider
    from .config import AuthConfig

__all__ = ["build_provider", "register_provider"]

ProviderBuilder = Callable[["AuthConfig"], "AuthProvider"]

_REGISTRY: dict[str, ProviderBuilder] = {}


def register_provider(name: str, builder: ProviderBuilder) -> None:
    """Register a provider builder under ``name`` (overwrites any existing one)."""
    _REGISTRY[name] = builder


def build_provider(cfg: AuthConfig) -> AuthProvider:
    """Instantiate the appropriate provider based on the configuration.

    Returns:
        The configured ``AuthProvider`` instance.

    Raises:
        ValueError: If the provider name is not recognized.

    """
    builder = _REGISTRY.get(cfg.provider)
    if builder is None:
        msg = f"Unknown auth provider: {cfg.provider!r}"
        raise ValueError(msg)
    return builder(cfg)


def _build_none(cfg: AuthConfig) -> AuthProvider:
    if cfg.none is None:
        msg = "auth.none config is required when provider=none"
        raise ValueError(msg)
    return NullProvider(cfg.none)


def _build_header(cfg: AuthConfig) -> AuthProvider:
    if cfg.header is None:
        msg = "auth.header config is required when provider=header"
        raise ValueError(msg)
    return HeaderProvider(cfg.header, cfg.role_mappings)


def _build_oidc(cfg: AuthConfig) -> AuthProvider:
    if cfg.oidc is None:
        msg = "auth.oidc config is required when provider=oidc"
        raise ValueError(msg)
    return OidcProvider(cfg.oidc, cfg.role_mappings)


register_provider("none", _build_none)
register_provider("header", _build_header)
register_provider("oidc", _build_oidc)
