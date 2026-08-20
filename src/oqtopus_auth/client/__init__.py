"""Client-side helpers for calling OIDC-protected services (extra: client)."""

from .client_credentials import (
    ClientCredentialsError,
    ClientCredentialsTokenProvider,
)

__all__ = [
    "ClientCredentialsError",
    "ClientCredentialsTokenProvider",
]
