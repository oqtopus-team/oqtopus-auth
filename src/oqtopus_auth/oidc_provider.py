"""Verify-first OIDC/OAuth2 authentication provider.

Unlike :class:`~oqtopus_auth.header_provider.HeaderProvider` (which trusts a
JWT injected by a reverse proxy and requires roles/groups), this provider
verifies the incoming ``Authorization: Bearer`` token against the issuer's JWKS
and can enforce an OAuth2 scope. It therefore supports machine-to-machine
(client-credentials) callers that carry a ``scope`` but no roles.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, override

from .base import (
    AuthContext,
    AuthenticationError,
    AuthProvider,
    AuthUser,
    InsufficientScopeError,
)
from .header_provider import extract_token
from .oidc import OidcError, extract_scopes, has_required_scope, verify_bearer_token

if TYPE_CHECKING:
    from .config import OidcProviderConfig

logger = logging.getLogger(__name__)

_BEARER_HEADER = "authorization"


class OidcProvider(AuthProvider):
    """Provider that verifies an OIDC Bearer token and enforces an optional scope."""

    def __init__(
        self, cfg: OidcProviderConfig, role_mappings: dict[str, str] | None = None
    ) -> None:
        self._cfg = cfg
        self._role_mappings = role_mappings or {}
        if cfg.allow_any_audience and cfg.audience is None:
            logger.warning(
                "OidcProvider audience verification is DISABLED "
                "(allow_any_audience=true) for issuer %s; tokens minted for "
                "other resources of the same issuer will be accepted",
                cfg.issuer,
            )

    @override
    async def authenticate(self, context: AuthContext) -> AuthUser | None:
        """Verify the Bearer token, enforce the required scope, and build a principal.

        Returns:
            An ``AuthUser`` whose ``account`` is the user id (human) or client id
            (machine) and whose ``scopes`` are the token's granted scopes.

        Raises:
            AuthenticationError: If the token is missing or fails verification.
            InsufficientScopeError: If the required scope is not present.

        """
        cfg = self._cfg

        token = extract_token(_BEARER_HEADER, context.get(_BEARER_HEADER, ""))
        if not token:
            msg = "missing bearer token"
            raise AuthenticationError(msg)

        try:
            # verify_bearer_token does blocking network I/O (JWKS/discovery);
            # keep it off the event loop so a slow issuer doesn't stall others.
            claims = await asyncio.to_thread(verify_bearer_token, token, cfg)
        except OidcError as exc:
            logger.warning("OIDC verification failed: %s", exc)
            msg = "invalid bearer token"
            raise AuthenticationError(msg) from None

        if cfg.required_scope and not has_required_scope(claims, cfg.required_scope):
            msg = f"missing required scope '{cfg.required_scope}'"
            raise InsufficientScopeError(msg)

        account = self._resolve_account(claims)
        if not account:
            msg = f"token is missing the '{cfg.principal_claim}' claim"
            raise AuthenticationError(msg)

        roles = self._resolve_roles(claims)
        return AuthUser(
            account=account,
            roles=roles,
            raw_groups=[],
            scopes=frozenset(extract_scopes(claims)),
        )

    def _resolve_account(self, claims: dict) -> str:
        # Use the explicitly-configured principal claim -- no auto human/machine
        # detection. For client-credentials callers configure principal_claim="azp".
        value = claims.get(self._cfg.principal_claim)
        return str(value) if value else ""

    def _resolve_roles(self, claims: dict) -> list[str]:
        cfg = self._cfg
        if cfg.roles_claim is None:
            return []
        raw = _normalise_roles(_get_claim(claims, cfg.roles_claim))
        return [self._role_mappings.get(role, role) for role in raw]


def _get_claim(payload: dict, claim: str | list[str]) -> object:
    """Read a claim by key or nested path (list of keys).

    Returns:
        The claim value, or ``None`` if any key along the path is missing.

    """
    if isinstance(claim, str):
        return payload.get(claim)
    current: object = payload
    for key in claim:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _normalise_roles(raw_value: object) -> list[str]:
    """Normalise a roles claim to a flat list (array or comma-separated string).

    Returns:
        A flat list of non-empty role strings.

    """
    if isinstance(raw_value, list):
        return [str(r) for r in raw_value if r]
    if isinstance(raw_value, str):
        return [r.strip() for r in raw_value.split(",") if r.strip()]
    return []
