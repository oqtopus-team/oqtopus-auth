"""Header-based JWT authentication provider."""

from __future__ import annotations

import asyncio
import fnmatch
import logging
from typing import TYPE_CHECKING, override

import jwt
from jwt import PyJWKClient

from .base import AuthContext, AuthenticationError, AuthProvider, AuthUser

if TYPE_CHECKING:
    from .config import (
        HeaderProviderConfig,
        SignatureVerificationConfig,
    )

# One PyJWKClient per JWKS URI; kept alive for key caching across requests
_jwks_clients: dict[str, PyJWKClient] = {}

logger = logging.getLogger(__name__)


def extract_token(jwt_header: str, header_value: str) -> str | None:
    """Extract the raw JWT string from a header value.

    For the ``authorization`` header, strips the ``Bearer `` prefix.
    For all other headers, treats the value as a raw JWT.

    Returns:
        Raw JWT string, or ``None`` if absent or Bearer prefix is missing.

    """
    if not header_value:
        return None
    if jwt_header.lower() == "authorization":
        if not header_value.lower().startswith("bearer "):
            return None
        return header_value[len("bearer ") :]
    return header_value


def _get_claim(payload: dict, claim: str | list[str]) -> object:
    """Navigate a JWT payload using a claim key or nested path.

    ``claim`` is a plain key name (string) or an ordered list of keys for
    nested access (e.g. ``["custom", "cognito:groups"]``).

    Returns:
        The claim value, or ``None`` if any key is missing along the path.

    """
    if isinstance(claim, str):
        return payload.get(claim)
    current: object = payload
    for key in claim:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _extract_roles(raw_value: object) -> list[str]:
    """Normalise a roles claim value to a flat list of strings.

    Handles both JSON arrays and comma-separated strings, since different
    identity providers use different formats for multi-value claims.

    Returns:
        Flat list of non-empty role strings.

    """
    if raw_value is None:
        return []
    if isinstance(raw_value, list):
        return [str(r) for r in raw_value if r]
    if isinstance(raw_value, str):
        return [r.strip() for r in raw_value.split(",") if r.strip()]
    return []


def _verify_jwt(token: str, sig_cfg: SignatureVerificationConfig) -> None:
    """Verify JWT signature and claims via the issuer's JWKS endpoint."""
    jwks_uri = sig_cfg.jwks_url or f"{sig_cfg.issuer.rstrip('/')}/.well-known/jwks.json"
    if jwks_uri not in _jwks_clients:
        _jwks_clients[jwks_uri] = PyJWKClient(
            jwks_uri, cache_jwk_set=True, lifespan=300
        )
    signing_key = _jwks_clients[jwks_uri].get_signing_key_from_jwt(token)
    jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=sig_cfg.audience,
        issuer=sig_cfg.issuer,
    )


class HeaderProvider(AuthProvider):
    """Provider that extracts user and roles from JWT claims set by a reverse proxy."""

    def __init__(
        self, header_config: HeaderProviderConfig, role_mappings: dict[str, str]
    ) -> None:
        self._header_config = header_config
        self._role_mappings = role_mappings

    @override
    async def authenticate(self, context: AuthContext) -> AuthUser | None:
        """Extract user and roles from JWT claims, then optionally verify the signature.

        Returns:
            Authenticated ``AuthUser``.

        Raises:
            AuthenticationError: If the JWT is missing/invalid, no roles match,
                or signature verification fails.

        """
        header_config = self._header_config

        # Extract raw JWT from the configured header
        header_value = context.get(header_config.jwt_header, "")
        token = extract_token(header_config.jwt_header, header_value)
        if not token:
            msg = "missing JWT"
            raise AuthenticationError(msg)

        # Decode without verification to read claims
        try:
            payload: dict = jwt.decode(token, options={"verify_signature": False})
        except Exception as exc:  # noqa: BLE001
            logger.warning("JWT decode failed: %s", exc)
            msg = "invalid JWT"
            raise AuthenticationError(msg) from None

        account = str(_get_claim(payload, header_config.user_claim) or "")
        if not account:
            msg = "missing user identifier claim"
            raise AuthenticationError(msg)
        raw_groups = _extract_roles(_get_claim(payload, header_config.roles_claim))

        # Discard values not matching any allow_raw_roles pattern before mapping
        if header_config.allow_raw_roles:
            allowed = [
                raw_role
                for raw_role in raw_groups
                if any(
                    fnmatch.fnmatch(raw_role, pat)
                    for pat in header_config.allow_raw_roles
                )
            ]
        else:
            allowed = raw_groups

        if not allowed:
            msg = "no allowed role"
            raise AuthenticationError(msg)

        # Map to display name; fall back to raw value if unmapped
        roles = [self._role_mappings.get(raw_role, raw_role) for raw_role in allowed]

        # Verify signature if enabled
        sig = header_config.signature_verification
        if sig and sig.enabled:
            try:
                # _verify_jwt does blocking network I/O (JWKS fetch); keep it
                # off the event loop so one slow/unreachable issuer doesn't
                # stall every other in-flight request.
                await asyncio.to_thread(_verify_jwt, token, sig)
            except Exception as exc:  # noqa: BLE001
                logger.warning("JWT verification failed: %s", exc)
                msg = "invalid JWT"
                raise AuthenticationError(msg) from None  # hide internal details

        return AuthUser(account=account, roles=roles, raw_groups=raw_groups)
