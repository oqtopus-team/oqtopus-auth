"""Generic OIDC/OAuth2 Bearer-token verification and scope helpers.

Verifies an access/ID token against any OIDC issuer that exposes a JWKS
endpoint (Cognito, Keycloak, ...). Kept dependency-light: signature keys are
fetched with :class:`jwt.PyJWKClient` and the discovery document (when needed)
with the standard library, so the core package depends only on ``pydantic`` and
``pyjwt``.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
import urllib.parse
import urllib.request
from functools import lru_cache
from typing import TYPE_CHECKING

import jwt

if TYPE_CHECKING:
    from collections.abc import Mapping

    from jwt.types import Options

    from .config import OidcProviderConfig

_SAFE_JWKS_SCHEMES = frozenset({"http", "https"})

_JWKS_HTTP_TIMEOUT_SECONDS = 5
_DISCOVERY_HTTP_TIMEOUT_SECONDS = 5
# Minimum spacing between *forced* JWKS refreshes (see _RateLimitedJWKClient).
_MIN_FORCED_JWKS_REFRESH_SECONDS = 30.0


class OidcError(Exception):
    """Raised when a Bearer token cannot be verified."""


class _RateLimitedJWKClient(jwt.PyJWKClient):
    """``PyJWKClient`` that rate-limits forced JWKS refreshes on unknown ``kid``.

    ``PyJWKClient`` re-fetches the JWKS whenever a token's ``kid`` is not in the
    cache -- correct for key rotation, but unbounded. Since ``kid`` is read
    *before* signature verification, an unauthenticated caller can force an IdP
    round-trip per request by sending tokens with random ``kid`` values. This
    caps forced refreshes to one per ``_MIN_FORCED_JWKS_REFRESH_SECONDS`` while
    still following genuine rotations.

    Trade-off: a legitimate key rotation can be rejected for up to
    ``_MIN_FORCED_JWKS_REFRESH_SECONDS`` (its new ``kid`` not yet re-fetched).
    This is per-process, so an external/edge rate limit is still warranted for a
    publicly-exposed ``oidc`` endpoint.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._last_forced_refresh = float("-inf")
        self._forced_refresh_lock = threading.Lock()

    def get_signing_key(self, kid: str) -> jwt.PyJWK:
        key = self.match_kid(self.get_signing_keys(), kid)
        if key is not None:
            return key
        # Unknown kid: refresh at most once per window to follow rotation without
        # letting bogus kids hammer the IdP.
        with self._forced_refresh_lock:
            # Re-check first: another thread may have refreshed the JWKS while we
            # were waiting for the lock (so concurrent requests after a genuine
            # rotation all succeed, not just the one that refreshed).
            key = self.match_kid(self.get_signing_keys(), kid)
            if key is None and (
                time.monotonic() - self._last_forced_refresh
                >= _MIN_FORCED_JWKS_REFRESH_SECONDS
            ):
                self._last_forced_refresh = time.monotonic()
                key = self.match_kid(self.get_signing_keys(refresh=True), kid)
        if key is None:
            msg = f'Unable to find a signing key that matches: "{kid}"'
            raise jwt.exceptions.PyJWKClientError(msg)
        return key


@lru_cache(maxsize=8)
def _jwks_client(jwks_url: str) -> jwt.PyJWKClient:
    # PyJWKClient caches signing keys internally; lru_cache keeps one client per
    # URL so keys are not re-fetched on every request. The rate-limited subclass
    # bounds forced refreshes triggered by unknown-kid (bogus) tokens.
    return _RateLimitedJWKClient(jwks_url, timeout=_JWKS_HTTP_TIMEOUT_SECONDS)


@lru_cache(maxsize=8)
def _discover_jwks_url(issuer: str) -> str:
    """Resolve the JWKS URL from the issuer's OIDC discovery document.

    Returns:
        The ``jwks_uri`` advertised by the issuer.

    Raises:
        OidcError: If the discovery document cannot be fetched or parsed.

    """
    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        with urllib.request.urlopen(  # noqa: S310 - issuer is operator-configured
            discovery_url, timeout=_DISCOVERY_HTTP_TIMEOUT_SECONDS
        ) as resp:
            doc = json.loads(resp.read())
        jwks_uri = str(doc["jwks_uri"])
        doc_issuer = doc.get("issuer")
    except Exception as exc:
        msg = f"OIDC discovery failed for {discovery_url}: {exc}"
        raise OidcError(msg) from exc
    # OIDC Discovery 1.0 §4.3: the document's issuer MUST match the requested one.
    if doc_issuer != issuer:
        msg = (
            f"OIDC discovery issuer mismatch: expected {issuer!r}, "
            f"document has {doc_issuer!r}"
        )
        raise OidcError(msg)
    # jwks_uri comes from the discovery document (not operator config), so guard
    # its scheme before PyJWKClient fetches it (defence against file://, etc.).
    if urllib.parse.urlsplit(jwks_uri).scheme not in _SAFE_JWKS_SCHEMES:
        msg = f"OIDC discovery returned a non-HTTP(S) jwks_uri: {jwks_uri!r}"
        raise OidcError(msg)
    return jwks_uri


def _resolve_jwks_url(cfg: OidcProviderConfig) -> str:
    if cfg.jwks_url:
        return cfg.jwks_url
    return _discover_jwks_url(cfg.issuer)


def verify_bearer_token(token: str, cfg: OidcProviderConfig) -> dict:
    """Verify an OIDC JWT and return its validated claims.

    Verifies the signature (via JWKS), ``iss``, ``exp``, and the token's binding
    to this app: ``aud`` when ``cfg.audience`` is set, and/or the client-id claim
    when ``cfg.client_id`` is set (for issuers whose access tokens carry no
    ``aud``, e.g. Cognito). When ``cfg.token_use`` is set it is enforced too.

    This performs **blocking network I/O** on first use / key rotation (fetching
    the JWKS, and the discovery document when ``jwks_url`` is not set). Do **not**
    call it directly from an async event loop -- wrap it in
    :func:`asyncio.to_thread` (as :class:`OidcProvider` does) or use
    :func:`verify_bearer_token_async`.

    Returns:
        The decoded, validated claims.

    Raises:
        OidcError: On any verification failure.

    """
    jwks_url = _resolve_jwks_url(cfg)
    try:
        signing_key = _jwks_client(jwks_url).get_signing_key_from_jwt(token)
    except Exception as exc:
        msg = f"Failed to get signing key from JWKS: {exc}"
        raise OidcError(msg) from exc

    require = ["exp", "iss"]
    options: Options = {"verify_iss": True, "verify_exp": True}
    decode_kwargs: dict = {"issuer": cfg.issuer}
    if cfg.audience:
        require.append("aud")
        options["verify_aud"] = True
        decode_kwargs["audience"] = cfg.audience
    else:
        options["verify_aud"] = False
    options["require"] = require

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=cfg.algorithms,
            options=options,
            **decode_kwargs,
        )
    except Exception as exc:
        msg = f"Bearer token verification failed: {exc}"
        raise OidcError(msg) from exc

    # Bind the token to this app by the client-id claim when `aud` is not used
    # (e.g. Cognito access tokens have no `aud`; they carry `client_id`). PyJWT
    # does not know this claim, so verify it ourselves.
    if cfg.client_id is not None:
        allowed = (
            {cfg.client_id} if isinstance(cfg.client_id, str) else set(cfg.client_id)
        )
        actual = claims.get(cfg.client_id_claim)
        # Guard the type before the set membership test: a non-string claim (an
        # array/object in a crafted token) is unhashable and would raise
        # TypeError -- which is not an OidcError, so it would surface as a 500
        # instead of a 401. Reject any non-string value outright.
        if not isinstance(actual, str) or actual not in allowed:
            msg = (
                f"token {cfg.client_id_claim!r} claim {actual!r} is not an "
                f"allowed client id"
            )
            raise OidcError(msg)

    # Reject the wrong kind of token (e.g. an id token where an access token is
    # expected) when the issuer distinguishes them via `token_use` (Cognito).
    if cfg.token_use is not None:
        actual_use = claims.get("token_use")
        if actual_use != cfg.token_use:
            msg = f"unexpected token_use {actual_use!r} (expected {cfg.token_use!r})"
            raise OidcError(msg)

    return claims


async def verify_bearer_token_async(token: str, cfg: OidcProviderConfig) -> dict:
    """Async wrapper around :func:`verify_bearer_token`.

    Runs the blocking verification (JWKS/discovery network I/O) in a worker
    thread so it does not stall the event loop. Prefer this from ``async def``
    handlers that call verification directly. Propagates :class:`OidcError` from
    :func:`verify_bearer_token` on any verification failure.

    Returns:
        The decoded, validated claims.

    """
    return await asyncio.to_thread(verify_bearer_token, token, cfg)


def extract_scopes(claims: Mapping[str, object]) -> set[str]:
    """Return the set of OAuth2 scopes carried by a token's claims.

    Accepts both the space-delimited ``scope`` string and an ``scp`` list, since
    issuers differ on which they use.

    Returns:
        The set of granted scope strings (possibly empty).

    """
    scopes: set[str] = set()
    raw = claims.get("scope")
    if isinstance(raw, str):
        scopes.update(raw.split())
    scp = claims.get("scp")
    if isinstance(scp, str):
        scopes.update(scp.split())
    elif isinstance(scp, (list, tuple)):
        scopes.update(str(s) for s in scp)
    return scopes


def has_required_scope(claims: Mapping[str, object], required: str) -> bool:
    """Check whether the token's granted scopes include ``required``.

    Returns:
        True iff ``required`` is among the token's scopes.

    """
    return required in extract_scopes(claims)
