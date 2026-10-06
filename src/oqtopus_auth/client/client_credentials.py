"""Client-side OAuth2 client-credentials token acquisition and caching.

For a service that needs to *call* another OIDC-protected service (the machine
side of :class:`~oqtopus_auth.oidc_provider.OidcProvider`). Fetches an access
token from the IdP token endpoint via the client-credentials grant and caches it
until it is about to expire, so the token endpoint is hit only occasionally
rather than on every outbound request.

Requires the ``client`` extra (``pip install "oqtopus-auth[client]"``).
"""

from __future__ import annotations

import base64
import logging
import threading
import time
import urllib.parse
from typing import Literal

import httpx2

logger = logging.getLogger(__name__)


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    """Build an RFC 6749 §2.3.1 ``client_secret_basic`` Authorization header.

    The spec requires each credential to be ``application/x-www-form-urlencoded``
    before being joined with ``:`` and base64-encoded -- a step httpx2's
    ``auth=(id, secret)`` does not perform, so we build the header ourselves.

    Returns:
        The ``Authorization`` header value (``"Basic <base64>"``).

    """
    # application/x-www-form-urlencoded encoding (space -> "+"), per RFC 6749.
    user = urllib.parse.quote_plus(client_id, safe="")
    secret = urllib.parse.quote_plus(client_secret, safe="")
    token = base64.b64encode(f"{user}:{secret}".encode()).decode("ascii")
    return f"Basic {token}"


_DEFAULT_EXPIRY_SKEW_SECONDS = 60
_DEFAULT_TIMEOUT_SECONDS = 10
_HTTP_OK = 200
_MAX_ERROR_BODY_CHARS = 500


class ClientCredentialsError(RuntimeError):
    """Raised when a client-credentials access token cannot be obtained."""


def _parse_token_payload(payload: object) -> tuple[str, int]:
    """Validate a token-endpoint JSON payload and return (access_token, expires_in).

    Rejects a missing/blank ``access_token``, a non-positive ``expires_in``, and
    a non-Bearer ``token_type`` -- rather than coercing them into a bogus but
    truthy token.

    Returns:
        The access token and its lifetime in seconds.

    Raises:
        ClientCredentialsError: If the payload is not a valid token response.

    """
    if not isinstance(payload, dict):
        msg = "Token response is not a JSON object"
        raise ClientCredentialsError(msg)

    # RFC 6749 §5.1: token_type is REQUIRED and must be Bearer for our use.
    token_type = payload.get("token_type")
    if not isinstance(token_type, str) or token_type.strip().lower() != "bearer":
        msg = f"Token response token_type must be Bearer, got {token_type!r}"
        raise ClientCredentialsError(msg)

    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token.strip():
        msg = "Token response has no valid 'access_token'"
        raise ClientCredentialsError(msg)

    # Positive integer only: reject bools, floats (0.5 would truncate to 0), and
    # NaN/inf (which would slip past a naive comparison and blow up on int()).
    expires_in = payload.get("expires_in")
    if isinstance(expires_in, bool) or not isinstance(expires_in, int):
        msg = f"Token response 'expires_in' must be an integer, got {expires_in!r}"
        raise ClientCredentialsError(msg)
    if expires_in <= 0:
        msg = f"Token response 'expires_in' must be positive, got {expires_in!r}"
        raise ClientCredentialsError(msg)

    return access_token.strip(), expires_in


class ClientCredentialsTokenProvider:
    """Fetches and caches an OAuth2 client-credentials access token.

    Thread-safe: concurrent callers share one cached token and only one performs
    the network refresh at a time. Expiry is tracked from the token response's
    ``expires_in`` (not by decoding the JWT), so the token stays opaque here.

    All methods are **synchronous** (blocking network I/O). From an async context
    call them via :func:`asyncio.to_thread` (as oqtopus-engine does).
    """

    def __init__(  # noqa: PLR0913
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str = "",
        *,
        expiry_skew_seconds: int = _DEFAULT_EXPIRY_SKEW_SECONDS,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
        auth_style: Literal["basic", "post"] = "basic",
    ) -> None:
        """Initialize the token provider.

        Args:
            token_url: The IdP OAuth2 token endpoint.
            client_id: The confidential client identifier.
            client_secret: The confidential client secret.
            scope: Space-delimited scopes to request (e.g. ``"provider.write"``).
            expiry_skew_seconds: Refresh the token this many seconds before it
                actually expires, to absorb clock skew and in-flight latency.
                Must be >= 0.
            timeout_seconds: HTTP timeout for the token request. Must be > 0.
            auth_style: How to present client credentials. ``"basic"`` (default)
                uses the HTTP Basic header (``client_secret_basic``), which
                RFC 6749 §2.3.1 prefers and some IdPs require; ``"post"`` sends
                them in the request body (``client_secret_post``).

        Raises:
            ValueError: If ``expiry_skew_seconds`` < 0, ``timeout_seconds`` <= 0,
                or ``auth_style`` is not ``"basic"`` / ``"post"``.

        """
        if expiry_skew_seconds < 0:
            msg = f"expiry_skew_seconds must be >= 0, got {expiry_skew_seconds}"
            raise ValueError(msg)
        if timeout_seconds <= 0:
            msg = f"timeout_seconds must be > 0, got {timeout_seconds}"
            raise ValueError(msg)
        # The Literal annotation is not enforced at runtime: reject a typo rather
        # than silently falling back to client_secret_post (which moves the
        # secret from the Authorization header into the request body).
        if auth_style not in {"basic", "post"}:
            msg = f'auth_style must be "basic" or "post", got {auth_style!r}'
            raise ValueError(msg)
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._expiry_skew_seconds = expiry_skew_seconds
        self._timeout_seconds = timeout_seconds
        self._auth_style = auth_style

        self._lock = threading.Lock()
        self._access_token: str | None = None
        self._expires_at_monotonic: float = 0.0

    def get_token(self, *, force_refresh: bool = False) -> str:
        """Return a valid access token, refreshing it if necessary.

        Args:
            force_refresh: If ``True``, discard any cached token and fetch a new
                one (e.g. after an unexpected ``401``).

        Returns:
            A currently-valid bearer access token.

        Raises:
            ClientCredentialsError: If a token cannot be obtained.

        """
        with self._lock:
            if force_refresh or self._needs_refresh():
                self._refresh()
            token = self._access_token
            if token is None:
                msg = "Access token is unexpectedly unset after refresh"
                raise ClientCredentialsError(msg)
            return token

    def _needs_refresh(self) -> bool:
        return (
            self._access_token is None or time.monotonic() >= self._expires_at_monotonic
        )

    def _refresh(self) -> None:
        data = {"grant_type": "client_credentials"}
        headers: dict[str, str] = {}
        if self._auth_style == "basic":
            headers["Authorization"] = _basic_auth_header(
                self._client_id, self._client_secret
            )
        else:
            data["client_id"] = self._client_id
            data["client_secret"] = self._client_secret
        if self._scope:
            data["scope"] = self._scope

        # Base the expiry on when the request *started*: expires_in counts from
        # the IdP issuing the token, so measuring after a slow round-trip would
        # over-estimate the remaining lifetime.
        requested_at = time.monotonic()
        try:
            response = httpx2.post(
                self._token_url,
                data=data,
                headers=headers,
                timeout=self._timeout_seconds,
            )
        except httpx2.HTTPError as exc:
            msg = f"Failed to reach token endpoint {self._token_url}: {exc}"
            raise ClientCredentialsError(msg) from exc

        if response.status_code != _HTTP_OK:
            # Cap the body so a large/hostile error page doesn't flood caller logs.
            body = response.text[:_MAX_ERROR_BODY_CHARS]
            msg = f"Token endpoint returned {response.status_code}: {body}"
            raise ClientCredentialsError(msg)

        try:
            payload = response.json()
        except ValueError as exc:
            msg = f"Token response is not valid JSON: {exc}"
            raise ClientCredentialsError(msg) from exc

        access_token, expires_in = _parse_token_payload(payload)
        self._access_token = access_token
        # Clamp the skew so a short-lived token (expires_in <= skew) is still
        # cached for part of its life instead of being treated as already-expired
        # -- which would re-hit the token endpoint on every call.
        effective_skew = min(self._expiry_skew_seconds, expires_in // 2)
        self._expires_at_monotonic = requested_at + expires_in - effective_skew
        logger.info(
            "client-credentials token acquired",
            extra={
                "token_url": self._token_url,
                "client_id": self._client_id,
                "expires_in": expires_in,
            },
        )
