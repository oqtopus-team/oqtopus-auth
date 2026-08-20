"""Client-side OAuth2 client-credentials token acquisition and caching.

For a service that needs to *call* another OIDC-protected service (the machine
side of :class:`~oqtopus_auth.oidc_provider.OidcProvider`). Fetches an access
token from the IdP token endpoint via the client-credentials grant and caches it
until it is about to expire, so the token endpoint is hit only occasionally
rather than on every outbound request.

Requires the ``client`` extra (``pip install "oqtopus-auth[client]"``).
"""

from __future__ import annotations

import logging
import threading
import time

import httpx

logger = logging.getLogger(__name__)

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
    ) -> None:
        """Initialize the token provider.

        Args:
            token_url: The IdP OAuth2 token endpoint.
            client_id: The confidential client identifier.
            client_secret: The confidential client secret.
            scope: Space-delimited scopes to request (e.g. ``"provider.write"``).
            expiry_skew_seconds: Refresh the token this many seconds before it
                actually expires, to absorb clock skew and in-flight latency.
            timeout_seconds: HTTP timeout for the token request.

        """
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._expiry_skew_seconds = expiry_skew_seconds
        self._timeout_seconds = timeout_seconds

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
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if self._scope:
            data["scope"] = self._scope

        try:
            response = httpx.post(
                self._token_url, data=data, timeout=self._timeout_seconds
            )
        except httpx.HTTPError as exc:
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
        self._expires_at_monotonic = (
            time.monotonic() + expires_in - self._expiry_skew_seconds
        )
        logger.info(
            "client-credentials token acquired",
            extra={
                "token_url": self._token_url,
                "client_id": self._client_id,
                "expires_in": expires_in,
            },
        )
