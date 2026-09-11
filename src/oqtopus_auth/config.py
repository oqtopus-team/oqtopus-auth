"""Pydantic configuration models for authentication."""

from __future__ import annotations

from pydantic import BaseModel


class SignatureVerificationConfig(BaseModel):
    """JWT signature verification sub-config (under provider: header)."""

    enabled: bool = False
    issuer: str = ""  # required when enabled=true; also used to derive jwks_url
    jwks_url: str | None = None  # explicit JWKS endpoint; overrides issuer-derived URL
    audience: str = ""  # required when enabled=true


class HeaderProviderConfig(BaseModel):
    """Settings specific to the header-based authentication provider."""

    # "authorization" → strip "Bearer " prefix automatically
    jwt_header: str
    user_claim: str
    # str = simple key; list[str] = nested path (e.g. ["custom", "cognito:groups"])
    roles_claim: str | list[str] = "cognito:groups"
    # glob patterns on raw roles_claim values, applied before role_mappings
    allow_raw_roles: list[str] = []  # empty = allow all
    signature_verification: SignatureVerificationConfig | None = None
    signout_url: str | None = None


class NoneProviderConfig(BaseModel):
    """Settings for the provider: none (disabled auth) mode."""

    default_account: str
    default_roles: list[str]


class PublicPathConfig(BaseModel):
    """One unauthenticated (method, path-template) pair, as loaded from YAML.

    ``method`` is an HTTP method name (e.g. "GET") or "*" for any method.
    It has no default and must always be given explicitly: a path bypassing
    authentication for every HTTP method is a deliberate, broader choice
    that a bare ``path:`` entry should never make by accident.
    ``path`` uses Starlette's path-template syntax (e.g. "/health" or
    "/devices/{device_id}"), matched the same way real routes are.

    Note: this only bypasses authentication for requests whose method and
    path *template* match. It cannot authorize based on path parameter
    *values* (e.g. "only device X is public"); that kind of check belongs in
    the endpoint itself.
    """

    method: str
    path: str


class PublicIdentityConfig(BaseModel):
    """Synthetic identity assigned to requests bypassed via ``public_paths``.

    Mirrors ``NoneProviderConfig``'s shape and field names, since both
    describe a synthetic identity for requests that never go through a real
    provider. This one is scoped to requests matching ``public_paths`` only,
    instead of applying to every request in the application.

    When ``public_identity`` is omitted entirely, requests matching
    ``public_paths`` get ``request.state.user = None`` (no identity at all).
    """

    default_account: str = "public"
    default_roles: list[str] = []


class AuthConfig(BaseModel):
    """Top-level authentication configuration.

    ``public_paths`` and ``public_identity`` are checked before a provider is
    invoked, so they apply the same way regardless of ``provider``; they are
    not part of any single provider's configuration. Under ``provider: none``
    they have no practical effect, since every request is already granted
    ``none.default_account`` / ``default_roles`` unconditionally.
    """

    provider: str = "none"
    none: NoneProviderConfig | None = None  # required when provider == "none"
    header: HeaderProviderConfig | None = None  # required when provider == "header"
    role_mappings: dict[str, str] = {}
    public_paths: list[PublicPathConfig] = []
    public_identity: PublicIdentityConfig | None = None


def parse_header_provider_config(raw: dict) -> HeaderProviderConfig:
    """Parse a ``HeaderProviderConfig`` from a raw dict, raising on missing fields.

    Returns:
        A validated ``HeaderProviderConfig`` instance.

    Raises:
        ValueError: If ``jwt_header`` or ``user_claim`` is missing.

    """
    for key in ("jwt_header", "user_claim"):
        if not raw.get(key):
            msg = f"auth.header.{key} is required when provider=header"
            raise ValueError(msg)
    sig_ver_raw = raw.get("signature_verification") or {}
    sig_ver = SignatureVerificationConfig(**sig_ver_raw) if sig_ver_raw else None
    if sig_ver and sig_ver.enabled and not (sig_ver.issuer and sig_ver.audience):
        msg = (
            "auth.header.signature_verification.issuer and .audience are "
            "required when signature_verification.enabled=true"
        )
        raise ValueError(msg)
    return HeaderProviderConfig(
        jwt_header=raw["jwt_header"],
        user_claim=raw["user_claim"],
        roles_claim=raw.get("roles_claim", "cognito:groups"),
        allow_raw_roles=raw.get("allow_raw_roles") or [],
        signature_verification=sig_ver,
        signout_url=raw.get("signout_url"),
    )


def parse_auth_config(raw: dict) -> AuthConfig:
    """Parse an ``AuthConfig`` from a raw dict (e.g., loaded from YAML).

    Delegates to ``parse_none_provider_config`` and
    ``parse_header_provider_config`` which raise ``ValueError`` when required
    fields are missing.

    Returns:
        A validated ``AuthConfig`` instance.

    """
    provider = raw.get("provider", "none")
    return AuthConfig(
        provider=provider,
        none=(
            parse_none_provider_config(raw.get("none") or {})
            if provider == "none"
            else None
        ),
        header=(
            parse_header_provider_config(raw.get("header") or {})
            if provider == "header"
            else None
        ),
        role_mappings=raw.get("role_mappings") or {},
        public_paths=[PublicPathConfig(**p) for p in raw.get("public_paths") or []],
        public_identity=(
            PublicIdentityConfig(**raw["public_identity"])
            if raw.get("public_identity") is not None
            else None
        ),
    )


def parse_none_provider_config(raw: dict) -> NoneProviderConfig:
    """Parse a ``NoneProviderConfig`` from a raw dict, raising on missing fields.

    Returns:
        A validated ``NoneProviderConfig`` instance.

    Raises:
        ValueError: If ``default_account`` or ``default_roles`` is missing.

    """
    for key in ("default_account", "default_roles"):
        if raw.get(key) is None:
            msg = f"auth.none.{key} is required when provider=none"
            raise ValueError(msg)
    return NoneProviderConfig(
        default_account=raw["default_account"],
        default_roles=raw["default_roles"],
    )
