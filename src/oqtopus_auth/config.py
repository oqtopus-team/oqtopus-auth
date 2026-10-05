"""Pydantic configuration models for authentication."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

# Asymmetric algorithms only: reject "none" and symmetric HS* (a shared secret
# leaked from config would let a caller forge tokens).
_ALLOWED_OIDC_ALGORITHMS = frozenset({
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
})


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


class OidcProviderConfig(BaseModel):
    """Settings for the provider: oidc (verify-first OAuth2/OIDC) mode.

    Unlike ``header`` (which trusts a reverse-proxy-injected JWT), this provider
    verifies the incoming ``Authorization: Bearer`` token against the issuer's
    JWKS and can enforce an OAuth2 scope -- covering machine-to-machine
    (client-credentials) callers that carry no roles/groups.

    ``extra="forbid"`` so a config typo (e.g. ``audence``/``required_scop``)
    fails loudly instead of silently disabling a security check.
    """

    model_config = ConfigDict(extra="forbid")

    issuer: str  # expected iss; also used to discover the JWKS URL
    jwks_url: str | None = None  # explicit JWKS endpoint; skips discovery
    audience: str | None = None  # expected aud; a token binding (see below)
    # DANGEROUS opt-out: accept tokens regardless of aud/client_id. Only for
    # issuers that do not scope tokens per resource; enables token substitution.
    allow_any_audience: bool = False
    # Bind the token to this app by the client-id claim instead of (or in
    # addition to) `aud`. Needed for issuers whose *access tokens* carry no
    # `aud` -- e.g. Cognito access tokens use `client_id` + `token_use=access`.
    # Accepts one id or several.
    client_id: str | list[str] | None = None
    # Claim carrying the client id (Cognito: "client_id"; some IdPs: "azp").
    client_id_claim: str = "client_id"
    # When set, require the token's `token_use` claim to equal this value
    # (Cognito access tokens use "access", id tokens "id"). None disables it.
    token_use: str | None = None
    algorithms: list[str] = ["RS256"]
    required_scope: str | None = None  # None disables the scope gate
    # Claim used verbatim as AuthUser.account. For client-credentials (M2M)
    # callers set this to "azp" (the client id); for human tokens "sub"/"email".
    principal_claim: str = "sub"
    roles_claim: str | list[str] | None = None  # optional roles for RBAC

    @field_validator("issuer", "principal_claim", "client_id_claim")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            msg = "must not be empty"
            raise ValueError(msg)
        return value

    @field_validator("audience", "required_scope", "token_use")
    @classmethod
    def _non_empty_if_set(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            msg = "must not be an empty string (use null to disable)"
            raise ValueError(msg)
        return value

    @field_validator("client_id")
    @classmethod
    def _non_empty_client_id(
        cls, value: str | list[str] | None
    ) -> str | list[str] | None:
        if value is None:
            return value
        if isinstance(value, str):
            if not value.strip():
                msg = "client_id must not be an empty string (use null to disable)"
                raise ValueError(msg)
            return value
        if not value or any(not v.strip() for v in value):
            msg = "client_id list must be non-empty with non-empty entries"
            raise ValueError(msg)
        return value

    @field_validator("algorithms")
    @classmethod
    def _supported_algorithms(cls, value: list[str]) -> list[str]:
        if not value:
            msg = "algorithms must not be empty"
            raise ValueError(msg)
        unsupported = [a for a in value if a not in _ALLOWED_OIDC_ALGORITHMS]
        if unsupported:
            msg = (
                f"unsupported/insecure algorithms {unsupported}; "
                f"allowed: {sorted(_ALLOWED_OIDC_ALGORITHMS)}"
            )
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _require_token_binding(self) -> OidcProviderConfig:
        # A token must be bound to *this* app, by one of two mechanisms:
        #   - `audience`  -> verify the `aud` claim (OIDC id tokens, Keycloak
        #                    access tokens with an audience mapper, ...)
        #   - `client_id` -> verify the client-id claim (issuers whose access
        #                    tokens have no `aud`, e.g. Cognito)
        # allow_any_audience is the explicit, dangerous opt-out of *both* and so
        # is mutually exclusive with each (otherwise any token from the issuer,
        # for any client/resource, would be accepted).
        if self.allow_any_audience:
            if self.audience is not None:
                msg = (
                    "audience and allow_any_audience are mutually exclusive: set "
                    "an audience to verify it, or allow_any_audience=true to skip it"
                )
                raise ValueError(msg)
            if self.client_id is not None:
                msg = (
                    "client_id and allow_any_audience are mutually exclusive: "
                    "client_id already binds the token to this app"
                )
                raise ValueError(msg)
            return self
        if self.audience is None and self.client_id is None:
            msg = (
                "a token binding is required: set `audience` (verify the aud "
                "claim), or `client_id` (verify the client-id claim, for issuers "
                "whose access tokens carry no aud, e.g. Cognito), or "
                "allow_any_audience=true to accept any token from the issuer "
                "(dangerous: enables token substitution)"
            )
            raise ValueError(msg)
        return self


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
    oidc: OidcProviderConfig | None = None  # required when provider == "oidc"
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


def parse_oidc_provider_config(raw: dict) -> OidcProviderConfig:
    """Parse an ``OidcProviderConfig`` from a raw dict, raising on missing fields.

    Returns:
        A validated ``OidcProviderConfig`` instance.

    Raises:
        ValueError: If ``issuer`` is missing.

    """
    if not raw.get("issuer"):
        msg = "auth.oidc.issuer is required when provider=oidc"
        raise ValueError(msg)
    return OidcProviderConfig(**raw)


def parse_auth_config(raw: dict) -> AuthConfig:
    """Parse an ``AuthConfig`` from a raw dict (e.g., loaded from YAML).

    Delegates to ``parse_none_provider_config``, ``parse_header_provider_config``
    and ``parse_oidc_provider_config`` which raise ``ValueError`` when required
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
        oidc=(
            parse_oidc_provider_config(raw.get("oidc") or {})
            if provider == "oidc"
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
