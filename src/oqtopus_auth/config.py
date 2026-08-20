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
    audience: str | None = None  # expected aud; required unless opted out
    # DANGEROUS opt-out: accept tokens regardless of aud. Only for issuers that
    # do not scope tokens per resource; enables token substitution otherwise.
    allow_any_audience: bool = False
    algorithms: list[str] = ["RS256"]
    required_scope: str | None = None  # None disables the scope gate
    # Claim used verbatim as AuthUser.account. For client-credentials (M2M)
    # callers set this to "azp" (the client id); for human tokens "sub"/"email".
    principal_claim: str = "sub"
    roles_claim: str | list[str] | None = None  # optional roles for RBAC

    @field_validator("issuer", "principal_claim")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            msg = "must not be empty"
            raise ValueError(msg)
        return value

    @field_validator("audience", "required_scope")
    @classmethod
    def _non_empty_if_set(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            msg = "must not be an empty string (use null to disable)"
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
    def _require_audience(self) -> OidcProviderConfig:
        if self.audience is None and not self.allow_any_audience:
            msg = (
                "audience is required unless allow_any_audience=true "
                "(skipping aud verification enables token substitution)"
            )
            raise ValueError(msg)
        if self.audience is not None and self.allow_any_audience:
            msg = (
                "audience and allow_any_audience are mutually exclusive: set an "
                "audience to verify it, or allow_any_audience=true to skip it"
            )
            raise ValueError(msg)
        return self


class AuthConfig(BaseModel):
    """Top-level authentication configuration."""

    provider: str = "none"
    none: NoneProviderConfig | None = None  # required when provider == "none"
    header: HeaderProviderConfig | None = None  # required when provider == "header"
    oidc: OidcProviderConfig | None = None  # required when provider == "oidc"
    role_mappings: dict[str, str] = {}


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
