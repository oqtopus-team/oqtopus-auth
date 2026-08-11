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


class AuthConfig(BaseModel):
    """Top-level authentication configuration."""

    provider: str = "none"
    none: NoneProviderConfig | None = None  # required when provider == "none"
    header: HeaderProviderConfig | None = None  # required when provider == "header"
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
