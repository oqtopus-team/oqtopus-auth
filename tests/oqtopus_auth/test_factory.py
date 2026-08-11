"""Unit tests for oqtopus_auth/factory.py."""

from __future__ import annotations

import asyncio

import pytest

from oqtopus_auth.base import AuthContext
from oqtopus_auth.config import (
    AuthConfig,
    HeaderProviderConfig,
    NoneProviderConfig,
    SignatureVerificationConfig,
)
from oqtopus_auth.factory import build_provider
from oqtopus_auth.header_provider import HeaderProvider
from oqtopus_auth.null_provider import NullProvider


# ── build_provider ────────────────────────────────────────────────────────────


class TestBuildProvider:
    def _make_auth_cfg(self, provider: str) -> AuthConfig:
        if provider == "header":
            return AuthConfig(
                provider="header",
                header=HeaderProviderConfig(
                    jwt_header="authorization",
                    user_claim="email",
                    roles_claim="groups",
                    allow_raw_roles=[],
                    signature_verification=SignatureVerificationConfig(
                        enabled=False, issuer="https://example.com", audience="aud"
                    ),
                ),
            )
        if provider == "none":
            return AuthConfig(
                provider="none",
                none=NoneProviderConfig(
                    default_account="test_user", default_roles=["operator"]
                ),
            )
        return AuthConfig(provider=provider)

    def test_none_returns_null_provider(self) -> None:
        cfg = self._make_auth_cfg("none")
        assert isinstance(build_provider(cfg), NullProvider)

    def test_none_without_none_config_raises(self) -> None:
        cfg = AuthConfig(provider="none")
        with pytest.raises(ValueError, match="auth.none config is required"):
            build_provider(cfg)

    def test_header_returns_header_provider(self) -> None:
        cfg = self._make_auth_cfg("header")
        assert isinstance(build_provider(cfg), HeaderProvider)

    def test_header_without_header_config_raises(self) -> None:
        cfg = AuthConfig(provider="header")
        with pytest.raises(ValueError, match="auth.header config is required"):
            build_provider(cfg)

    def test_none_provider_uses_config_account_and_roles(self) -> None:
        cfg = self._make_auth_cfg("none")
        provider = build_provider(cfg)
        user = asyncio.run(provider.authenticate(AuthContext(context={})))
        assert user is not None
        assert user.account == "test_user"
        assert user.roles == ["operator"]

    def test_unknown_provider_raises(self) -> None:
        cfg = AuthConfig(provider="unknown")
        with pytest.raises(ValueError, match="Unknown auth provider"):
            build_provider(cfg)
