"""Unit tests for oqtopus_auth/config.py."""

from __future__ import annotations

import pytest

from oqtopus_auth.config import (
    parse_auth_config,
    parse_header_provider_config,
    parse_none_provider_config,
)


class TestParseHeaderProviderConfigRequiredFields:
    def test_missing_jwt_header_raises(self) -> None:
        with pytest.raises(ValueError, match="auth.header.jwt_header is required"):
            parse_header_provider_config({"user_claim": "email"})

    def test_missing_user_claim_raises(self) -> None:
        with pytest.raises(ValueError, match="auth.header.user_claim is required"):
            parse_header_provider_config({"jwt_header": "authorization"})


class TestParseNoneProviderConfig:
    def test_missing_default_account_raises(self) -> None:
        with pytest.raises(ValueError, match="auth.none.default_account is required"):
            parse_none_provider_config({"default_roles": ["admin"]})

    def test_missing_default_roles_raises(self) -> None:
        with pytest.raises(ValueError, match="auth.none.default_roles is required"):
            parse_none_provider_config({"default_account": "admin_user"})

    def test_valid_config_succeeds(self) -> None:
        config = parse_none_provider_config(
            {"default_account": "admin_user", "default_roles": ["admin"]}
        )
        assert config.default_account == "admin_user"
        assert config.default_roles == ["admin"]


class TestParseAuthConfig:
    def test_defaults_to_none_provider(self) -> None:
        config = parse_auth_config(
            {"none": {"default_account": "admin_user", "default_roles": ["admin"]}}
        )
        assert config.provider == "none"
        assert config.none is not None
        assert config.none.default_account == "admin_user"
        assert config.header is None

    def test_header_provider(self) -> None:
        config = parse_auth_config(
            {
                "provider": "header",
                "header": {"jwt_header": "authorization", "user_claim": "email"},
                "role_mappings": {"raw.admin": "admin"},
            }
        )
        assert config.provider == "header"
        assert config.header is not None
        assert config.header.jwt_header == "authorization"
        assert config.none is None
        assert config.role_mappings == {"raw.admin": "admin"}

    def test_public_paths_default_to_empty(self) -> None:
        config = parse_auth_config(
            {"none": {"default_account": "admin_user", "default_roles": ["admin"]}}
        )
        assert config.public_paths == []

    def test_public_paths_are_parsed(self) -> None:
        config = parse_auth_config(
            {
                "none": {"default_account": "admin_user", "default_roles": ["admin"]},
                "public_paths": [
                    {"method": "GET", "path": "/health"},
                    {"path": "/metrics"},  # method omitted -> defaults to "*"
                ],
            }
        )
        assert len(config.public_paths) == 2
        assert config.public_paths[0].method == "GET"
        assert config.public_paths[0].path == "/health"
        assert config.public_paths[1].method == "*"

    def test_public_identity_defaults_to_none(self) -> None:
        config = parse_auth_config(
            {"none": {"default_account": "admin_user", "default_roles": ["admin"]}}
        )
        assert config.public_identity is None

    def test_public_identity_is_parsed(self) -> None:
        config = parse_auth_config(
            {
                "none": {"default_account": "admin_user", "default_roles": ["admin"]},
                "public_identity": {"default_roles": ["public"]},
            }
        )
        assert config.public_identity is not None
        assert config.public_identity.default_account == "public"
        assert config.public_identity.default_roles == ["public"]

    def test_public_identity_account_can_be_overridden(self) -> None:
        config = parse_auth_config(
            {
                "none": {"default_account": "admin_user", "default_roles": ["admin"]},
                "public_identity": {
                    "default_account": "anonymous",
                    "default_roles": ["metrics-public"],
                },
            }
        )
        assert config.public_identity is not None
        assert config.public_identity.default_account == "anonymous"
        assert config.public_identity.default_roles == ["metrics-public"]


class TestParseHeaderProviderConfigSignatureVerification:
    def test_enabled_without_issuer_or_audience_raises(self) -> None:
        raw = {
            "jwt_header": "authorization",
            "user_claim": "email",
            "signature_verification": {"enabled": True},
        }
        with pytest.raises(ValueError, match="issuer and .audience are required"):
            parse_header_provider_config(raw)

    def test_enabled_with_issuer_and_audience_succeeds(self) -> None:
        raw = {
            "jwt_header": "authorization",
            "user_claim": "email",
            "signature_verification": {
                "enabled": True,
                "issuer": "https://example.com",
                "audience": "aud",
            },
        }
        config = parse_header_provider_config(raw)
        assert config.signature_verification is not None
        assert config.signature_verification.enabled is True

    def test_disabled_without_issuer_or_audience_succeeds(self) -> None:
        raw = {
            "jwt_header": "authorization",
            "user_claim": "email",
            "signature_verification": {"enabled": False},
        }
        config = parse_header_provider_config(raw)
        assert config.signature_verification is not None
        assert config.signature_verification.enabled is False

    def test_omitted_signature_verification_succeeds(self) -> None:
        raw = {"jwt_header": "authorization", "user_claim": "email"}
        config = parse_header_provider_config(raw)
        assert config.signature_verification is None
