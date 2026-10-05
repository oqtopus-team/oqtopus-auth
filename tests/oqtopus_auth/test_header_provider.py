"""Unit tests for oqtopus_auth/header_provider.py."""

from __future__ import annotations

import asyncio

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from pytest_mock import MockerFixture

from oqtopus_auth.base import AuthContext, AuthenticationError
from oqtopus_auth.config import HeaderProviderConfig, SignatureVerificationConfig
from oqtopus_auth.header_provider import (
    HeaderProvider,
    _extract_roles,
    _get_claim,
    extract_token,
)


SECRET = "test-secret-key-for-hs256-at-least-32-bytes"


# ── extract_token ────────────────────────────────────────────────────────────


class TestExtractToken:
    def test_authorization_bearer_stripped(self) -> None:
        assert extract_token("authorization", "Bearer abc.def.ghi") == "abc.def.ghi"

    def test_authorization_bearer_case_insensitive(self) -> None:
        assert extract_token("authorization", "BEARER abc.def.ghi") == "abc.def.ghi"

    def test_authorization_missing_bearer_returns_none(self) -> None:
        assert extract_token("authorization", "abc.def.ghi") is None

    def test_empty_header_returns_none(self) -> None:
        assert extract_token("authorization", "") is None

    def test_custom_header_returns_value_as_is(self) -> None:
        assert extract_token("x-jwt-token", "abc.def.ghi") == "abc.def.ghi"

    def test_custom_header_empty_returns_none(self) -> None:
        assert extract_token("x-jwt-token", "") is None


# ── _get_claim ────────────────────────────────────────────────────────────────


class TestGetClaim:
    def test_string_key_present(self) -> None:
        assert _get_claim({"email": "a@b.com"}, "email") == "a@b.com"

    def test_string_key_missing_returns_none(self) -> None:
        assert _get_claim({}, "email") is None

    def test_nested_list_path(self) -> None:
        payload = {"custom": {"cognito:groups": ["admin"]}}
        assert _get_claim(payload, ["custom", "cognito:groups"]) == ["admin"]

    def test_nested_intermediate_not_dict_returns_none(self) -> None:
        assert _get_claim({"a": "not-a-dict"}, ["a", "b"]) is None

    def test_nested_missing_key_returns_none(self) -> None:
        assert _get_claim({"a": {}}, ["a", "b"]) is None


# ── _extract_roles ────────────────────────────────────────────────────────────


class TestExtractRoles:
    def test_none_returns_empty(self) -> None:
        assert _extract_roles(None) == []

    def test_list_input(self) -> None:
        assert _extract_roles(["admin", "user"]) == ["admin", "user"]

    def test_list_filters_empty_strings(self) -> None:
        assert _extract_roles(["admin", "", "user"]) == ["admin", "user"]

    def test_comma_separated_string(self) -> None:
        assert _extract_roles("admin,user, guest") == ["admin", "user", "guest"]

    def test_other_type_returns_empty(self) -> None:
        assert _extract_roles(42) == []


# ── HeaderProvider.authenticate ───────────────────────────────────────────────


class TestHeaderProviderAuthenticate:
    def _make_provider(self) -> HeaderProvider:
        config = HeaderProviderConfig(
            jwt_header="authorization", user_claim="email", roles_claim="groups"
        )
        return HeaderProvider(config, role_mappings={})

    def test_missing_user_claim_is_rejected(self) -> None:
        provider = self._make_provider()
        token = pyjwt.encode({"groups": ["admin"]}, SECRET, algorithm="HS256")
        context = AuthContext(context={"authorization": f"Bearer {token}"})
        with pytest.raises(AuthenticationError, match="missing user identifier claim"):
            asyncio.run(provider.authenticate(context))

    def test_present_user_claim_is_accepted(self) -> None:
        provider = self._make_provider()
        token = pyjwt.encode(
            {"email": "a@b.com", "groups": ["admin"]}, SECRET, algorithm="HS256"
        )
        context = AuthContext(context={"authorization": f"Bearer {token}"})
        user = asyncio.run(provider.authenticate(context))
        assert user is not None
        assert user.account == "a@b.com"

    def test_malformed_jwt_is_rejected(self) -> None:
        provider = self._make_provider()
        context = AuthContext(context={"authorization": "Bearer not-a-real-jwt"})
        with pytest.raises(AuthenticationError, match="invalid JWT"):
            asyncio.run(provider.authenticate(context))


# ── HeaderProvider signature verification (mocked JWKS) ───────────────────────


def _rsa_keypair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


class TestHeaderProviderSignatureVerification:
    def _make_provider(
        self, mocker: MockerFixture, public_key: RSAPublicKey, *, issuer: str
    ) -> HeaderProvider:
        signing_key = mocker.Mock(key=public_key)
        jwk_client = mocker.Mock()
        jwk_client.get_signing_key_from_jwt.return_value = signing_key
        mocker.patch(
            "oqtopus_auth.header_provider.PyJWKClient", return_value=jwk_client
        )
        config = HeaderProviderConfig(
            jwt_header="authorization",
            user_claim="email",
            roles_claim="groups",
            signature_verification=SignatureVerificationConfig(
                enabled=True, issuer=issuer, audience="aud"
            ),
        )
        return HeaderProvider(config, role_mappings={})

    def test_valid_signature_is_accepted(self, mocker: MockerFixture) -> None:
        private_key, public_key = _rsa_keypair()
        issuer = "https://issuer-valid.example.com"
        provider = self._make_provider(mocker, public_key, issuer=issuer)
        token = pyjwt.encode(
            {"email": "a@b.com", "groups": ["admin"], "iss": issuer, "aud": "aud"},
            private_key,
            algorithm="RS256",
        )
        context = AuthContext(context={"authorization": f"Bearer {token}"})
        user = asyncio.run(provider.authenticate(context))
        assert user is not None
        assert user.account == "a@b.com"

    def test_signature_from_wrong_key_is_rejected(self, mocker: MockerFixture) -> None:
        _, public_key = _rsa_keypair()
        other_private_key, _ = _rsa_keypair()
        issuer = "https://issuer-wrong-key.example.com"
        provider = self._make_provider(mocker, public_key, issuer=issuer)
        # Signed with a key that doesn't match the "published" public key.
        token = pyjwt.encode(
            {"email": "a@b.com", "groups": ["admin"], "iss": issuer, "aud": "aud"},
            other_private_key,
            algorithm="RS256",
        )
        context = AuthContext(context={"authorization": f"Bearer {token}"})
        with pytest.raises(AuthenticationError, match="invalid JWT"):
            asyncio.run(provider.authenticate(context))

    def test_signature_checked_before_role_gate(self, mocker: MockerFixture) -> None:
        # A forged token whose (unverified) roles don't match must fail as an
        # authentication error (invalid JWT), NOT an authorization error — else
        # the response leaks whether the forged claims would have been allowed.
        _, public_key = _rsa_keypair()
        other_private_key, _ = _rsa_keypair()
        issuer = "https://issuer-order.example.com"
        signing_key = mocker.Mock(key=public_key)
        jwk_client = mocker.Mock()
        jwk_client.get_signing_key_from_jwt.return_value = signing_key
        mocker.patch(
            "oqtopus_auth.header_provider.PyJWKClient", return_value=jwk_client
        )
        config = HeaderProviderConfig(
            jwt_header="authorization",
            user_claim="email",
            roles_claim="groups",
            allow_raw_roles=["allowed.*"],
            signature_verification=SignatureVerificationConfig(
                enabled=True, issuer=issuer, audience="aud"
            ),
        )
        provider = HeaderProvider(config, role_mappings={})
        token = pyjwt.encode(
            {"email": "a@b.com", "groups": ["not-allowed"], "iss": issuer, "aud": "aud"},
            other_private_key,  # forged signature
            algorithm="RS256",
        )
        context = AuthContext(context={"authorization": f"Bearer {token}"})
        with pytest.raises(AuthenticationError, match="invalid JWT"):
            asyncio.run(provider.authenticate(context))

    def test_wrong_audience_is_rejected(self, mocker: MockerFixture) -> None:
        private_key, public_key = _rsa_keypair()
        issuer = "https://issuer-wrong-aud.example.com"
        provider = self._make_provider(mocker, public_key, issuer=issuer)
        token = pyjwt.encode(
            {
                "email": "a@b.com",
                "groups": ["admin"],
                "iss": issuer,
                "aud": "someone-else",
            },
            private_key,
            algorithm="RS256",
        )
        context = AuthContext(context={"authorization": f"Bearer {token}"})
        with pytest.raises(AuthenticationError, match="invalid JWT"):
            asyncio.run(provider.authenticate(context))
