"""Unit tests for oqtopus_auth/oidc_provider.py (mocked JWKS)."""

from __future__ import annotations

import asyncio
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from pytest_mock import MockerFixture

from oqtopus_auth import oidc
from oqtopus_auth.base import (
    AuthContext,
    AuthenticationError,
    InsufficientScopeError,
)
from oqtopus_auth.config import OidcProviderConfig
from oqtopus_auth.oidc_provider import OidcProvider

ISSUER = "https://idp.example.com/realms/oqtopus"
AUDIENCE = "oqtopus-provider-api"


def _rsa_keypair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _mock_jwks(mocker: MockerFixture, public_key: RSAPublicKey) -> None:
    # verify_bearer_token resolves keys via oqtopus_auth.oidc._jwks_client, an
    # lru_cache over jwt.PyJWKClient — clear it and patch the client factory.
    oidc._jwks_client.cache_clear()
    signing_key = mocker.Mock(key=public_key)
    jwk_client = mocker.Mock()
    jwk_client.get_signing_key_from_jwt.return_value = signing_key
    mocker.patch("oqtopus_auth.oidc.jwt.PyJWKClient", return_value=jwk_client)


def _encode(private_key: RSAPrivateKey, claims: dict[str, object]) -> str:
    """Sign an RS256 token, adding a valid ``exp`` (required by the verifier)."""
    return pyjwt.encode(
        {"exp": int(time.time()) + 3600, **claims},
        private_key,
        algorithm="RS256",
    )


def _make_provider(**overrides: object) -> OidcProvider:
    cfg = OidcProviderConfig(
        issuer=ISSUER,
        jwks_url="https://idp.example.com/jwks",  # explicit → no discovery
        audience=AUDIENCE,
        required_scope="provider.write",
        **overrides,  # type: ignore[arg-type]
    )
    return OidcProvider(cfg)


def _bearer(token: str) -> AuthContext:
    return AuthContext(context={"authorization": f"Bearer {token}"})


class TestOidcProviderAuthenticate:
    def test_missing_token_is_401_authentication_error(self) -> None:
        provider = _make_provider()
        with pytest.raises(AuthenticationError, match="missing bearer token"):
            asyncio.run(provider.authenticate(AuthContext(context={})))

    def test_machine_principal_from_azp(self, mocker: MockerFixture) -> None:
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        # M2M: principal_claim="azp" (the client id); token carries no sub.
        token = _encode(
            private_key,
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "azp": "oqtopus-engine",
                "scope": "provider.write",
            },
        )
        provider = _make_provider(principal_claim="azp")
        user = asyncio.run(provider.authenticate(_bearer(token)))
        assert user is not None
        assert user.account == "oqtopus-engine"
        assert "provider.write" in user.scopes

    def test_principal_claim_is_used_verbatim(self, mocker: MockerFixture) -> None:
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        # Default principal_claim="sub"; azp present must NOT override it.
        token = _encode(
            private_key,
            {
                "iss": ISSUER,
                "aud": AUDIENCE,
                "sub": "service-account-id",
                "azp": "oqtopus-engine",
                "scope": "provider.write",
            },
        )
        user = asyncio.run(_make_provider().authenticate(_bearer(token)))
        assert user is not None
        assert user.account == "service-account-id"

    def test_missing_principal_claim_is_401(self, mocker: MockerFixture) -> None:
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        # principal_claim="azp" but the token has no azp.
        token = _encode(
            private_key,
            {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "scope": "provider.write"},
        )
        provider = _make_provider(principal_claim="azp")
        with pytest.raises(AuthenticationError, match="missing the 'azp' claim"):
            asyncio.run(provider.authenticate(_bearer(token)))

    def test_missing_scope_is_insufficient_scope_error(
        self, mocker: MockerFixture
    ) -> None:
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        token = _encode(
            private_key,
            {"iss": ISSUER, "aud": AUDIENCE, "azp": "x", "scope": "openid"},
        )
        with pytest.raises(InsufficientScopeError, match="missing required scope"):
            asyncio.run(_make_provider().authenticate(_bearer(token)))

    def test_wrong_key_is_401(self, mocker: MockerFixture) -> None:
        _, public_key = _rsa_keypair()
        other_private_key, _ = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        token = _encode(
            other_private_key,
            {"iss": ISSUER, "aud": AUDIENCE, "azp": "x", "scope": "provider.write"},
        )
        with pytest.raises(AuthenticationError, match="invalid bearer token"):
            asyncio.run(_make_provider().authenticate(_bearer(token)))

    def test_wrong_audience_is_401(self, mocker: MockerFixture) -> None:
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        token = _encode(
            private_key,
            {"iss": ISSUER, "aud": "someone-else", "azp": "x", "scope": "provider.write"},
        )
        with pytest.raises(AuthenticationError, match="invalid bearer token"):
            asyncio.run(_make_provider().authenticate(_bearer(token)))

    def test_no_scope_gate_when_required_scope_none(
        self, mocker: MockerFixture
    ) -> None:
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        cfg = OidcProviderConfig(
            issuer=ISSUER,
            jwks_url="https://idp.example.com/jwks",
            audience=AUDIENCE,
            required_scope=None,
        )
        token = _encode(private_key, {"iss": ISSUER, "aud": AUDIENCE, "sub": "someone"})
        user = asyncio.run(OidcProvider(cfg).authenticate(_bearer(token)))
        assert user is not None
        assert user.account == "someone"


COGNITO_CLIENT_ID = "app-client-123"


class TestCognitoAccessToken:
    """Access tokens with no `aud`, bound by `client_id` + `token_use` (Cognito)."""

    @staticmethod
    def _cognito_provider(**overrides: object) -> OidcProvider:
        kwargs: dict[str, object] = {
            "issuer": ISSUER,
            "jwks_url": "https://idp.example.com/jwks",
            "audience": None,
            "client_id": COGNITO_CLIENT_ID,
            "token_use": "access",
            "principal_claim": "sub",
            "required_scope": None,
        }
        kwargs.update(overrides)
        return OidcProvider(OidcProviderConfig(**kwargs))  # type: ignore[arg-type]

    @staticmethod
    def _token(private_key: RSAPrivateKey, **claims: object) -> str:
        # Shape of a Cognito access token: no `aud`, carries client_id/token_use.
        base: dict[str, object] = {
            "iss": ISSUER,
            "client_id": COGNITO_CLIENT_ID,
            "token_use": "access",
            "sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "username": "generated-cognito-username",
            "scope": "aws.cognito.signin.user.admin",
        }
        base.update(claims)
        return _encode(private_key, base)

    def test_valid_access_token_authenticates(self, mocker: MockerFixture) -> None:
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        user = asyncio.run(
            self._cognito_provider().authenticate(_bearer(self._token(private_key)))
        )
        assert user is not None
        assert user.account == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_wrong_client_id_is_rejected(self, mocker: MockerFixture) -> None:
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        token = self._token(private_key, client_id="some-other-client")
        with pytest.raises(AuthenticationError, match="invalid bearer token"):
            asyncio.run(self._cognito_provider().authenticate(_bearer(token)))

    def test_missing_client_id_claim_is_rejected(self, mocker: MockerFixture) -> None:
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        # Drop client_id by signing a token without it.
        claims: dict[str, object] = {
            "iss": ISSUER,
            "token_use": "access",
            "sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "username": "generated-cognito-username",
        }
        token = _encode(private_key, claims)
        with pytest.raises(AuthenticationError, match="invalid bearer token"):
            asyncio.run(self._cognito_provider().authenticate(_bearer(token)))

    def test_wrong_token_use_is_rejected(self, mocker: MockerFixture) -> None:
        # An id token (token_use="id") must not pass where access is required.
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        token = self._token(private_key, token_use="id")
        with pytest.raises(AuthenticationError, match="invalid bearer token"):
            asyncio.run(self._cognito_provider().authenticate(_bearer(token)))

    def test_accepts_one_of_several_client_ids(self, mocker: MockerFixture) -> None:
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        provider = self._cognito_provider(client_id=["other", COGNITO_CLIENT_ID])
        user = asyncio.run(provider.authenticate(_bearer(self._token(private_key))))
        assert user is not None
        assert user.account == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    @pytest.mark.parametrize(
        "bad_claim",
        [["app-client-123"], {"id": "app-client-123"}],
        ids=["array", "object"],
    )
    def test_non_string_client_id_claim_is_401_not_500(
        self, mocker: MockerFixture, bad_claim: object
    ) -> None:
        # A crafted token whose client_id claim is unhashable (array/object) must
        # map to 401, not surface as a 500 via an unhandled TypeError.
        private_key, public_key = _rsa_keypair()
        _mock_jwks(mocker, public_key)
        token = self._token(private_key, client_id=bad_claim)
        with pytest.raises(AuthenticationError, match="invalid bearer token"):
            asyncio.run(self._cognito_provider().authenticate(_bearer(token)))
