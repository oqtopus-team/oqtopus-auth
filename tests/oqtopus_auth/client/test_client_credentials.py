"""Unit tests for oqtopus_auth/client/client_credentials.py (mocked httpx2)."""

from __future__ import annotations

import base64

import httpx2
import pytest
from pytest_mock import MockerFixture

from oqtopus_auth.client import (
    ClientCredentialsError,
    ClientCredentialsTokenProvider,
)

TOKEN_URL = "https://idp.example.com/realms/oqtopus/protocol/openid-connect/token"


def _make_provider(**overrides: object) -> ClientCredentialsTokenProvider:
    kwargs: dict[str, object] = {
        "token_url": TOKEN_URL,
        "client_id": "oqtopus-engine",
        "client_secret": "secret",
        "scope": "provider.write",
    }
    kwargs.update(overrides)
    return ClientCredentialsTokenProvider(**kwargs)  # type: ignore[arg-type]


def _ok(mocker: MockerFixture, access_token: str = "tok-1", expires_in: int = 900) -> object:
    resp = mocker.Mock()
    resp.status_code = 200
    resp.json.return_value = {
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
    }
    return resp


class TestClientCredentialsTokenProvider:
    def test_token_is_cached_and_reused(self, mocker: MockerFixture) -> None:
        post = mocker.patch("httpx2.post", return_value=_ok(mocker))
        provider = _make_provider()
        assert provider.get_token() == "tok-1"
        assert provider.get_token() == "tok-1"
        post.assert_called_once()

    def test_basic_auth_is_default(self, mocker: MockerFixture) -> None:
        post = mocker.patch("httpx2.post", return_value=_ok(mocker))
        _make_provider().get_token()
        _, kwargs = post.call_args
        assert kwargs["data"]["grant_type"] == "client_credentials"
        assert kwargs["data"]["scope"] == "provider.write"
        assert kwargs["timeout"] > 0
        # Default is client_secret_basic: credentials in the Authorization header,
        # not the request body.
        assert "client_id" not in kwargs["data"]
        auth = kwargs["headers"]["Authorization"]
        assert auth.startswith("Basic ")
        decoded = base64.b64decode(auth.removeprefix("Basic ")).decode()
        assert decoded == "oqtopus-engine:secret"

    def test_post_auth_style_sends_credentials_in_body(
        self, mocker: MockerFixture
    ) -> None:
        post = mocker.patch("httpx2.post", return_value=_ok(mocker))
        _make_provider(auth_style="post").get_token()
        _, kwargs = post.call_args
        assert kwargs["data"]["client_id"] == "oqtopus-engine"
        assert kwargs["data"]["client_secret"] == "secret"
        assert "Authorization" not in kwargs["headers"]

    def test_basic_auth_url_encodes_special_characters(
        self, mocker: MockerFixture
    ) -> None:
        post = mocker.patch("httpx2.post", return_value=_ok(mocker))
        _make_provider(
            client_id="id:with/special", client_secret="p@ss:w rd"
        ).get_token()
        _, kwargs = post.call_args
        auth = kwargs["headers"]["Authorization"]
        decoded = base64.b64decode(auth.removeprefix("Basic ")).decode()
        # RFC 6749 §2.3.1: each credential is application/x-www-form-urlencoded
        # before the ":" join -- note a space becomes "+", not "%20".
        assert decoded == "id%3Awith%2Fspecial:p%40ss%3Aw+rd"

    def test_short_lived_token_is_still_cached(self, mocker: MockerFixture) -> None:
        # expires_in (30) <= default skew (60): the clamp must still cache it,
        # otherwise it would be treated as already-expired and refetched each call.
        post = mocker.patch("httpx2.post", return_value=_ok(mocker, expires_in=30))
        mocker.patch(
            "oqtopus_auth.client.client_credentials.time.monotonic",
            side_effect=[0.0, 5.0],  # requested_at=0 -> expiry 0+30-15=15; check at 5
        )
        provider = _make_provider()  # default skew 60
        assert provider.get_token() == "tok-1"
        assert provider.get_token() == "tok-1"
        post.assert_called_once()

    def test_negative_skew_rejected(self) -> None:
        with pytest.raises(ValueError, match="expiry_skew_seconds"):
            _make_provider(expiry_skew_seconds=-1)

    def test_nonpositive_timeout_rejected(self) -> None:
        with pytest.raises(ValueError, match="timeout_seconds"):
            _make_provider(timeout_seconds=0)

    def test_unknown_auth_style_rejected(self) -> None:
        with pytest.raises(ValueError, match="auth_style"):
            _make_provider(auth_style="basci")  # typo must not fall back to post

    def test_refresh_after_expiry(self, mocker: MockerFixture) -> None:
        post = mocker.patch(
            "httpx2.post",
            side_effect=[_ok(mocker, "tok-1"), _ok(mocker, "tok-2")],
        )
        # monotonic is read 3x: refresh#1 stamps expiry at 0+900; the expiry
        # check on the 2nd get_token sees 1000 (>=900) and forces refresh#2.
        mocker.patch(
            "oqtopus_auth.client.client_credentials.time.monotonic",
            side_effect=[0.0, 1000.0, 1000.0],
        )
        provider = _make_provider(expiry_skew_seconds=0)
        assert provider.get_token() == "tok-1"
        assert provider.get_token() == "tok-2"
        assert post.call_count == 2

    def test_force_refresh(self, mocker: MockerFixture) -> None:
        post = mocker.patch(
            "httpx2.post",
            side_effect=[_ok(mocker, "tok-1"), _ok(mocker, "tok-2")],
        )
        provider = _make_provider()
        assert provider.get_token() == "tok-1"
        assert provider.get_token(force_refresh=True) == "tok-2"
        assert post.call_count == 2

    def test_non_200_raises(self, mocker: MockerFixture) -> None:
        resp = mocker.Mock()
        resp.status_code = 401
        resp.text = "invalid_client"
        mocker.patch("httpx2.post", return_value=resp)
        with pytest.raises(ClientCredentialsError):
            _make_provider().get_token()

    def test_network_error_raises(self, mocker: MockerFixture) -> None:
        mocker.patch("httpx2.post", side_effect=httpx2.ConnectError("boom"))
        with pytest.raises(ClientCredentialsError):
            _make_provider().get_token()

    def test_malformed_response_raises(self, mocker: MockerFixture) -> None:
        resp = mocker.Mock()
        resp.status_code = 200
        resp.json.return_value = {"expires_in": 900}
        mocker.patch("httpx2.post", return_value=resp)
        with pytest.raises(ClientCredentialsError):
            _make_provider().get_token()

    def test_null_access_token_rejected(self, mocker: MockerFixture) -> None:
        resp = mocker.Mock()
        resp.status_code = 200
        resp.json.return_value = {
            "token_type": "Bearer",
            "access_token": None,
            "expires_in": 900,
        }
        mocker.patch("httpx2.post", return_value=resp)
        with pytest.raises(ClientCredentialsError, match="access_token"):
            _make_provider().get_token()

    def test_blank_access_token_rejected(self, mocker: MockerFixture) -> None:
        resp = mocker.Mock()
        resp.status_code = 200
        resp.json.return_value = {
            "token_type": "Bearer",
            "access_token": "   ",
            "expires_in": 900,
        }
        mocker.patch("httpx2.post", return_value=resp)
        with pytest.raises(ClientCredentialsError, match="access_token"):
            _make_provider().get_token()

    def test_non_positive_expires_in_rejected(self, mocker: MockerFixture) -> None:
        resp = mocker.Mock()
        resp.status_code = 200
        resp.json.return_value = {
            "token_type": "Bearer",
            "access_token": "tok",
            "expires_in": 0,
        }
        mocker.patch("httpx2.post", return_value=resp)
        with pytest.raises(ClientCredentialsError, match="expires_in"):
            _make_provider().get_token()

    def test_float_expires_in_rejected(self, mocker: MockerFixture) -> None:
        resp = mocker.Mock()
        resp.status_code = 200
        resp.json.return_value = {
            "token_type": "Bearer",
            "access_token": "tok",
            "expires_in": 0.5,
        }
        mocker.patch("httpx2.post", return_value=resp)
        with pytest.raises(ClientCredentialsError, match="expires_in"):
            _make_provider().get_token()

    def test_missing_token_type_rejected(self, mocker: MockerFixture) -> None:
        resp = mocker.Mock()
        resp.status_code = 200
        resp.json.return_value = {"access_token": "tok", "expires_in": 900}
        mocker.patch("httpx2.post", return_value=resp)
        with pytest.raises(ClientCredentialsError, match="token_type"):
            _make_provider().get_token()

    def test_non_bearer_token_type_rejected(self, mocker: MockerFixture) -> None:
        resp = mocker.Mock()
        resp.status_code = 200
        resp.json.return_value = {
            "access_token": "tok",
            "expires_in": 900,
            "token_type": "mac",
        }
        mocker.patch("httpx2.post", return_value=resp)
        with pytest.raises(ClientCredentialsError, match="token_type"):
            _make_provider().get_token()

    def test_non_json_body_rejected(self, mocker: MockerFixture) -> None:
        resp = mocker.Mock()
        resp.status_code = 200
        resp.json.side_effect = ValueError("no json")
        mocker.patch("httpx2.post", return_value=resp)
        with pytest.raises(ClientCredentialsError, match="not valid JSON"):
            _make_provider().get_token()
