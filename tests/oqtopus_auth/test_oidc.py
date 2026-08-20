"""Unit tests for oqtopus_auth/oidc.py scope helpers and JWKS discovery."""

from __future__ import annotations

import json
from types import TracebackType
from typing import Literal

import pytest
from pytest_mock import MockerFixture

from oqtopus_auth import oidc
from oqtopus_auth.config import OidcProviderConfig
from oqtopus_auth.oidc import (
    OidcError,
    extract_scopes,
    has_required_scope,
)


class TestExtractScopes:
    def test_space_delimited_scope_string(self) -> None:
        assert extract_scopes({"scope": "a b c"}) == {"a", "b", "c"}

    def test_scp_list(self) -> None:
        assert extract_scopes({"scp": ["a", "b"]}) == {"a", "b"}

    def test_scp_space_delimited_string(self) -> None:
        assert extract_scopes({"scp": "a b c"}) == {"a", "b", "c"}

    def test_both_are_merged(self) -> None:
        assert extract_scopes({"scope": "a", "scp": ["b"]}) == {"a", "b"}

    def test_absent_returns_empty(self) -> None:
        assert extract_scopes({}) == set()

    def test_non_string_scope_ignored(self) -> None:
        assert extract_scopes({"scope": 123}) == set()


class TestHasRequiredScope:
    def test_present(self) -> None:
        assert has_required_scope({"scope": "provider.write x"}, "provider.write")

    def test_absent(self) -> None:
        assert not has_required_scope({"scope": "openid"}, "provider.write")

    def test_empty(self) -> None:
        assert not has_required_scope({}, "provider.write")


# ── JWKS discovery ────────────────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        return False


def _cfg(**overrides: object) -> OidcProviderConfig:
    kwargs: dict[str, object] = {"issuer": "https://idp.example.com", "audience": "api"}
    kwargs.update(overrides)
    return OidcProviderConfig(**kwargs)  # type: ignore[arg-type]


class TestJwksDiscovery:
    def test_explicit_jwks_url_skips_discovery(self, mocker: MockerFixture) -> None:
        urlopen = mocker.patch("oqtopus_auth.oidc.urllib.request.urlopen")
        cfg = _cfg(jwks_url="https://idp.example.com/keys")
        assert oidc._resolve_jwks_url(cfg) == "https://idp.example.com/keys"
        urlopen.assert_not_called()

    def test_discovery_resolves_jwks_uri(self, mocker: MockerFixture) -> None:
        oidc._discover_jwks_url.cache_clear()
        body = json.dumps(
            {"jwks_uri": "https://idp.example.com/protocol/openid-connect/certs"}
        ).encode()
        mocker.patch(
            "oqtopus_auth.oidc.urllib.request.urlopen",
            return_value=_FakeResp(body),
        )
        assert (
            oidc._resolve_jwks_url(_cfg())
            == "https://idp.example.com/protocol/openid-connect/certs"
        )

    def test_discovery_rejects_non_http_jwks_uri(self, mocker: MockerFixture) -> None:
        oidc._discover_jwks_url.cache_clear()
        body = json.dumps({"jwks_uri": "file:///etc/passwd"}).encode()
        mocker.patch(
            "oqtopus_auth.oidc.urllib.request.urlopen",
            return_value=_FakeResp(body),
        )
        with pytest.raises(OidcError, match="non-HTTP"):
            oidc._resolve_jwks_url(_cfg(issuer="https://other.example.com"))
