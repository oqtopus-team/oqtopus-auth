"""Unit tests for oqtopus_auth/oidc.py scope helpers and JWKS discovery."""

from __future__ import annotations

import json
import threading
from types import TracebackType
from typing import Literal

import pytest
from jwt.exceptions import PyJWKClientError
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
            {
                "issuer": "https://idp.example.com",
                "jwks_uri": "https://idp.example.com/protocol/openid-connect/certs",
            }
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
        body = json.dumps(
            {
                "issuer": "https://other.example.com",
                "jwks_uri": "file:///etc/passwd",
            }
        ).encode()
        mocker.patch(
            "oqtopus_auth.oidc.urllib.request.urlopen",
            return_value=_FakeResp(body),
        )
        with pytest.raises(OidcError, match="non-HTTP"):
            oidc._resolve_jwks_url(_cfg(issuer="https://other.example.com"))

    def test_discovery_rejects_issuer_mismatch(self, mocker: MockerFixture) -> None:
        # OIDC Discovery §4.3: the document's issuer must match the configured one.
        oidc._discover_jwks_url.cache_clear()
        body = json.dumps(
            {
                "issuer": "https://evil.example.com",
                "jwks_uri": "https://idp.example.com/certs",
            }
        ).encode()
        mocker.patch(
            "oqtopus_auth.oidc.urllib.request.urlopen",
            return_value=_FakeResp(body),
        )
        with pytest.raises(OidcError, match="issuer mismatch"):
            oidc._resolve_jwks_url(_cfg())

    def test_discovery_fetch_failure_raises_oidc_error(
        self, mocker: MockerFixture
    ) -> None:
        oidc._discover_jwks_url.cache_clear()
        mocker.patch(
            "oqtopus_auth.oidc.urllib.request.urlopen",
            side_effect=OSError("connection refused"),
        )
        with pytest.raises(OidcError, match="discovery failed"):
            oidc._resolve_jwks_url(_cfg())


class TestRateLimitedJWKClient:
    def test_unknown_kid_forces_at_most_one_refresh_per_window(
        self, mocker: MockerFixture
    ) -> None:
        client = oidc._RateLimitedJWKClient("https://idp.example.com/certs")
        get_keys = mocker.patch.object(client, "get_signing_keys", return_value=[])
        mocker.patch.object(client, "match_kid", return_value=None)
        # 20 bogus (unknown-kid) tokens must not trigger 20 forced JWKS refreshes.
        for _ in range(20):
            with pytest.raises(PyJWKClientError):
                client.get_signing_key("bogus-kid")
        forced = [c for c in get_keys.call_args_list if c.kwargs.get("refresh")]
        assert len(forced) == 1

    def test_known_kid_does_not_force_refresh(self, mocker: MockerFixture) -> None:
        client = oidc._RateLimitedJWKClient("https://idp.example.com/certs")
        sentinel = object()
        get_keys = mocker.patch.object(
            client, "get_signing_keys", return_value=["k"]
        )
        mocker.patch.object(client, "match_kid", return_value=sentinel)
        assert client.get_signing_key("good-kid") is sentinel
        assert not any(c.kwargs.get("refresh") for c in get_keys.call_args_list)

    def test_concurrent_rotation_forces_only_one_refresh(
        self, mocker: MockerFixture
    ) -> None:
        # After a genuine rotation, concurrent requests must all get the new key,
        # with only ONE forced refresh (the in-lock re-check serves the others).
        client = oidc._RateLimitedJWKClient("https://idp.example.com/certs")
        sentinel = object()
        state = {"refreshed": False}
        refresh_count = 0
        refresh_lock = threading.Lock()
        initial_lookup_barrier = threading.Barrier(2)
        thread_state = threading.local()

        def fake_get_signing_keys(refresh: bool = False) -> list[str]:
            nonlocal refresh_count
            if refresh:
                with refresh_lock:
                    refresh_count += 1
                state["refreshed"] = True
                return ["fresh-key"]

            lookup_count = getattr(thread_state, "lookup_count", 0)
            thread_state.lookup_count = lookup_count + 1
            if lookup_count == 0:
                # Both workers must complete their initial, out-of-lock lookup
                # against the stale cache before either can force a refresh.
                initial_lookup_barrier.wait()
                return ["stale-key"]
            return ["fresh-key"] if state["refreshed"] else ["stale-key"]

        def fake_match_kid(keys: object, _kid: str) -> object:
            return sentinel if keys == ["fresh-key"] else None

        mocker.patch.object(
            client, "get_signing_keys", side_effect=fake_get_signing_keys
        )
        mocker.patch.object(client, "match_kid", side_effect=fake_match_kid)

        results: list[object] = []

        def worker() -> None:
            try:
                results.append(client.get_signing_key("rotated-kid"))
            except Exception as exc:  # noqa: BLE001 - record for the assertion
                results.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert results == [sentinel, sentinel]
        assert refresh_count == 1
