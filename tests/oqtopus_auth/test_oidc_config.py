"""Validation tests for OidcProviderConfig (fail-closed security config)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from oqtopus_auth.config import OidcProviderConfig, parse_oidc_provider_config

ISSUER = "https://idp.example.com/realms/oqtopus"


def _valid(**overrides: object) -> OidcProviderConfig:
    kwargs: dict[str, object] = {"issuer": ISSUER, "audience": "api"}
    kwargs.update(overrides)
    return OidcProviderConfig(**kwargs)  # type: ignore[arg-type]


class TestOidcProviderConfigValidation:
    def test_valid_config(self) -> None:
        cfg = _valid(required_scope="provider.write")
        assert cfg.audience == "api"

    def test_unknown_field_is_rejected(self) -> None:
        # A typo like "audence" must fail loudly, not silently disable aud checks.
        with pytest.raises(ValidationError):
            OidcProviderConfig(issuer=ISSUER, audience="api", audence="api")  # type: ignore[call-arg]

    def test_token_binding_required_by_default(self) -> None:
        with pytest.raises(ValidationError, match="token binding is required"):
            OidcProviderConfig(issuer=ISSUER)

    def test_allow_any_audience_opt_out(self) -> None:
        cfg = OidcProviderConfig(issuer=ISSUER, allow_any_audience=True)
        assert cfg.audience is None
        assert cfg.allow_any_audience is True

    def test_audience_and_allow_any_audience_are_mutually_exclusive(self) -> None:
        with pytest.raises(ValidationError, match="mutually exclusive"):
            OidcProviderConfig(
                issuer=ISSUER, audience="api", allow_any_audience=True
            )

    # ── client_id binding (e.g. Cognito access tokens with no aud) ──────────────

    def test_client_id_is_a_valid_binding_without_audience(self) -> None:
        cfg = OidcProviderConfig(
            issuer=ISSUER, client_id="app-client-123", token_use="access"
        )
        assert cfg.audience is None
        assert cfg.client_id == "app-client-123"
        assert cfg.client_id_claim == "client_id"

    def test_audience_and_client_id_can_coexist(self) -> None:
        cfg = OidcProviderConfig(
            issuer=ISSUER, audience="api", client_id="app-client-123"
        )
        assert cfg.audience == "api"
        assert cfg.client_id == "app-client-123"

    def test_client_id_list_is_accepted(self) -> None:
        cfg = OidcProviderConfig(issuer=ISSUER, client_id=["a", "b"])
        assert cfg.client_id == ["a", "b"]

    def test_client_id_and_allow_any_audience_are_mutually_exclusive(self) -> None:
        with pytest.raises(ValidationError, match="mutually exclusive"):
            OidcProviderConfig(
                issuer=ISSUER, client_id="app-client-123", allow_any_audience=True
            )

    def test_empty_client_id_string_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OidcProviderConfig(issuer=ISSUER, client_id="")

    def test_empty_client_id_list_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OidcProviderConfig(issuer=ISSUER, client_id=[])

    def test_client_id_list_with_empty_entry_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OidcProviderConfig(issuer=ISSUER, client_id=["ok", "  "])

    def test_empty_token_use_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OidcProviderConfig(issuer=ISSUER, audience="api", token_use="")

    def test_empty_client_id_claim_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OidcProviderConfig(
                issuer=ISSUER, client_id="x", client_id_claim="  "
            )

    def test_empty_audience_string_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OidcProviderConfig(issuer=ISSUER, audience="")

    def test_empty_required_scope_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _valid(required_scope="")

    def test_empty_issuer_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OidcProviderConfig(issuer="  ", audience="api")

    def test_empty_algorithms_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _valid(algorithms=[])

    def test_none_algorithm_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unsupported/insecure"):
            _valid(algorithms=["none"])

    def test_hs_algorithm_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unsupported/insecure"):
            _valid(algorithms=["HS256"])

    def test_asymmetric_algorithms_allowed(self) -> None:
        cfg = _valid(algorithms=["RS256", "ES256", "EdDSA"])
        assert "ES256" in cfg.algorithms


class TestParseOidcProviderConfig:
    def test_missing_issuer_raises(self) -> None:
        with pytest.raises(ValueError, match="auth.oidc.issuer is required"):
            parse_oidc_provider_config({})

    def test_unknown_key_raises(self) -> None:
        with pytest.raises(ValidationError):
            parse_oidc_provider_config(
                {"issuer": ISSUER, "audience": "api", "required_scop": "x"}
            )
