"""Authentication package: providers and configuration models (framework-agnostic)."""

from .base import (
    AuthContext,
    AuthenticationError,
    AuthorizationError,
    AuthProvider,
    AuthUser,
    InsufficientScopeError,
)
from .config import (
    AuthConfig,
    HeaderProviderConfig,
    NoneProviderConfig,
    OidcProviderConfig,
    PublicIdentityConfig,
    PublicPathConfig,
    SignatureVerificationConfig,
    parse_auth_config,
    parse_header_provider_config,
    parse_none_provider_config,
    parse_oidc_provider_config,
)
from .factory import build_provider, register_provider
from .header_provider import HeaderProvider
from .null_provider import NullProvider
from .oidc import (
    OidcError,
    extract_scopes,
    has_required_scope,
    verify_bearer_token,
    verify_bearer_token_async,
)
from .oidc_provider import OidcProvider
from .permissions import Permissions, has_permission, parse_role_permissions

__all__ = [
    "AuthConfig",
    "AuthContext",
    "AuthProvider",
    "AuthUser",
    "AuthenticationError",
    "AuthorizationError",
    "HeaderProvider",
    "HeaderProviderConfig",
    "InsufficientScopeError",
    "NoneProviderConfig",
    "NullProvider",
    "OidcError",
    "OidcProvider",
    "OidcProviderConfig",
    "Permissions",
    "PublicIdentityConfig",
    "PublicPathConfig",
    "SignatureVerificationConfig",
    "build_provider",
    "extract_scopes",
    "has_permission",
    "has_required_scope",
    "parse_auth_config",
    "parse_header_provider_config",
    "parse_none_provider_config",
    "parse_oidc_provider_config",
    "parse_role_permissions",
    "register_provider",
    "verify_bearer_token",
    "verify_bearer_token_async",
]
