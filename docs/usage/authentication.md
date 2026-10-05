# Authentication

oqtopus-auth provides pluggable authentication providers, driven by an
`AuthConfig` that you parse from your own application's configuration
(typically via `parse_auth_config()` on a dict loaded from YAML/TOML/JSON).

!!! note "Config format"
    `parse_auth_config()` and the other `parse_*` helpers take a plain
    Python `dict` — oqtopus-auth has no YAML/TOML/JSON dependency itself.
    This page shows configuration as YAML throughout purely for
    readability; load it with whatever format/library your application
    already uses (e.g. `yaml.safe_load(...)`) and pass the resulting
    `dict` to `parse_auth_config()`.

## Provider overview

| `provider` | Description |
|------------|-------------|
| `none` | Authentication is disabled. All requests are allowed without a real user identity. Suitable for local development only. |
| `header` | **Trusts** a JWT carried in an HTTP header injected by a trusted reverse proxy (e.g. AWS ALB + Amazon Cognito via oauth2-proxy, or Cloudflare Access). The proxy is the verifier. |
| `oidc` | **Verifies** the incoming `Authorization: Bearer` token itself (signature via JWKS, `iss`/`exp`, and `aud` or `client_id`) and can enforce an OAuth2 `required_scope`. For when the app is the resource server (M2M / client-credentials callers, or an API with no edge authorizer). See [provider: oidc](#provider-oidc-verify-first). |

## provider: none

```yaml
auth:
  provider: none
  none:
    default_account: admin_user   # account name exposed to your app
    default_roles: [admin]        # roles granted when auth is disabled
```

Authentication is disabled. A virtual user with the configured
`default_account` and `default_roles` is returned by the provider for every
request, so that permission checks in your application behave identically
to a real session with those roles.

### none.*

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `default_account` | string | **Yes** | — | Account name attached to the synthetic user when auth is disabled. |
| `default_roles` | list of strings | **Yes** | — | Roles granted to every request when auth is disabled. Should match role names used by your permission mapping, if any. |

## provider: header

Trusts a JWT delivered in an HTTP header set by a reverse proxy that sits in
front of your application. The proxy is responsible for authenticating the
user and injecting the JWT before forwarding the request; oqtopus-auth
decodes the JWT to read the user's identifier and roles directly from claims.

### Authentication flow

#### Premise: role naming convention

oqtopus-auth assumes that roles in the identity provider follow an
`<application-identifier>.<role>` naming pattern, such as `myapp.admin` or
`myapp.operator`. A user may hold multiple roles simultaneously.

#### How each request is authenticated

1. **JWT extraction** — read the HTTP header named by `jwt_header`. For
   `authorization`, the `Bearer` prefix (and the following space) is
   stripped automatically; for any other header name (e.g.
   `cf-access-jwt-assertion`), the value is used
   as-is. If no JWT is present, the request is rejected with `403`.

2. **User identity** — navigate the JWT payload to the path specified by
   `user_claim` (e.g. `email`) and treat the value as the user's identifier.

3. **Raw role extraction** — navigate the JWT payload to the path specified
   by `roles_claim` (e.g. `cognito:groups`) and read the value as a list of
   role strings. Both JSON arrays and comma-separated strings are accepted.

4. **`allow_raw_roles` filtering** — if `allow_raw_roles` is configured, only
   roles matching at least one glob pattern are passed to subsequent steps.
   Roles unrelated to this application (e.g. from other systems sharing the
   same identity provider) are discarded here. If no roles remain, the
   request is rejected with `403`.

5. **`role_mappings`** — each role is looked up in `role_mappings`. If a
   mapping exists, the display name is used (e.g. `myapp.admin` → `admin`);
   otherwise the raw value passes through as-is.
   !!! note
       Unmapped roles pass through unchanged. If `role_mappings` is omitted
       entirely, raw role values become the effective roles.

6. **Signature verification** — if `signature_verification.enabled` is
   `true`, the JWT signature is verified against the issuer's JWKS endpoint.
   If verification fails, the request is rejected with `403`.

7. **Result** — the mapped roles and user identifier are returned as the
   authenticated `AuthUser`.

### Full configuration reference

```yaml
auth:
  provider: header
  header:
    jwt_header: authorization          # "authorization" → Bearer prefix stripped automatically
    user_claim: email                  # JWT claim for the user's identifier
    roles_claim: "cognito:groups"      # JWT claim for roles; list = nested path
    allow_raw_roles:                   # glob patterns on raw roles_claim values, applied
      - your-app.*                     # before role_mappings; omit to allow all
    signature_verification:
      enabled: true
      issuer: https://your-issuer-url/
      # jwks_url: https://your-jwks-url/   # omit to derive from issuer automatically
      audience: your-audience
    signout_url: https://your-proxy/oauth2/sign_out
  role_mappings:
    your-app.operator: operator
    your-app.admin: admin
  public_paths:                        # optional; default: [] (no paths bypass auth)
    - method: GET                      # see "Public paths" under FastAPI integration
      path: /health
  public_identity:                     # optional; default: none (bypassed requests get no user)
    default_account: public            # see "Public paths" under FastAPI integration
    default_roles: [public]
```

### header.*

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `jwt_header` | string | **Yes** | — | Request header containing the JWT. For `authorization`, the `Bearer` prefix (and the following space) is stripped automatically. For any other header name (e.g. `cf-access-jwt-assertion`), the value is used as-is. |
| `user_claim` | string | **Yes** | — | JWT claim key for the user's identifier. A JWT missing this claim is rejected with `403`. |
| `roles_claim` | string or list of strings | No | `cognito:groups` | JWT claim key for roles. A plain string selects a top-level key; a list of strings selects a nested path (e.g. `["custom", "cognito:groups"]`). The claim value may be a JSON array or a comma-separated string — both are handled. |
| `allow_raw_roles` | list of strings | No | *(allow all)* | Glob patterns (shell-style, using `fnmatch`) applied to each raw value from `roles_claim` **before** `role_mappings`. Values that do not match any pattern are discarded. When omitted or empty, all values are allowed. See [allow_raw_roles](#allow_raw_roles) for details. |
| `signout_url` | string | No | — | URL your application can point a **Sign out** link to. Typically the proxy's sign-out endpoint. |

### header.signature_verification.*

JWT signature verification prevents token forgery: even if an attacker
injects a modified JWT header, it cannot produce a valid signature without
the identity provider's private key.

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `enabled` | boolean | No | `false` | Set `true` to enable JWT signature verification. When `true`, `issuer` and `audience` are required. |
| `issuer` | string | Yes (if enabled) | — | Expected `iss` claim. Also used to derive the JWKS endpoint as `{issuer}/.well-known/jwks.json` when `jwks_url` is not set. |
| `jwks_url` | string | No | *(derived from issuer)* | Explicit JWKS endpoint URL. Use when the identity provider's JWKS endpoint is not at the standard path (e.g. Cloudflare Access: `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`). |
| `audience` | string | Yes (if enabled) | — | Expected `aud` claim in the JWT. |

!!! warning "Token expiry"
    The proxy must refresh tokens before they expire. When using
    oauth2-proxy, set `cookie_refresh` to a value shorter than the identity
    provider's token lifetime (e.g. `cookie_refresh = "50m"` for a
    60-minute token). If the token expires before refresh, requests will be
    rejected with `JWT verification failed: Signature has expired`.

## allow_raw_roles

`allow_raw_roles` is a list of [fnmatch](https://docs.python.org/3/library/fnmatch.html) glob patterns.

| Pattern character | Meaning |
|-------------------|---------|
| `*` | Matches any string of characters (zero or more) |
| `?` | Matches any single character |
| `[seq]` | Matches any character in `seq` |

The patterns are evaluated with **OR** logic — a value is allowed if it
matches **any** pattern in the list.

**Example:**

```yaml
allow_raw_roles:
  - myapp.*
```

| Raw value | Matches? |
|-----------|----------|
| `myapp.admin` | ✓ |
| `myapp.operator` | ✓ |
| `other-app.admin` | ✗ (discarded before role_mappings) |

## role_mappings

Maps raw role values to display names used throughout your application.

```yaml
auth:
  role_mappings:
    your-app.operator: operator
    your-app.admin: admin
```

| Behaviour | Description |
|-----------|-------------|
| Mapped value | The role becomes the mapped name (e.g. `admin`, `operator`). |
| Unmapped value | Passed through as-is (the raw string). |
| No match at all | The request is rejected with `403 Forbidden`. |

## provider: oidc (verify-first)

Unlike `provider: header` (which trusts a JWT injected by a reverse proxy), the
`oidc` provider **verifies the incoming `Authorization: Bearer` token itself**
against the issuer's JWKS (signature, `iss`, `exp`) and can enforce an OAuth2
`scope`. Use it when the application is the resource server that validates tokens
in-app (e.g. machine-to-machine clients, or an API behind API Gateway with no
authorizer).

### Binding the token to this app: `audience` vs `client_id`

A token must be bound to *this* application so a token minted for another
resource/client of the same issuer cannot be replayed. Configure **one** of:

| Field | Verifies | Use when |
|-------|----------|----------|
| `audience` | the `aud` claim | the token carries an `aud` (OIDC **ID tokens**; Keycloak **access tokens** with an audience mapper; Cognito **access tokens with a resource binding**) |
| `client_id` | a client-id claim (default claim name `client_id`) | the token has **no `aud`** and identifies the client another way — notably **Cognito access tokens without a resource binding**, which carry `client_id` |

Rules:

- At least one of `audience` / `client_id` is **required** (fail-closed). Setting
  neither raises a config error.
- They may be combined — if both are set, **both** are verified.
- `allow_any_audience: true` is the explicit, dangerous opt-out of *both* and is
  mutually exclusive with each (it accepts any token from the issuer).
- `token_use` (optional) requires the token's `token_use` claim to equal the
  given value — set it to `access` to reject ID tokens where an access token is
  expected (Cognito).

### Example: Amazon Cognito access token (without resource binding)

A Cognito access token's `aud` is **conditional**: by default (no resource
server / API bound to the app client) it has **no `aud`** and carries
`client_id`, `token_use`, `sub` and `scope`. When you request a **resource
binding** (a Cognito resource server with custom scopes), the resource server
identifier is placed in `aud` instead.

- **If `aud` is present** (resource binding configured) — prefer `audience:` to
  verify it (it identifies the target resource/API). You may additionally set
  `client_id` to also pin the OAuth client.
- **If `aud` is absent** (the default below) — bind by `client_id`. Note that
  `client_id` identifies the OAuth *client*, not the target API, so also setting
  an **API-specific `required_scope`** is recommended so a token minted for a
  different purpose by the same client is still rejected.

```yaml
auth:
  provider: oidc
  oidc:
    issuer: "https://cognito-idp.{region}.amazonaws.com/{user-pool-id}"
    client_id: "{app-client-id}"   # binds the token (no aud without resource binding)
    client_id_claim: client_id     # default; Cognito uses "client_id"
    token_use: access              # reject ID tokens
    principal_claim: sub           # AuthUser.account ← stable per-user id (recommended)
    required_scope: "myapi/write"  # recommended when there is no aud to bind the API
```

`principal_claim: sub` is the generally-safe choice — AWS recommends `sub` as the
stable, immutable user identifier. Use a different claim (e.g. `username`) only
when your application's existing user id is guaranteed to equal it.

For an issuer whose access tokens *do* carry an `aud` (e.g. Keycloak with an
audience mapper, or Cognito with a resource binding), use `audience:` to verify
it — optionally alongside `client_id`.

### Example: Keycloak (audience mapper)

Keycloak can add an `aud` claim to access tokens via an *Audience* protocol
mapper, so the standard `audience` check applies:

```yaml
auth:
  provider: oidc
  oidc:
    issuer: "https://keycloak.example.com/realms/oqtopus"
    audience: "oqtopus-user-api"   # the audience mapper's value
    required_scope: "provider.write"   # optional OAuth2 scope gate (M2M)
    principal_claim: sub
    roles_claim: ["realm_access", "roles"]  # nested claim path (list, not "a.b")
```

`allow_any_audience: true` disables the `aud` check entirely — **dangerous**: it
accepts any token minted by the issuer for any resource. Use it only for issuers
that do not scope tokens per resource, and never on a publicly-exposed endpoint.

### JSON vs HTML error responses

By default the FastAPI middleware renders auth failures as `403` HTML (suited to
a server-rendered app). For a JSON API, pass `response_format="json"` to
`AuthMiddleware`: an authentication failure is then `401` and an authorization
failure `403`, both as `{"detail": ...}`, with a `WWW-Authenticate` challenge
(and `insufficient_scope` for a missing scope).

### Blocking I/O from async code

`verify_bearer_token` performs **blocking** network I/O (JWKS fetch / discovery)
on first use and on key rotation. `OidcProvider` already offloads it via
`asyncio.to_thread`; if you call verification directly from an `async def`
handler, use `verify_bearer_token_async` (or wrap `verify_bearer_token` in
`asyncio.to_thread`) so a slow IdP does not stall the event loop.

### Machine-to-machine clients (`client` extra)

The *caller* side of an `oidc`-protected service obtains a token with the OAuth2
client-credentials grant via `ClientCredentialsTokenProvider` (install the
`client` extra: `pip install "oqtopus-auth[client]"`). It fetches and caches the
token until shortly before it expires. It is synchronous; from async code call
`get_token()` via `asyncio.to_thread`.

```python
from oqtopus_auth.client import ClientCredentialsTokenProvider

tokens = ClientCredentialsTokenProvider(
    token_url="https://keycloak.example.com/realms/oqtopus/protocol/openid-connect/token",
    client_id="oqtopus-engine",
    client_secret="...",
    scope="provider.write",
    # auth_style defaults to "basic" (client_secret_basic); "post" also available.
)
bearer = tokens.get_token()
```

### Custom providers (`register_provider`)

To add a provider beyond `none` / `header` / `oidc`, register a factory with
`register_provider(name, factory)`; `build_provider` (and the FastAPI
middleware) will then accept `provider: <name>`.

## Permissions

`oqtopus_auth.permissions` provides a small role → permission model that is
independent of any provider or web framework:

```python
from oqtopus_auth import AuthUser, Permissions, parse_role_permissions

raw_permissions = {
    "_extends_": {"admin": "operator"},  # admin inherits operator's permissions
    "operator": ["environment.get", "environment.create"],
    "admin": ["app_settings.update"],
}

role_permissions = parse_role_permissions(raw_permissions)
permissions = Permissions(role_permissions)

user = AuthUser(account="a@b.com", roles=["admin"])
permissions.has_permission(user, "environment.get")  # True, inherited from operator
```

Permission strings follow a `<resource>.<action>` or
`<resource>.<sub-resource>.<action>` convention (e.g. `environment.get`,
`environment.config.update`), with `*` as a wildcard granting every
permission for that role.

## FastAPI integration

Install the extra to use `oqtopus_auth.fastapi`:

```shell
pip install "oqtopus-auth[fastapi]"
```

- `AuthMiddleware` runs the configured provider on every request and sets
  `request.state.user`.
- `CurrentUser` (a `Depends`-based type alias) and `get_current_user` read
  that user in route handlers.
- `require_roles(*roles)` / `FastAPIRoles.require(*roles)` enforce
  role-based access control directly from the authenticated user's roles
  (no permission mapping required).
- `FastAPIPermissions(role_permissions).require(permission)` enforces
  permission-based access control built on top of `Permissions`.
- `require_permission(permission)` is a convenience dependency that reads a
  `FastAPIPermissions` instance from `request.app.state.permissions`, useful
  when route modules are imported before that instance is constructed.

```python
from fastapi import FastAPI
from oqtopus_auth import parse_auth_config, parse_role_permissions
from oqtopus_auth.fastapi import AuthMiddleware, FastAPIPermissions

auth_config = parse_auth_config(raw_auth_config)
role_permissions = parse_role_permissions(raw_permissions_config)
permissions = FastAPIPermissions(role_permissions)

app = FastAPI()
app.add_middleware(AuthMiddleware, auth_cfg=auth_config)
app.state.permissions = permissions


@app.get("/settings", dependencies=[permissions.require("app_settings.get")])
def settings() -> dict:
    return {"ok": True}
```

### Public paths (skipping authentication)

Depending on the deployment, some endpoints, such as health checks, may need
to be reachable without authentication. `AuthMiddleware` accepts a
`public_paths` argument, and `AuthConfig` accepts a `public_paths` field
loaded from YAML (optional; defaults to `[]`, i.e. no paths bypass
authentication). Both use the same (method, path-template) matching as real
FastAPI routes, including path parameters and type converters (e.g.
`{device_id}`). A request matching either list skips the provider entirely,
and `request.state.user` is set to `None` (or to a synthetic user, see
`public_identity` below) so `get_current_user` keeps working. `method` has
no default and must always be given explicitly; pass (or write)
`method="*"` to match any HTTP method, but only as a deliberate choice, not
by omission. Matching is on the path *template* only: it cannot authorize
based on a path parameter's *value* (e.g. "only device X is public"), which
belongs in the endpoint itself. Trailing slashes are not normalized either,
so register both `"/health"` and `"/health/"` if both must be public.

`public_paths` and `public_identity` are checked before a provider is
invoked, so they apply the same way regardless of `provider`; they are not
part of `header`'s or any other provider's configuration. Under
`provider: none` they have no practical effect, since every request is
already granted `none.default_account` / `default_roles` unconditionally.

```python
from oqtopus_auth.fastapi import AuthMiddleware, PublicPath

app.add_middleware(
    AuthMiddleware,
    auth_cfg=auth_config,
    public_paths=[PublicPath("GET", "/health")],
)
```

The same paths can be declared in YAML instead of (or in addition to) code;
the two lists are merged:

```yaml
auth:
  provider: header
  header:
    jwt_header: authorization
    user_claim: email
  public_paths:
    - method: GET
      path: /health
    - method: GET
      path: /devices/{device_id}
```

#### Fully public endpoints (no code changes needed)

If the bypassed endpoint has no role/permission dependency at all (a plain
health check, a static icon, `favicon.ico`), `public_paths` alone is
enough; there's no need to add `require_permission(...)` or
`permissions.require(...)` "just in case". As long as `public_identity` is
left unset, `request.state.user` stays `None` for these requests, so there
is no user to check a permission or role against. (If the endpoint *does*
need one to pass, that's what `public_identity` is for, covered next.)

```yaml
auth:
  provider: header
  header:
    jwt_header: authorization
    user_claim: email
  public_paths:
    - method: GET
      path: /health
    - method: GET
      path: /app-icon
    - method: GET
      path: /favicon.ico
  # public_identity omitted, so request.state.user stays None for these paths
```

`public_identity` (below) is only needed for the opposite situation: an
endpoint that already carries a permission/role dependency you don't want
to touch.

#### `public_identity`: giving bypassed requests a role

By default, a request matching `public_paths` gets `request.state.user =
None`. That's fine for an endpoint with no role/permission dependency (see
above), but if the endpoint already has one (e.g.
`dependencies=[permissions.require("metrics.get")]`), the check still runs
and rejects the request with 403, since `None` never satisfies a permission
or role check. Rather than removing that dependency from the endpoint's
code, set `public_identity` so bypassed requests carry a synthetic user
instead:

```yaml
auth:
  provider: header
  header:
    jwt_header: authorization
    user_claim: email
  role_mappings:
    your-app.operator: operator
    your-app.admin: admin
  public_paths:
    - method: GET
      path: /health
    - method: GET
      path: /metrics
  public_identity:
    default_account: public          # optional; defaults to "public"
    default_roles: [public]          # optional; defaults to [] (no synthetic user)
```

```yaml
# permissions config (application-owned, see "Permissions" below)
permissions:
  operator:
    - environment.get
    - environment.create
  admin:
    - app_settings.update
  public:
    - metrics.get                    # only what /metrics needs, nothing else
```

Every request matching `public_paths` now gets the same
`AuthUser(account="public", roles=["public"])`, so `permissions.require
("metrics.get")` passes without any code change to the `/metrics` endpoint.
Grant the `public` role only the permissions its public endpoints actually
need. It behaves like any other role in `permissions:`, so an overly broad
grant is exposed to every unauthenticated caller.

`public_identity` only helps dependencies that consult `role_permissions`
at request time (`FastAPIPermissions.require(...)`, `require_permission
(...)`). A dependency built with `require_roles("admin")` checks for the
literal role name `"admin"` in code, so granting the synthetic user an
`"admin"` role to slip past it would be assuming an identity rather than
being deliberately made public. Prefer `permissions.require(...)` for
anything you intend to expose this way.

`PublicIdentityConfig` mirrors `NoneProviderConfig`'s field names
(`default_account` / `default_roles`) because both describe a synthetic
identity for requests that never go through a real provider. The
difference is scope: `none` applies it to every request in the application,
while `public_identity` applies it only to requests matching `public_paths`.

### Why not standard FastAPI OAuth2 scopes?

FastAPI provides `Security(dep, scopes=[...])` and `SecurityScopes` for
scope-based access control, which integrates with the OpenAPI/Swagger UI. For
the **`header` provider** (the subject of this section), oqtopus-auth
deliberately does not use this pattern, for two reasons:

**Different authorization model.** FastAPI's OAuth2 scopes are designed for
flows where the *client* requests specific scopes at login time (e.g.
`scope=items:read`), and the server verifies the JWT contains those scopes.
oqtopus-auth's `header` provider implements RBAC: the *server* maps
proxy-injected roles to permissions at request time. The client has no role
in choosing scopes.

**Non-standard token injection.** With the `header` provider, tokens are
injected by a trusted reverse proxy (e.g. oauth2-proxy, Cloudflare Access), not
obtained through an OAuth2 token endpoint. FastAPI's `OAuth2PasswordBearer` and
`HTTPBearer` schemes assume a specific flow (token endpoint or
`Authorization: Bearer`) that does not match custom headers such as
`cf-access-jwt-assertion`.

> **Note — the `oidc` provider.** The `oidc` provider *does* accept a standard
> `Authorization: Bearer` token and verifies it directly, and it *does* support
> an OAuth2 `required_scope` (useful for client-credentials / M2M callers that
> carry a `scope` but no roles). It still enforces that scope internally
> (`has_required_scope` / an `InsufficientScopeError`) rather than via FastAPI's
> `Security(scopes=...)`, so the OpenAPI-documentation trade-off below applies to
> both providers.

**Consequence.** Permission enforcement uses
`Depends(require_permission("scope"))` instead of
`Security(dep, scopes=["scope"])`. Applications built on oqtopus-auth work
correctly, but required scopes are not reflected in the OpenAPI
documentation. This trade-off is accepted because these APIs are typically
not intended for direct third-party consumption.

## Example: Amazon Cognito with oauth2-proxy

This example shows a complete setup using Amazon Cognito as the identity
provider and [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) as
the reverse proxy.

### Architecture

```text
Browser → oauth2-proxy → your application (oqtopus-auth)
                ↕
          Amazon Cognito
```

oauth2-proxy authenticates the user against Cognito and forwards requests to
your application with an `Authorization: Bearer <id_token>` header.
oqtopus-auth decodes the JWT to read `email` and `cognito:groups` claims
directly.

### oauth2-proxy configuration (`oauth2-proxy.cfg`)

```cfg
# Provider
provider          = "oidc"
oidc_issuer_url   = "https://cognito-idp.{region}.amazonaws.com/{user-pool-id}"
oidc_groups_claim = "cognito:groups"
scope             = "openid email"
client_id         = "{app-client-id}"
client_secret     = "{app-client-secret}"

# Network
http_address = "127.0.0.1:4180"
redirect_url = "http://127.0.0.1:4180/oauth2/callback"
upstreams    = ["http://localhost:38000"]

# Cookie
cookie_secret  = "{32-byte-random-secret}"
cookie_secure  = false   # true in production (requires HTTPS)
cookie_refresh = "50m"   # must be shorter than Cognito token expiry (default 1h)

# Headers passed to upstream
pass_authorization_header = true   # Authorization: Bearer <id_token> — required for JWT reading

# Access control
email_domains = ["*"]

# UI
skip_provider_button = true
```

Generate `cookie_secret` with the following one-liner:

```shell
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

oauth2-proxy injects the following header into upstream requests:

| Header | Example value | Purpose |
|--------|--------------|---------|
| `authorization` | `Bearer eyJ...` | JWT containing `email` and `cognito:groups` claims |

### Application configuration

```yaml
auth:
  provider: header
  header:
    jwt_header: authorization          # "authorization" → Bearer prefix stripped automatically
    user_claim: email                  # standard JWT claim for email
    roles_claim: "cognito:groups"      # Cognito group membership claim
    allow_raw_roles:
      - myapp.*                        # discard groups from other applications
    signature_verification:
      enabled: true                    # verify the JWT to prevent token forgery
      issuer: "https://cognito-idp.{region}.amazonaws.com/{user-pool-id}"
      audience: "{app-client-id}"
    signout_url: "http://localhost:4180/oauth2/sign_out?rd={cognito-login-url}"
  role_mappings:
    myapp.operator: operator
    myapp.admin: admin
```

### Cognito setup checklist

1. **User Pool** — create a Cognito User Pool.
2. **App client** — create an app client with:
   - OAuth 2.0 grant type: **Authorization code**
   - Scopes: `openid`, `email`
   - Callback URL: `http://localhost:4180/oauth2/callback` (or your production URL)
3. **Groups** — create groups named `myapp.operator` and `myapp.admin` and assign users.
4. **`iss` claim** — the issuer URL is `https://cognito-idp.{region}.amazonaws.com/{user-pool-id}`.
5. **`aud` claim** — the audience is the App client ID.
6. **Token expiry** — the default ID token lifetime is **1 hour**. Set `cookie_refresh = "50m"` in oauth2-proxy to ensure tokens are refreshed before they expire.

## Example: Cloudflare Access + Amazon Cognito

This example uses [Cloudflare Access](https://www.cloudflare.com/products/zero-trust/access/) as the reverse proxy and Amazon Cognito as the OIDC identity provider.

<!-- pyml disable-num-lines 2 no-duplicate-heading,blanks-around-headings -->
<!-- markdownlint-disable-next-line MD024 MD022 -->
### Architecture

```text
Browser → Cloudflare Access → your application (oqtopus-auth)
                ↕
          Amazon Cognito (OIDC)
```

Cloudflare Access authenticates users via Cognito and injects a signed JWT
into every upstream request via the `cf-access-jwt-assertion` header.
oqtopus-auth reads `email` and Cognito group claims directly from this JWT.

### JWT claims structure

Cloudflare Access places OIDC claims forwarded from Cognito under a
`custom` key in the JWT payload:

```json
{
  "iss": "https://{team}.cloudflareaccess.com",
  "aud": ["{application-aud-tag}"],
  "email": "user@example.com",
  "custom": {
    "cognito:groups": ["myapp.admin", "myapp.operator"]
  }
}
```

The JWKS endpoint is at a non-standard path (`/cdn-cgi/access/certs`), so
`jwks_url` must be set explicitly.

### Header injected by Cloudflare Access

| Header | Example value | Purpose |
|--------|--------------|---------|
| `cf-access-jwt-assertion` | `eyJ...` | Cloudflare-signed JWT (raw value, no `Bearer` prefix) |

<!-- pyml disable-num-lines 2 no-duplicate-heading,blanks-around-headings -->
<!-- markdownlint-disable-next-line MD024 MD022 -->
### Application configuration

```yaml
auth:
  provider: header
  header:
    jwt_header: cf-access-jwt-assertion       # raw JWT, no Bearer prefix
    user_claim: email
    roles_claim: ["custom", "cognito:groups"] # Cognito groups nested under "custom"
    allow_raw_roles:
      - myapp.*
    signature_verification:
      enabled: true
      issuer: "https://{team}.cloudflareaccess.com"
      jwks_url: "https://{team}.cloudflareaccess.com/cdn-cgi/access/certs"
      audience: "{application-aud-tag}"       # shown in Cloudflare Zero Trust dashboard
    signout_url: "https://{team}.cloudflareaccess.com/cdn-cgi/access/logout"
  role_mappings:
    myapp.operator: operator
    myapp.admin: admin
```

### Setup checklist

1. **Cognito User Pool** — create groups named `myapp.operator` and `myapp.admin` and assign users.
2. **Cognito App client** — create an app client with:
   - OAuth 2.0 grant type: **Authorization code**
   - Scopes: `openid`, `email`
   - Callback URL: `https://{team}.cloudflareaccess.com/cdn-cgi/access/callback`
3. **Cloudflare Access application** — create a Self-hosted application and add an OIDC identity provider pointing to your Cognito User Pool.
4. **`issuer`** — use your team domain: `https://{team}.cloudflareaccess.com`.
5. **`audience`** — find the AUD tag at: Zero Trust → Access → Applications → *[your app]* → **Application Audience (AUD) Tag**.
6. **`jwks_url`** — Cloudflare Access uses a non-standard JWKS path; set it explicitly to `https://{team}.cloudflareaccess.com/cdn-cgi/access/certs`.
