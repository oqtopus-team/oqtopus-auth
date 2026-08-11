# Getting Started

## Installation

oqtopus-auth requires Python >=3.12.

Install the framework-agnostic core:

```shell
pip install oqtopus-auth
```

If you use the bundled FastAPI middleware and dependencies
(`oqtopus_auth.fastapi`), install the `fastapi` extra:

```shell
pip install "oqtopus-auth[fastapi]"
```

## Core usage (framework-agnostic)

Parse an `AuthConfig` from a raw dict (e.g. loaded from your own YAML file)
and build the configured provider:

```python
from oqtopus_auth import AuthContext, build_provider, parse_auth_config

raw_config = {
    "provider": "none",
    "none": {"default_account": "admin_user", "default_roles": ["admin"]},
}

auth_config = parse_auth_config(raw_config)
provider = build_provider(auth_config)

# Any framework's request headers work, as long as they behave like a
# Mapping[str, str].
context = AuthContext(context={"authorization": "Bearer ..."})
user = await provider.authenticate(context)
```

## FastAPI usage

```python
from fastapi import FastAPI
from oqtopus_auth import parse_auth_config
from oqtopus_auth.fastapi import AuthMiddleware, CurrentUser, require_roles

auth_config = parse_auth_config(raw_config)

app = FastAPI()
app.add_middleware(AuthMiddleware, auth_cfg=auth_config)


@app.get("/me")
def me(user: CurrentUser) -> dict:
    return {"account": user.account if user else None}


@app.get("/admin", dependencies=[require_roles("admin")])
def admin_page() -> dict:
    return {"ok": True}
```

See [Authentication](authentication.md) for the full provider and
configuration reference, permission-based access control, and real-world
reverse-proxy examples (Amazon Cognito, Cloudflare Access).
