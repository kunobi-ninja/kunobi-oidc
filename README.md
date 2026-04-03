# kunobi-auth

Authentication framework for service APIs. Handles the full authn lifecycle — OIDC browser login, JWT validation, token management — so your service focuses on authorization.

**Client side** (CLIs, apps): browser-based OIDC login with PKCE, static token auth, credential persistence with auto-refresh.

**Server side** (APIs, operators): JWT validation with cached JWKS, audit logging, structured error responses.

No Kubernetes dependency. Works with any OIDC provider (Clerk, Auth0, Keycloak, Dex, Google).

## Client usage

```rust
use kunobi_auth::client::{AuthClient, ServiceConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Discover auth config from the service
    let config = ServiceConfig::discover("https://kobe.kunobi.ninja").await?;

    // Get a valid token (loads cached, refreshes, or opens browser login)
    let client = AuthClient::new(config)?;
    let token = client.token().await?;

    println!("Bearer {token}");
    Ok(())
}
```

### Interactive login

```rust
let client = AuthClient::new(config)?;
client.login().await?;   // Opens browser, stores token
```

### Static token (CI / scripts)

```rust
let client = AuthClient::with_static_token("my-api-token".into())?;
let token = client.token().await?;
```

## Server usage

```rust
use kunobi_auth::server::JwksManager;
use kunobi_auth::AuthIdentity;

let jwks = JwksManager::new();

// Validate a JWT from a request
let claims = jwks.validate_jwt(
    &token,
    "https://auth.kunobi.ninja/.well-known/jwks.json",
    &["https://api.kunobi.ninja"],
    &["RS256"],
).await?;

// Build identity — claims pass through for downstream authz
let identity = AuthIdentity {
    provider: "my-oidc-provider".into(),
    identity: claims["sub"].as_str().unwrap_or_default().into(),
    method: "oidc".into(),
    claims,
};
```

## Discovery

The client fetches auth configuration from `GET {endpoint}/v1/status`:

```json
{
  "version": "0.4.0",
  "auth": {
    "methods": [
      { "type": "oidc", "issuer": "https://auth.kunobi.ninja", "clientId": "cli" },
      { "type": "token" }
    ],
    "sessions": []
  }
}
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `client` | Yes | OIDC browser login, token storage, discovery |
| `server` | Yes | JWT validation, JWKS caching, audit logging |

```toml
# Server only (no browser deps)
kunobi-auth = { version = "0.2", default-features = false, features = ["server"] }

# Client only
kunobi-auth = { version = "0.2", default-features = false, features = ["client"] }
```

## Token storage

Tokens are persisted to `~/.config/kunobi/tokens/` with `0600` permissions. Each issuer gets its own file. Tokens are automatically loaded from cache and refreshed when expired.

## Design

**AuthN only.** This crate answers "who is this person and what claims do they have?" Authorization decisions (what they can access) are left to the consuming service. Claims flow through untouched — the service interprets them.

## License

Apache-2.0
