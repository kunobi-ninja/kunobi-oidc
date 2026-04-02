# kunobi-oidc

A reusable OIDC authentication library for Kunobi services. Provides browser-based OIDC login with PKCE, token persistence in `~/.config/kunobi/tokens/`, automatic refresh of expired tokens, service discovery via a well-known endpoint, and static token authentication for CI/script environments.

## Usage (library)

```rust
use kunobi_oidc::{AuthClient, ServiceConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Discover auth config from a Kunobi service
    let config = ServiceConfig::discover("https://kobe.kunobi.ninja").await?;

    // Get a valid token (loads cached, refreshes, or opens browser login)
    let client = AuthClient::new(config)?;
    let token = client.token().await?;

    println!("Bearer {}", token);
    Ok(())
}
```

## CLI integration

```rust
use kunobi_oidc::{AuthClient, ServiceConfig};

// Interactive login
let config = ServiceConfig::new(
    "https://kobe.kunobi.ninja",
    "https://auth.kunobi.ninja",
    "your_client_id",
);
let client = AuthClient::new(config)?;
let stored = client.login().await?;  // Opens browser

// Static token (CI / service accounts)
let client = AuthClient::with_static_token("my-api-token".into())?;
let token = client.token().await?;

// Logout (removes cached token)
client.logout()?;
```

## Discovery

The library fetches OIDC configuration from a Kunobi service's well-known endpoint:

```
GET {endpoint}/.well-known/kunobi-auth
```

Expected response:

```json
{
  "issuer": "https://auth.kunobi.ninja",
  "clientId": "cli_abc123",
  "audience": "https://api.kunobi.ninja"
}
```

The `audience` field is optional.

## Token storage

Tokens are persisted to `~/.config/kunobi/tokens/` with `0600` permissions (Unix). Each issuer gets its own file, keyed by a hash of the issuer URL. Tokens are automatically loaded from cache on subsequent calls and refreshed when expired.

## License

Apache-2.0
