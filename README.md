# kunobi-auth

Authentication framework for service APIs. Handles the full authn lifecycle — OIDC browser login, refresh-token persistence, JWT validation, SSH-key signed requests — so your service focuses on authorization.

**Client side** (CLIs, apps): browser-based OIDC login with PKCE, automatic refresh-token flow, static-token auth, SSH-agent request signing.

**Server side** (APIs, operators): JWT validation with cached + auto-rotating JWKS, SSH-signature verification with replay protection, axum extractors for `RequiredAuth` / `OptionalAuth`.

No Kubernetes dependency. Works with any OIDC provider (Auth0, Keycloak, Dex, Okta, Google).

## Features

| Feature  | Default | Description                                                  |
| -------- | ------- | ------------------------------------------------------------ |
| `client` | yes     | OIDC browser login, refresh, token storage, SSH-agent signing |
| `server` | yes     | JWT/JWKS validation, SSH-signature verification, axum extractors |

```toml
# Server only (no browser deps)
kunobi-auth = { version = "0.2", default-features = false, features = ["server"] }

# Client only
kunobi-auth = { version = "0.2", default-features = false, features = ["client"] }
```

## Client usage

### OIDC (recommended for human users)

```rust
use kunobi_auth::client::{AuthClient, ServiceConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Discover auth config from the service.
    let config = ServiceConfig::discover("https://kobe.kunobi.ninja").await?;

    // token() = cached → refresh-token grant if expired → browser login if no
    // refresh token. The ID token is validated against the provider's JWKS
    // before being persisted (signature, exp, aud, iss, nonce).
    let client = AuthClient::new(config)?;
    let token = client.token().await?;

    println!("Bearer {token}");
    Ok(())
}
```

`AuthClient::login()` forces an interactive browser login regardless of cached state. `AuthClient::logout()` removes the persisted token.

### Static token (CI / scripts)

```rust
let client = AuthClient::with_static_token("my-api-token".into())?;
let token = client.token().await?;
```

### SSH-key signed requests (recommended for service-to-service)

Signs each request with an Ed25519 key (via `ssh-agent` if available, else `~/.ssh/id_ed25519`). The server verifies the signature without ever seeing a bearer token. Replay-safe: each request has a fresh nonce + timestamp drift check.

```rust
use kunobi_auth::client::AuthClient;

let client = AuthClient::with_ssh(None)?;  // or Some(fingerprint) to pin a key

// Builds an `Authorization: SSH-Signature ...` header value bound to the
// HTTP method, path, and body.
let header = client
    .authorize("my-service-ns", "POST", "/api/v1/action", b"request body")
    .await?;
```

The header format is:

```
SSH-Signature fingerprint="SHA256:…",timestamp="…",nonce="…",signature="<b64-SSHSIG>"
```

### Trust-on-first-use audience pinning

For SSH-auth clients that need to detect IdP/audience swaps:

```rust
use kunobi_auth::client::{TofuStore, TofuResult};

let tofu = TofuStore::new()?;
match tofu.verify("https://api.example.com", "api://example")? {
    TofuResult::FirstConnect { endpoint, audience } => {
        // Prompt user, then:
        tofu.trust(&endpoint, &audience)?;
    }
    TofuResult::Trusted => {} // OK
    TofuResult::AudienceChanged { previous, current, .. } => {
        anyhow::bail!("audience changed from {previous} to {current} -- possible MITM");
    }
}
```

## Server usage

### Axum extractors (recommended)

Implement `AuthnProvider` on your application state once, then use `RequiredAuth` / `OptionalAuth` as request extractors anywhere:

```rust
use kunobi_auth::server::{AuthnProvider, JwksManager, RequiredAuth};
use kunobi_auth::{AuthError, AuthIdentity};
use axum::{routing::get, Router};
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    jwks: Arc<JwksManager>,
    issuer: String,
    jwks_url: String,
    audience: Vec<String>,
}

impl AuthnProvider for AppState {
    async fn authenticate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
        let claims = self.jwks
            .validate_jwt(
                token,
                &self.jwks_url,
                &self.issuer,
                &self.audience,
                &["RS256".to_string()],
            )
            .await
            .map_err(|e| AuthError::Unauthorized(e.to_string()))?;

        Ok(AuthIdentity {
            provider: "oidc".into(),
            identity: claims["sub"].as_str().unwrap_or_default().into(),
            method: "jwt".into(),
            claims,
        })
    }
}

async fn me(RequiredAuth(identity): RequiredAuth) -> String {
    format!("Hello, {}", identity.identity)
}

fn build(state: AppState) -> Router {
    Router::new().route("/me", get(me)).with_state(state)
}
```

`OptionalAuth(Option<AuthIdentity>)` is the same idea but returns `None` for missing/malformed `Authorization` headers (still 401s for an actively-bad token).

### Direct JWT validation (low-level)

```rust
use kunobi_auth::server::JwksManager;

let jwks = JwksManager::new();
let claims = jwks.validate_jwt(
    token,
    "https://auth.kunobi.ninja/.well-known/jwks.json",
    "https://auth.kunobi.ninja",                       // issuer (required)
    &["https://api.kunobi.ninja".to_string()],         // audience (required, non-empty)
    &["RS256".to_string()],
).await?;
```

Both `issuer` and `audience` are required and must be non-empty — passing empty values returns an error rather than silently disabling validation. The JWKS cache auto-refetches on `kid` rotation (rate-limited 30s cooldown).

Supported algorithms: RS256/384/512, PS256/384/512, ES256/384, EdDSA (incl. OKP/Ed25519 JWKs).

### SSH-signature verification

```rust
use kunobi_auth::server::ssh::{
    parse_ssh_auth_header, parse_authorized_key,
    verify_ssh_signature, NonceTracker, CompiledSshProvider,
};
use std::collections::HashSet;
use std::time::Duration;

let key = parse_authorized_key(
    "ssh-ed25519 AAAA… alice@example.com"
)?;
let provider = CompiledSshProvider {
    name: "internal-services".into(),
    keys: vec![key],
    revoked_fingerprints: HashSet::new(),
    identity_template: "ssh:{comment}".into(),  // {fingerprint}, {comment}
};

let nonces = NonceTracker::new(Duration::from_secs(300));

let header = parse_ssh_auth_header(header_str)?;
if nonces.check_and_insert(&header.nonce).await {
    return Err(AuthError::Unauthorized("replay".into()));
}

let identity = verify_ssh_signature(
    &header,
    "my-service-ns",
    "POST",
    "/api/v1/action",
    body,
    std::slice::from_ref(&provider),
    Duration::from_secs(300),  // max clock drift
)?;
```

`NonceTracker::check_and_insert` is atomic under contention; concurrent requests with the same nonce can't both pass. Fingerprints in error responses are redacted (`SHA256:01234567…`); full fingerprints stay in `tracing::warn!` logs for forensics.

## Discovery

Clients fetch auth configuration from `GET {endpoint}/v1/status`:

```json
{
  "version": "0.2.0",
  "auth": {
    "methods": [
      { "type": "oidc", "issuer": "https://auth.kunobi.ninja", "clientId": "cli" },
      { "type": "token" }
    ],
    "sessions": []
  }
}
```

## Token storage

OIDC tokens are persisted to `~/.config/kunobi/tokens/`, one file per issuer (filename is a hash of the issuer URL). The directory is `0o700`; each token file is `0o600`. Writes are atomic — a temp file in the same directory is `fsync`'d, then renamed over the destination, so a partial write is never observable. The TOFU store at `~/.config/kunobi/known_services.json` follows the same scheme.

Refresh-token flow: when a cached ID token is past its expiry (with a 60s buffer), `AuthClient::token()` exchanges the refresh token for a fresh ID token without prompting. Only if refresh fails (or no refresh token was issued) does it fall back to interactive login. Request `offline_access` scope from your IdP to ensure refresh tokens are issued.

## Development

Toolchain is pinned via [`mise`](https://mise.jdx.dev). One-time setup:

```sh
mise install   # provisions Rust + cargo-audit + cargo-mutants from .mise.toml
```

CI uses the same `.mise.toml` so local and CI runs match.

### Mutation testing

The crate is checked with [`cargo-mutants`](https://mutants.rs/). Mutation
testing reveals tests that "pass" because the assertion is too loose to
notice when the production code's behaviour changes — the canonical
example is a comparison operator (`<` vs `<=`) at a security boundary
that no test pins precisely.

```sh
mise run mutants               # full run (5–10 min on this crate)
mise run mutants:fast -- src/server/jwks.rs   # one file
```

A surviving mutant means a test gap. The pattern in this codebase: extract
the predicate into a small pure function and unit-test all sides of its
boundary. See `cache_entry_is_fresh`, `nonce_is_within_window`, and
`jwks_cache_should_be_used` for examples.

Mutation testing is **not** run in CI (a full pass takes too long for
per-PR gating). Run it locally before non-trivial changes to the
validation, replay-protection, or parser paths.

### Property-based testing

`tests/proptest_parsers.rs` and `tests/proptest_jwt.rs` use
[`proptest`](https://proptest-rs.github.io/proptest/) to assert
**invariants over arbitrary inputs**. The flagship invariant is "this
parser never panics" — a single reachable panic in a function that runs
on attacker-controlled bytes (SSH-Signature header, DPoP proof, JWT)
is a remote-pre-auth DoS. `proptest_jwt.rs` spins up a real HTTP-served
JWKS endpoint via axum and validates random `JwksManager::validate_jwt`
invocations against signed tokens with arbitrary claims — covering
audience/issuer mismatch, signature tampering, and validation-cache
roundtrip.

```sh
cargo test --test proptest_parsers --all-features    # parsers
cargo test --test proptest_jwt --all-features        # full validate_jwt path
PROPTEST_CASES=10000 cargo test --test proptest_jwt  # deeper run
```

Properties run as part of `cargo test --all-features` by default.

### Fuzzing

The crate is also set up for coverage-guided fuzzing via
[`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html). Fuzz
targets live in `fuzz/fuzz_targets/`:

- `parse_ssh_auth_header` — SSH-Signature header parser
- `split_header_params` — quoted-comma-aware splitter
- `parse_authorized_key` — OpenSSH authorized_keys decoder
- `verify_dpop_proof` — DPoP JWT proof verifier

Each is the same "never panic on arbitrary input" invariant as the
proptest properties, but with libFuzzer-style coverage-guided
mutation — finds inputs proptest's random generator can't.

```sh
cd fuzz
cargo +nightly fuzz run parse_ssh_auth_header        # runs until Ctrl-C
cargo +nightly fuzz run verify_dpop_proof -- -max_total_time=300
```

Fuzzing requires nightly Rust (`cargo-fuzz` uses libFuzzer instrumentation
that's only on nightly). It is **not** run in CI — useful as a
nightly/weekly job on a dedicated host once the crate is in production.

## Testing

Unit tests:

```sh
cargo test --all-features
```

End-to-end tests against a real OIDC provider (Dex) live in `tests/e2e_dex.rs` and are gated with `#[ignore]`. Locally:

```sh
docker build -t kunobi-dex tests/fixtures -f tests/fixtures/Dockerfile.dex
docker run --rm -d --name kunobi-dex -p 5556:5556 kunobi-dex
DEX_ISSUER=http://127.0.0.1:5556/dex \
  cargo test --test e2e_dex -- --ignored --test-threads=1
```

The tests share one Dex instance and refresh-token rotation is on, so `--test-threads=1` is required.

## Design

**AuthN only.** This crate answers "who is this person and what claims do they have?" Authorization decisions (what they can access) are left to the consuming service. Claims flow through untouched — the service interprets them.

**Public clients (PKCE) by default.** No client_secret persistence; CLI flows use PKCE per RFC 7636. SSH-signature auth is the recommended path for non-interactive service-to-service calls.

## License

Apache-2.0
