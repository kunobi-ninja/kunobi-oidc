# kunobi-auth

[![Crates.io](https://img.shields.io/crates/v/kunobi-auth.svg)](https://crates.io/crates/kunobi-auth)
[![Docs.rs](https://img.shields.io/docsrs/kunobi-auth)](https://docs.rs/kunobi-auth)
[![CI](https://github.com/kunobi-ninja/kunobi-auth/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kunobi-ninja/kunobi-auth/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.94-blue.svg)](Cargo.toml)

Authentication framework for service APIs. Handles the full authn lifecycle — OIDC browser + device login, refresh-token persistence, token revocation/introspection, JWT validation with caching, SSH-key signed requests, DPoP-bound tokens — so your service focuses on authorization.

**Client side** (CLIs, apps, headless agents): browser-based OIDC login with PKCE, RFC 8628 device-authorization grant, automatic refresh-token flow, RFC 7009 revocation, static-token auth, SSH-agent request signing, per-shell session state.

**Server side** (APIs, operators): JWT validation with cached + auto-rotating JWKS, optional per-token validated-claims cache, SSH-signature verification with replay protection, RFC 9449 DPoP proof verifier (sender-constrained tokens), axum tower-layer + extractors integration.

No Kubernetes dependency. Tested end-to-end against [Dex](https://dexidp.io/) v2.41 in CI; should work with any OIDC Core 1.0–compliant provider (Auth0, Keycloak, Okta, Google) but those are not currently exercised by the test suite.

## Features

| Feature  | Default | Includes                                                                                                                                                                                                                          |
| -------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `client` | yes     | OIDC browser login (PKCE), device-authorization grant, refresh-token flow, token introspection + revocation, static-token, SSH-agent signing, TOFU audience pinning, per-shell session state                                      |
| `server` | yes     | JWT/JWKS validation (RS/PS/ES/EdDSA + auto-rotating cache), opt-in per-token validation cache, DPoP proof verifier (RFC 9449), SSH-signature verification with atomic-replay-protected nonce tracker, `AuthLayer` + axum extractors |

```toml
# Server only (no browser deps)
kunobi-auth = { git = "https://github.com/kunobi-ninja/kunobi-auth", tag = "v0.3.0", default-features = false, features = ["server"] }

# Client only
kunobi-auth = { git = "https://github.com/kunobi-ninja/kunobi-auth", tag = "v0.3.0", default-features = false, features = ["client"] }
```

> The crate is not (yet) on crates.io. Pin via git tag — see the [latest release](https://github.com/kunobi-ninja/kunobi-auth/releases) for stable refs.

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

### Device authorization grant (headless agents, CI workers, K8s operators)

For principals with no browser. The user completes the auth on a separate device by visiting a URL and entering a short code; the headless process polls the IdP for tokens (RFC 8628).

```rust
use kunobi_auth::client::AuthClient;

let client = AuthClient::new(config)?;
let token = client.device_login(
    "openid email offline_access",
    |prompt| {
        // Display however you want -- stdout, log, kubectl event, …
        println!("Visit {} and enter code {}", prompt.verification_uri, prompt.user_code);
    },
).await?;
```

`AuthClient::begin_device_login(scope)` returns a raw `DeviceFlowHandle` if you want full control over the prompt/poll loop. Polling honours RFC 8628 §3.5: retries on `authorization_pending`, backs off on `slow_down`, surfaces `expired_token` and `access_denied` immediately.

### Static token (CI / scripts)

```rust
let client = AuthClient::with_static_token("my-api-token".into())?;
let token = client.token().await?;
```

### Logout with revocation, introspection

```rust
// Best-effort RFC 7009 revocation at the IdP + remove the local file.
// A network failure does not block local cleanup; it is logged.
client.logout_async().await?;

// "Is this token still valid right now?" via RFC 7662 introspection.
// Useful for opaque (non-JWT) tokens or to bypass any local validation cache.
let result = client.introspect().await?;
if !result.active { /* revoked or expired at IdP */ }
```

The synchronous `logout()` (local-only) stays for callers that don't want network on the logout path. Returns an error when the IdP doesn't advertise `revocation_endpoint` (Dex ≤ 2.41 does not implement RFC 7009; Keycloak/Okta/Auth0 do).

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

### Configured auth builder

For the common case, configure accepted providers once and use the returned
`ConfiguredAuth` as your axum state. Provider names are labels only; Firebase,
Clerk, Auth0, Keycloak, Okta, etc. all use the same generic JWT/OIDC path.

```rust
use kunobi_auth::server::{AuthBuilder, RequiredAuth};
use axum::{routing::get, Router};
use std::time::Duration;

async fn me(RequiredAuth(identity): RequiredAuth) -> String {
    format!("Hello, {}", identity.identity)
}

let auth = AuthBuilder::new()
    .oidc(
        "firebase",
        "https://securetoken.google.com/my-project",
        "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
        vec!["my-project".into()],
    )
    .validation_cache(Duration::from_secs(30))
    .build();

let app = Router::new()
    .route("/me", get(me))
    .with_state(auth);
```

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

### Tower `AuthLayer` (composable middleware)

If you'd rather not put auth into every handler signature or thread the state through `with_state(...)`, use `AuthLayer`:

```rust
use kunobi_auth::server::AuthLayer;
use kunobi_auth::AuthIdentity;
use axum::{routing::get, Router, Extension};

async fn me(Extension(id): Extension<AuthIdentity>) -> String {
    format!("Hello, {}", id.identity)
}

let app = Router::new()
    .route("/me", get(me))
    .layer(AuthLayer::required(my_provider));   // 401 on missing/bad
    // .layer(AuthLayer::optional(my_provider)) // pass through on missing; 401 on bad
```

The layer extracts the bearer token, runs `AuthnProvider::authenticate`, inserts the resulting `AuthIdentity` into request extensions on success, and returns a 401 / `AuthError` response on failure without invoking the handler.

### Per-token validation cache (high-throughput services)

Every authenticated request runs a fresh signature verify by default. For services on the order of thousands of req/s with a small population of long-lived tokens, opt in to a TTL'd cache keyed by `SHA-256(token + validation context)`:

```rust
let jwks = JwksManager::new()
    .with_validation_cache(std::time::Duration::from_secs(30));
```

Cache hit = no signature verify, no audience/issuer parse, no JWKS lookup. Per-entry lifetime is `min(token.exp, ttl)`; cap is 4096 entries with oldest-by-`valid_until` eviction.

**Trade-off:** a token revoked at the IdP stays accepted by the validator for up to `ttl` after revocation. Pair with periodic `oidc::introspect` calls if you need instant revocation, or leave the cache off.

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

### DPoP proof verification (RFC 9449)

DPoP turns bearer access tokens into **sender-constrained** tokens: the access token carries a `cnf.jkt` confirmation claim that binds it to a client keypair, and the client signs a fresh per-request proof with that key. A leaked access token alone is useless without the matching private key.

```rust
use kunobi_auth::server::{verify_dpop_proof, cnf_jkt, JwksManager};
use std::time::Duration;

// 1. Validate the access token (existing path).
let claims = jwks.validate_jwt(access_token, jwks_url, issuer, &aud, &algs).await?;

// 2. Extract its DPoP binding (None = not DPoP-bound).
let bound_jkt = cnf_jkt(&claims);

// 3. Verify the DPoP proof from the `DPoP:` header.
let proof = verify_dpop_proof(
    dpop_header,
    request.method().as_str(),
    &full_request_url,
    Some(access_token),     // ath binding
    bound_jkt.as_deref(),   // jkt binding
    Duration::from_secs(60),
)?;

// 4. Track proof.jti via NonceTracker to defeat proof replay.
if nonces.check_and_insert(&proof.jti).await {
    return Err(AuthError::Unauthorized("dpop replay".into()));
}
```

Only ES256 (P-256) keys are accepted — the MUST-implement algorithm in RFC 9449 §3.1. Helpers exposed: ``verify_dpop_proof``, ``ath_for(token)`` (proof-side access-token hash), ``jkt_thumbprint(jwk)`` (RFC 7638), ``cnf_jkt(claims)`` (extract `cnf.jkt` from a validated claims map).

**Server-side only in this release.** Client-side DPoP (per-client keypair management + proof signing) is a follow-up.

## Discovery

Clients fetch auth configuration from `GET {endpoint}/v1/status`:

```json
{
  "version": "0.3.0",
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
mise install   # provisions Rust + cargo-audit + cargo-mutants
```

CI uses the same `.mise.toml` so local and CI runs match.

### Coverage

The crate uses [`cargo-tarpaulin`](https://github.com/xd009642/tarpaulin)
for Rust coverage. CI runs the same command with a conservative initial
`50%` line-coverage floor and uploads `coverage/tarpaulin-report.json`
as a workflow artifact.

```sh
cargo install cargo-tarpaulin --locked --version 0.35.4
mise run coverage       # JSON report in ./coverage
mise run coverage:html  # HTML report in ./coverage
```

On macOS, installing Tarpaulin may require `pkg-config`/OpenSSL
development headers (for example, `brew install pkgconf openssl`).

Coverage is a trend signal, not a security proof. For auth-critical
boundaries, prefer adding focused tests and pinning them with mutation
testing where practical.

### Mutation testing

The crate uses [`cargo-mutants`](https://mutants.rs/) to surface tests
that "pass" because their assertion is too loose to notice production
code lying — the canonical example is a comparison operator (`<` vs
`<=`) at a security boundary that no test pins precisely.

```sh
mise run mutants                              # full crate
mise run mutants:file -- src/server/jwks.rs   # one file
```

**Current scope:** the four security-boundary predicates extracted as
pure functions (`cache_entry_is_fresh`, `nonce_is_within_window`,
`jwks_cache_should_be_used`, `strip_surrounding_quotes`) are pinned at
49/49 viable mutants caught. The rest of the crate has not been
mutation-audited end-to-end; an initial run flagged surviving mutants
across `client/oidc.rs`, `client/ssh.rs`, and others — those are known
test gaps and not yet closed.

**Pattern when a mutant survives:** extract the offending comparison
into a small pure predicate, then unit-test all sides of its boundary.
The three predicates above are the templates.

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
