//! End-to-end tests against a real Dex instance.
//!
//! These tests require a running Dex configured per
//! `tests/fixtures/dex-config.yaml`. They are gated with `#[ignore]` so
//! `cargo test` does not attempt to run them by default.
//!
//! Run locally:
//!   docker build -t kunobi-dex tests/fixtures -f tests/fixtures/Dockerfile.dex
//!   docker run --rm -d --name kunobi-dex -p 5556:5556 kunobi-dex
//!   DEX_ISSUER=http://127.0.0.1:5556/dex \
//!     cargo test --test e2e_dex -- --ignored --nocapture --test-threads=1
//!
//! Tests share a single Dex instance + user; refresh-token rotation makes
//! parallel runs flake. Always pass `--test-threads=1`.
//!
//! Run in CI: see `.github/workflows/ci.yml` (`e2e` job).

#![cfg(feature = "client")]

use kunobi_auth::server::JwksManager;
use serde::Deserialize;

const CLIENT_ID: &str = "kunobi-test";
const TEST_USER: &str = "test@example.com";
const TEST_PASS: &str = "password";

fn issuer() -> String {
    std::env::var("DEX_ISSUER").expect("DEX_ISSUER must be set (e.g. http://127.0.0.1:5556/dex)")
}

fn jwks_url() -> String {
    format!("{}/keys", issuer())
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
    refresh_token: String,
    #[allow(dead_code)]
    access_token: String,
}

/// Fetch tokens via the password grant. Bypasses the browser; protocol
/// internals (signing, claims, refresh) are identical to the auth-code flow.
async fn password_grant() -> TokenResponse {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/token", issuer()))
        .form(&[
            ("grant_type", "password"),
            ("username", TEST_USER),
            ("password", TEST_PASS),
            ("client_id", CLIENT_ID),
            ("scope", "openid email profile offline_access"),
        ])
        .send()
        .await
        .expect("Dex /token request failed -- is Dex running?");
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "password grant failed ({status}): {text}"
    );
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("bad token JSON: {e} -- {text}"))
}

/// With the validation cache enabled, a second `validate_jwt` for the
/// same token must return identical claims even after the JWKS cache
/// would have been wiped (we point a freshly-zeroed manager at a bogus
/// JWKS URL between calls). Proves the cache hit short-circuits the
/// network/crypto path entirely.
#[tokio::test]
#[ignore]
async fn validation_cache_skips_jwks_lookup_on_hit() {
    let tokens = password_grant().await;

    let mgr = JwksManager::new().with_validation_cache(std::time::Duration::from_secs(60));

    let claims_a = mgr
        .validate_jwt(
            &tokens.id_token,
            &jwks_url(),
            &issuer(),
            &[CLIENT_ID.to_string()],
            &["RS256".to_string()],
        )
        .await
        .expect("first validation should succeed");

    // Second call points at a deliberately-broken JWKS URL. If the cache
    // didn't short-circuit, we'd hit it and fail.
    let claims_b = mgr
        .validate_jwt(
            &tokens.id_token,
            "http://127.0.0.1:1/does-not-exist",
            &issuer(),
            &[CLIENT_ID.to_string()],
            &["RS256".to_string()],
        )
        .await
        .expect("cached validation should not hit the network");

    assert_eq!(claims_a, claims_b);
}

#[tokio::test]
#[ignore]
async fn validate_real_dex_id_token() {
    let tokens = password_grant().await;
    let mgr = JwksManager::new();

    let claims = mgr
        .validate_jwt(
            &tokens.id_token,
            &jwks_url(),
            &issuer(),
            &[CLIENT_ID.to_string()],
            &["RS256".to_string()],
        )
        .await
        .expect("Dex-issued ID token failed validation");

    assert_eq!(claims["email"], TEST_USER);
    assert_eq!(claims["aud"], CLIENT_ID);
    assert_eq!(claims["iss"], issuer());
}

#[tokio::test]
#[ignore]
async fn rejects_wrong_audience_against_real_dex() {
    let tokens = password_grant().await;
    let mgr = JwksManager::new();

    let err = mgr
        .validate_jwt(
            &tokens.id_token,
            &jwks_url(),
            &issuer(),
            &["wrong-audience".to_string()],
            &["RS256".to_string()],
        )
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("validation") || msg.contains("InvalidAudience") || msg.contains("aud"),
        "expected aud-mismatch error, got: {msg}"
    );
}

#[tokio::test]
#[ignore]
async fn rejects_wrong_issuer_against_real_dex() {
    let tokens = password_grant().await;
    let mgr = JwksManager::new();

    let err = mgr
        .validate_jwt(
            &tokens.id_token,
            &jwks_url(),
            "https://evil.example.com",
            &[CLIENT_ID.to_string()],
            &["RS256".to_string()],
        )
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("validation") || msg.contains("Issuer") || msg.contains("iss"),
        "expected iss-mismatch error, got: {msg}"
    );
}

#[tokio::test]
#[ignore]
async fn refresh_token_roundtrip_real_dex() {
    let initial = password_grant().await;

    let refreshed = kunobi_auth::client::oidc::refresh(
        &issuer(),
        CLIENT_ID,
        "http://localhost:8329/callback",
        &initial.refresh_token,
    )
    .await
    .expect("refresh against real Dex failed");

    assert_ne!(
        refreshed.id_token, initial.id_token,
        "refresh should issue a new ID token"
    );
    assert!(
        refreshed.expires_at.is_some(),
        "refresh response should carry expires_in"
    );

    // The refreshed ID token should validate against the same JWKS.
    let mgr = JwksManager::new();
    mgr.validate_jwt(
        &refreshed.id_token,
        &jwks_url(),
        &issuer(),
        &[CLIENT_ID.to_string()],
        &["RS256".to_string()],
    )
    .await
    .expect("refreshed ID token failed validation");
}

/// Dex's `expiry.signingKeys` is set to 10s in our test config. After
/// rotation, a new token's `kid` will not be in the cached JWKS; the
/// `KID_MISS_REFRESH_COOLDOWN` path should refetch and validate.
///
/// We sleep > KID_MISS_REFRESH_COOLDOWN (30s) so the manager is allowed to
/// refetch on the kid miss. A shorter sleep would let the cache short-
/// circuit -- DoS protection working as designed, but not what this test
/// is exercising.
#[tokio::test]
#[ignore]
async fn jwks_kid_rotation_real_dex() {
    let mgr = JwksManager::new();

    // Token A, validated -- populates the JWKS cache.
    let a = password_grant().await;
    mgr.validate_jwt(
        &a.id_token,
        &jwks_url(),
        &issuer(),
        &[CLIENT_ID.to_string()],
        &["RS256".to_string()],
    )
    .await
    .expect("token A should validate");

    // Wait past both Dex's 10s signing-key rotation AND the manager's 30s
    // KID_MISS_REFRESH_COOLDOWN.
    tokio::time::sleep(std::time::Duration::from_secs(35)).await;

    // Token B is signed with a freshly-rotated key. The cached JWKS doesn't
    // contain its kid yet; our manager should refetch and still validate.
    let b = password_grant().await;
    mgr.validate_jwt(
        &b.id_token,
        &jwks_url(),
        &issuer(),
        &[CLIENT_ID.to_string()],
        &["RS256".to_string()],
    )
    .await
    .expect("token B (post-rotation) should validate after JWKS refetch");
}
