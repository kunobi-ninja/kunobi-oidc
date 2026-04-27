//! Property-based tests for the full `JwksManager::validate_jwt` path.
//!
//! `tests/proptest_parsers.rs` covers the **parsers** (no-panic invariants
//! over arbitrary bytes). This file goes one layer deeper: it spins up a
//! real HTTP-served JWKS endpoint, signs JWTs with a known keypair, and
//! asserts validation properties for arbitrary *valid* and *adversarial*
//! claim combinations.
//!
//! Pattern:
//!   1. `TestIdp::start()` — axum server on localhost:0, exposes a JWKS
//!      that contains our test public key.
//!   2. `idp.issue(claims)` — signs a JWT with the test private key.
//!   3. Properties: validate, mutate one piece (claim/signature), assert
//!      the expected outcome.
//!
//! Run with `cargo test --test proptest_jwt --all-features`.

use axum::Router;
use axum::routing::get;
use jsonwebtoken::{EncodingKey, Header};
use kunobi_auth::server::JwksManager;
use proptest::prelude::*;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::oneshot;

// ─────────────────────────────────────────────────────────────────────────────
// Test IdP: serves a JWKS containing our well-known public key, lets us
// mint signed JWTs with arbitrary claims for testing.
// ─────────────────────────────────────────────────────────────────────────────

const TEST_KID: &str = "kunobi-test-key-1";
const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjCZ3enwwbi1sTMaE
CIAe12xZratKWzRoekhOUBIDCZChRANCAAQitjpgInyqDv9dQ4D0FZ4SiZX+KaqP
4uS/qxtTQoPfLryamFKS8SYa/uu0hcS+ASwxyTxsMBNuMpdBBC+mLBOO
-----END PRIVATE KEY-----
";
const TEST_X: &str = "IrY6YCJ8qg7_XUOA9BWeEomV_imqj-Lkv6sbU0KD3y4";
const TEST_Y: &str = "vJqYUpLxJhr-67SFxL4BLDHJPGwwE24yl0EEL6YsE44";

/// Spawned JWKS server. Lives for the whole test process so we don't spin
/// it up per-property -- 256 spins per property would be wasteful.
struct TestIdp {
    addr: SocketAddr,
}

impl TestIdp {
    fn issuer(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn jwks_url(&self) -> String {
        format!("http://{}/jwks.json", self.addr)
    }

    /// Sign a JWT with the test private key. Caller supplies the full
    /// claims object.
    fn issue(&self, claims: &serde_json::Value) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(TEST_KID.into());
        let key = EncodingKey::from_ec_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }
}

async fn jwks_handler() -> axum::Json<serde_json::Value> {
    axum::Json(json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "kid": TEST_KID,
            "alg": "ES256",
            "use": "sig",
            "x": TEST_X,
            "y": TEST_Y,
        }]
    }))
}

/// Lazy, process-lifetime singleton: starts the server once on first call,
/// returns the same `TestIdp` thereafter.
fn test_idp() -> &'static TestIdp {
    static INSTANCE: OnceLock<TestIdp> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let (tx, rx) = oneshot::channel();
        // Spawn on a dedicated tokio runtime that lives in its own thread;
        // we can't rely on the test's runtime because proptest runs each
        // case in a fresh runtime context.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let app = Router::new().route("/jwks.json", get(jwks_handler));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(addr).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        let addr = rx.blocking_recv().unwrap();
        TestIdp { addr }
    })
}

// Helper: blocking validate_jwt call from inside a synchronous proptest body.
fn validate_blocking(
    mgr: &JwksManager,
    token: &str,
    issuer: &str,
    audience: &[String],
) -> anyhow::Result<std::collections::HashMap<String, serde_json::Value>> {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let rt = RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap());
    rt.block_on(mgr.validate_jwt(
        token,
        &test_idp().jwks_url(),
        issuer,
        audience,
        &["ES256".to_string()],
    ))
}

fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

// ─────────────────────────────────────────────────────────────────────────────
// Properties
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Any well-formed token (issued by the test IdP, with `aud`/`iss`/`exp`
    /// chosen by proptest within sensible bounds) MUST validate.
    #[test]
    fn well_formed_token_validates(
        sub in "[a-zA-Z0-9_-]{1,32}",
        aud in "[a-zA-Z0-9_:.-]{1,64}",
        ttl_secs in 60i64..3600i64,
        extra_claim_key in "[a-z]{1,10}",
        extra_claim_val in "[a-zA-Z0-9 _-]{0,32}",
    ) {
        let idp = test_idp();
        let now = now_unix();
        let claims = json!({
            "iss": idp.issuer(),
            "aud": aud,
            "sub": sub,
            "exp": now + ttl_secs,
            "iat": now,
            extra_claim_key: extra_claim_val,
        });
        let token = idp.issue(&claims);

        let mgr = JwksManager::new();
        let validated = validate_blocking(&mgr, &token, &idp.issuer(), std::slice::from_ref(&aud))
            .expect("well-formed token must validate");
        prop_assert_eq!(validated["sub"].as_str(), Some(sub.as_str()));
        prop_assert_eq!(validated["aud"].as_str(), Some(aud.as_str()));
    }

    /// Mismatched audience MUST always reject.
    #[test]
    fn audience_mismatch_rejects(
        sub in "[a-zA-Z0-9_-]{1,32}",
        token_aud in "[a-zA-Z0-9_-]{1,32}",
        validator_aud in "[a-zA-Z0-9_-]{1,32}",
    ) {
        // Force the audiences to differ.
        prop_assume!(token_aud != validator_aud);

        let idp = test_idp();
        let now = now_unix();
        let claims = json!({
            "iss": idp.issuer(),
            "aud": token_aud,
            "sub": sub,
            "exp": now + 600,
            "iat": now,
        });
        let token = idp.issue(&claims);

        let mgr = JwksManager::new();
        let result = validate_blocking(&mgr, &token, &idp.issuer(), std::slice::from_ref(&validator_aud));
        prop_assert!(
            result.is_err(),
            "token aud={token_aud:?} should not validate against {validator_aud:?}"
        );
    }

    /// Mismatched issuer MUST always reject.
    #[test]
    fn issuer_mismatch_rejects(
        validator_iss in "https://[a-z]{1,16}\\.example\\.com",
    ) {
        let idp = test_idp();
        // Token's iss is `idp.issuer()` (the spawned server's URL).
        prop_assume!(validator_iss != idp.issuer());

        let now = now_unix();
        let claims = json!({
            "iss": idp.issuer(),
            "aud": "test-aud",
            "sub": "test-user",
            "exp": now + 600,
            "iat": now,
        });
        let token = idp.issue(&claims);

        let mgr = JwksManager::new();
        let result = validate_blocking(&mgr, &token, &validator_iss, &["test-aud".to_string()]);
        prop_assert!(
            result.is_err(),
            "token issued by {} should not validate against {validator_iss:?}",
            idp.issuer()
        );
    }

    /// Tampering with any byte of a JWT MUST cause validation to fail.
    /// (The signature spans the whole payload, so any modification breaks
    /// either the signature check or JSON parsing.)
    #[test]
    fn tampering_rejects(
        flip_position_pct in 0u8..100u8,
        flip_byte in 1u8..=255u8,
    ) {
        let idp = test_idp();
        let now = now_unix();
        let claims = json!({
            "iss": idp.issuer(),
            "aud": "test-aud",
            "sub": "test-user",
            "exp": now + 600,
            "iat": now,
        });
        let token = idp.issue(&claims);

        // Pick a byte position by percentage; flip it via XOR. Skip the
        // very last char (a base64 pad-equivalent that may be ignored).
        let mut bytes = token.into_bytes();
        let pos = (flip_position_pct as usize * bytes.len()) / 100;
        let pos = pos.min(bytes.len().saturating_sub(2));
        bytes[pos] ^= flip_byte;
        let tampered = match String::from_utf8(bytes) {
            Ok(s) => s,
            // XORing into a UTF-8 sequence can produce invalid UTF-8; in
            // that case the parser would reject before signature check
            // anyway, which is fine for this property.
            Err(_) => return Ok(()),
        };

        let mgr = JwksManager::new();
        let result = validate_blocking(
            &mgr,
            &tampered,
            &idp.issuer(),
            &["test-aud".to_string()],
        );
        prop_assert!(result.is_err(), "tampered token must not validate");
    }

    /// Validation cache hit MUST return the same claims as the original
    /// validation. This catches any future bug where the cache layer
    /// loses or mutates fields between insert and read.
    #[test]
    fn cache_hit_preserves_claims(
        sub in "[a-zA-Z0-9_-]{1,32}",
        aud in "[a-zA-Z0-9_:-]{1,32}",
        custom_field in "[a-zA-Z0-9 _]{0,32}",
    ) {
        let idp = test_idp();
        let now = now_unix();
        let claims = json!({
            "iss": idp.issuer(),
            "aud": aud,
            "sub": sub,
            "exp": now + 600,
            "iat": now,
            "kunobi_custom": custom_field,
        });
        let token = idp.issue(&claims);

        let mgr = JwksManager::new().with_validation_cache(Duration::from_secs(60));
        let first = validate_blocking(&mgr, &token, &idp.issuer(), std::slice::from_ref(&aud))
            .expect("first validation should succeed");
        // Second call should hit the cache. Point at a deliberately-broken
        // JWKS URL so a non-cache-hit would surface as a network error.
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        let rt = RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap());
        let second = rt.block_on(mgr.validate_jwt(
            &token,
            "http://127.0.0.1:1/does-not-exist",
            &idp.issuer(),
            &[aud],
            &["ES256".to_string()],
        )).expect("cache hit should not need network");

        prop_assert_eq!(first, second);
    }
}
