//! SSH signature-based authentication: header parsing, nonce tracking, and
//! SSHSIG verification.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::{Digest, Sha256};
use ssh_encoding::Decode;
#[cfg(test)]
use ssh_encoding::Encode;
use ssh_key::{Algorithm, HashAlg, PublicKey, SshSig};
use tokio::sync::RwLock;

use crate::common::AuthError;

// ──────────────────────────────────────────────────────────────────────────────
// Task 2: SSH-Signature header parsing
// ──────────────────────────────────────────────────────────────────────────────

/// Parsed fields from the `SSH-Signature` HTTP header.
#[derive(Debug, Clone)]
pub struct SshSignatureHeader {
    pub fingerprint: String,
    pub timestamp: String,
    pub nonce: String,
    pub signature: Vec<u8>,
}

/// Parse an `SSH-Signature` header value of the form:
/// `fingerprint="...",timestamp="...",nonce="...",signature="base64..."`
///
/// Unknown keys are silently ignored for forward compatibility.
pub fn parse_ssh_auth_header(header: &str) -> Result<SshSignatureHeader, AuthError> {
    let mut fingerprint: Option<String> = None;
    let mut timestamp: Option<String> = None;
    let mut nonce: Option<String> = None;
    let mut signature_bytes: Option<Vec<u8>> = None;

    for param in split_header_params(header) {
        let param = param.trim().to_string();
        if let Some((key, value)) = param.split_once('=') {
            let key = key.trim();
            // Strip surrounding quotes from the value.
            let value = value.trim();
            let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
                &value[1..value.len() - 1]
            } else {
                value
            };

            match key {
                "fingerprint" => fingerprint = Some(value.to_string()),
                "timestamp" => timestamp = Some(value.to_string()),
                "nonce" => nonce = Some(value.to_string()),
                "signature" => {
                    let bytes = B64.decode(value).map_err(|e| {
                        AuthError::Unauthorized(format!("invalid signature base64: {e}"))
                    })?;
                    signature_bytes = Some(bytes);
                }
                _ => {} // ignore unknown keys
            }
        }
    }

    Ok(SshSignatureHeader {
        fingerprint: fingerprint.ok_or_else(|| {
            AuthError::Unauthorized("missing fingerprint in SSH-Signature header".into())
        })?,
        timestamp: timestamp.ok_or_else(|| {
            AuthError::Unauthorized("missing timestamp in SSH-Signature header".into())
        })?,
        nonce: nonce.ok_or_else(|| {
            AuthError::Unauthorized("missing nonce in SSH-Signature header".into())
        })?,
        signature: signature_bytes.ok_or_else(|| {
            AuthError::Unauthorized("missing signature in SSH-Signature header".into())
        })?,
    })
}

/// Split a header value by commas while respecting double-quoted strings.
///
/// A quoted string like `signature="a,b"` will not be split at the inner
/// comma.
pub fn split_header_params(header: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in header.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                parts.push(current.trim().to_string());
                current = String::new();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }

    parts
}

// ──────────────────────────────────────────────────────────────────────────────
// Task 3: Nonce tracker for replay protection
// ──────────────────────────────────────────────────────────────────────────────

/// Tracks seen nonces to prevent replay attacks.
///
/// Nonces are stored with their insertion time and are evicted once they
/// exceed `max_age`.
pub struct NonceTracker {
    seen: RwLock<HashMap<String, Instant>>,
    max_age: Duration,
}

impl NonceTracker {
    /// Create a new tracker where nonces are valid for `max_age`.
    pub fn new(max_age: Duration) -> Self {
        Self {
            seen: RwLock::new(HashMap::new()),
            max_age,
        }
    }

    /// Check whether `nonce` has already been seen.
    ///
    /// Returns `true` if this is a replay (nonce already present and not yet
    /// expired).  Returns `false` if the nonce is fresh.  In the fresh case
    /// the nonce is recorded and expired entries are purged inline.
    pub async fn check_and_insert(&self, nonce: &str) -> bool {
        // Fast path: read lock to check for replay.
        {
            let seen = self.seen.read().await;
            if let Some(inserted_at) = seen.get(nonce) {
                if inserted_at.elapsed() < self.max_age {
                    return true; // replay
                }
                // Entry exists but is expired — fall through to write path.
            }
        }

        // Write path: insert new nonce and clean up expired entries.
        let mut seen = self.seen.write().await;
        let now = Instant::now();

        // Remove expired entries.
        seen.retain(|_, inserted_at| inserted_at.elapsed() < self.max_age);

        // Insert the current nonce (or update if it was expired).
        seen.insert(nonce.to_string(), now);

        false // fresh nonce
    }

    /// Evict all expired nonces from the tracker.
    pub async fn cleanup(&self) {
        let mut seen = self.seen.write().await;
        seen.retain(|_, inserted_at| inserted_at.elapsed() < self.max_age);
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Task 4: SSHSIG verification
// ──────────────────────────────────────────────────────────────────────────────

/// A parsed and pre-validated entry from an `authorized_keys` file.
#[derive(Clone, Debug)]
pub struct ParsedAuthorizedKey {
    /// `"SHA256:..."` fingerprint string.
    pub fingerprint: String,
    /// The parsed public key.
    pub public_key: PublicKey,
    /// The comment field (e.g. `"user@host"`).
    pub comment: String,
}

/// A compiled SSH provider, ready for efficient signature verification.
#[derive(Clone, Debug)]
pub struct CompiledSshProvider {
    pub name: String,
    pub keys: Vec<ParsedAuthorizedKey>,
    pub revoked_fingerprints: HashSet<String>,
    /// Template for building an identity; `{fingerprint}` and `{comment}`
    /// are substituted at verification time.
    pub identity_template: String,
}

/// The verified identity that emerges from a successful SSH signature check.
#[derive(Clone, Debug)]
pub struct VerifiedSshIdentity {
    pub provider_name: String,
    pub fingerprint: String,
    pub comment: String,
    pub identity: String,
}

/// Parse a single `authorized_keys` line into a `ParsedAuthorizedKey`.
///
/// Only Ed25519 keys are accepted; all others return
/// `AuthError::Unauthorized`.
pub fn parse_authorized_key(line: &str) -> Result<ParsedAuthorizedKey, AuthError> {
    let key = PublicKey::from_openssh(line)
        .map_err(|e| AuthError::Unauthorized(format!("invalid authorized_key line: {e}")))?;

    if key.algorithm() != Algorithm::Ed25519 {
        return Err(AuthError::Unauthorized(format!(
            "only Ed25519 keys are accepted, got {:?}",
            key.algorithm()
        )));
    }

    let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
    let comment = key.comment().to_string();

    Ok(ParsedAuthorizedKey {
        fingerprint,
        public_key: key,
        comment,
    })
}

/// Build the canonical signed message from its components.
///
/// Format:
/// ```text
/// {timestamp}\n{nonce}\n{METHOD} {path_with_query}\n{body_sha256_hex|""}
/// ```
///
/// If `body` is non-empty its SHA-256 digest is hex-encoded; otherwise the
/// body line is empty.
pub fn build_signed_message(
    timestamp: &str,
    nonce: &str,
    method: &str,
    path_with_query: &str,
    body: &[u8],
) -> Vec<u8> {
    let body_hash = if body.is_empty() {
        String::new()
    } else {
        let digest = Sha256::digest(body);
        hex::encode(digest)
    };

    format!("{timestamp}\n{nonce}\n{method} {path_with_query}\n{body_hash}").into_bytes()
}

/// Verify an SSH signature and return the authenticated identity.
///
/// Steps:
/// 1. Parse and drift-check the timestamp.
/// 2. Look up the key by fingerprint across `providers`.
/// 3. Check for revocation.
/// 4. Reconstruct the signed message.
/// 5. Deserialize the SSHSIG from `header.signature`.
/// 6. Verify namespace matches.
/// 7. Verify signature via `public_key.verify(namespace, message, sshsig)`.
/// 8. Build the identity string from the provider's template.
pub fn verify_ssh_signature(
    header: &SshSignatureHeader,
    namespace: &str,
    method: &str,
    path_with_query: &str,
    body: &[u8],
    providers: &[CompiledSshProvider],
    max_drift: Duration,
) -> Result<VerifiedSshIdentity, AuthError> {
    // 1. Validate timestamp drift.
    let ts_secs: i64 = header
        .timestamp
        .parse()
        .map_err(|_| AuthError::Unauthorized("timestamp must be a unix epoch integer".into()))?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| AuthError::Internal(format!("system clock error: {e}")))?
        .as_secs() as i64;

    let drift = (now_secs - ts_secs).unsigned_abs();
    if drift > max_drift.as_secs() {
        return Err(AuthError::Unauthorized(format!(
            "timestamp drift of {drift}s exceeds maximum of {}s",
            max_drift.as_secs()
        )));
    }

    // 2. Find key by fingerprint.
    let mut found_key: Option<(&ParsedAuthorizedKey, &CompiledSshProvider)> = None;
    'outer: for provider in providers {
        for key in &provider.keys {
            if key.fingerprint == header.fingerprint {
                found_key = Some((key, provider));
                break 'outer;
            }
        }
    }

    let (parsed_key, provider) = found_key.ok_or_else(|| {
        AuthError::Unauthorized(format!(
            "no key found for fingerprint {}",
            header.fingerprint
        ))
    })?;

    // 3. Check revocation.
    if provider
        .revoked_fingerprints
        .contains(&parsed_key.fingerprint)
    {
        return Err(AuthError::Unauthorized(format!(
            "key {} has been revoked",
            parsed_key.fingerprint
        )));
    }

    // 4. Reconstruct signed message.
    let message = build_signed_message(
        &header.timestamp,
        &header.nonce,
        method,
        path_with_query,
        body,
    );

    // 5. Deserialize SSHSIG from binary bytes.
    let sshsig = SshSig::decode(&mut header.signature.as_slice())
        .map_err(|e| AuthError::Unauthorized(format!("invalid SSHSIG blob: {e}")))?;

    // 6. Verify namespace.
    if sshsig.namespace() != namespace {
        return Err(AuthError::Unauthorized(format!(
            "SSHSIG namespace mismatch: expected '{}', got '{}'",
            namespace,
            sshsig.namespace()
        )));
    }

    // 7. Verify signature.
    parsed_key
        .public_key
        .verify(namespace, &message, &sshsig)
        .map_err(|e| AuthError::Unauthorized(format!("signature verification failed: {e}")))?;

    // 8. Build identity.
    let identity = provider
        .identity_template
        .replace("{fingerprint}", &parsed_key.fingerprint)
        .replace("{comment}", &parsed_key.comment);

    Ok(VerifiedSshIdentity {
        provider_name: provider.name.clone(),
        fingerprint: parsed_key.fingerprint.clone(),
        comment: parsed_key.comment.clone(),
        identity,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Task 2 Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header_str() -> String {
        let sig_b64 = B64.encode(b"fakesigbytes");
        format!(
            r#"fingerprint="SHA256:abc123",timestamp="1700000000",nonce="deadbeef",signature="{sig_b64}""#
        )
    }

    #[test]
    fn test_parse_valid_header() {
        let h = parse_ssh_auth_header(&sample_header_str()).unwrap();
        assert_eq!(h.fingerprint, "SHA256:abc123");
        assert_eq!(h.timestamp, "1700000000");
        assert_eq!(h.nonce, "deadbeef");
        assert_eq!(h.signature, b"fakesigbytes");
    }

    #[test]
    fn test_parse_missing_fingerprint() {
        let sig_b64 = B64.encode(b"x");
        let hdr = format!(r#"timestamp="1700000000",nonce="n",signature="{sig_b64}""#);
        let err = parse_ssh_auth_header(&hdr).unwrap_err();
        assert!(matches!(err, AuthError::Unauthorized(_)));
    }

    #[test]
    fn test_parse_missing_timestamp() {
        let sig_b64 = B64.encode(b"x");
        let hdr = format!(r#"fingerprint="SHA256:x",nonce="n",signature="{sig_b64}""#);
        let err = parse_ssh_auth_header(&hdr).unwrap_err();
        assert!(matches!(err, AuthError::Unauthorized(_)));
    }

    #[test]
    fn test_parse_missing_nonce() {
        let sig_b64 = B64.encode(b"x");
        let hdr = format!(r#"fingerprint="SHA256:x",timestamp="1700000000",signature="{sig_b64}""#);
        let err = parse_ssh_auth_header(&hdr).unwrap_err();
        assert!(matches!(err, AuthError::Unauthorized(_)));
    }

    #[test]
    fn test_parse_missing_signature() {
        let hdr = r#"fingerprint="SHA256:x",timestamp="1700000000",nonce="n""#;
        let err = parse_ssh_auth_header(hdr).unwrap_err();
        assert!(matches!(err, AuthError::Unauthorized(_)));
    }

    #[test]
    fn test_parse_unknown_keys_ignored() {
        let sig_b64 = B64.encode(b"x");
        let hdr = format!(
            r#"fingerprint="SHA256:x",timestamp="1700000000",nonce="n",signature="{sig_b64}",unknown="whatever""#
        );
        assert!(parse_ssh_auth_header(&hdr).is_ok());
    }

    // ── Task 3 tests ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_nonce_first_use_returns_false() {
        let tracker = NonceTracker::new(Duration::from_secs(60));
        assert!(!tracker.check_and_insert("nonce1").await);
    }

    #[tokio::test]
    async fn test_nonce_replay_returns_true() {
        let tracker = NonceTracker::new(Duration::from_secs(60));
        tracker.check_and_insert("nonce1").await;
        assert!(tracker.check_and_insert("nonce1").await);
    }

    #[tokio::test]
    async fn test_different_nonces_both_return_false() {
        let tracker = NonceTracker::new(Duration::from_secs(60));
        assert!(!tracker.check_and_insert("nonce-a").await);
        assert!(!tracker.check_and_insert("nonce-b").await);
    }

    #[tokio::test]
    async fn test_expired_nonce_can_be_reused() {
        let tracker = NonceTracker::new(Duration::from_nanos(1));
        tracker.check_and_insert("nonce1").await;
        std::thread::sleep(Duration::from_millis(5));
        tracker.cleanup().await;
        assert!(!tracker.check_and_insert("nonce1").await);
    }

    // ── Task 4 tests ──────────────────────────────────────────────────────────

    /// A real Ed25519 authorized_keys line for testing.
    const TEST_ED25519_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com";

    #[test]
    fn test_parse_authorized_key_valid() {
        let k = parse_authorized_key(TEST_ED25519_PUB).unwrap();
        assert!(k.fingerprint.starts_with("SHA256:"));
        assert_eq!(k.comment, "test@example.com");
    }

    #[test]
    fn test_parse_authorized_key_non_ed25519_rejected() {
        let ecdsa_key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHxUGDfJZXgCXPMYfKhFMWbHd/F6OJgGsUIMDJYJGzaLLQDn7JDLZ8uS3Z4ZJgU9XdVPvIKW+L6m4GJBgMilAck= test@example.com";
        let err = parse_authorized_key(ecdsa_key).unwrap_err();
        assert!(matches!(err, AuthError::Unauthorized(_)));
    }

    #[test]
    fn test_build_signed_message_no_body() {
        let msg = build_signed_message("1700000000", "abc", "GET", "/api/v1/resource", &[]);
        let text = std::str::from_utf8(&msg).unwrap();
        assert_eq!(text, "1700000000\nabc\nGET /api/v1/resource\n");
    }

    #[test]
    fn test_build_signed_message_with_body() {
        let body = b"hello";
        let msg = build_signed_message("1700000000", "abc", "POST", "/api/v1/resource", body);
        let text = std::str::from_utf8(&msg).unwrap();
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let expected_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let expected = format!("1700000000\nabc\nPOST /api/v1/resource\n{expected_hash}");
        assert_eq!(text, expected);
    }

    #[tokio::test]
    async fn test_verify_rejects_expired_timestamp() {
        let k = parse_authorized_key(TEST_ED25519_PUB).unwrap();
        let provider = CompiledSshProvider {
            name: "test".into(),
            keys: vec![k],
            revoked_fingerprints: HashSet::new(),
            identity_template: "{comment}".into(),
        };
        let old_ts = "946684800"; // year 2000
        let sig_b64 = B64.encode(b"dummy");
        let header_str = format!(
            r#"fingerprint="SHA256:x",timestamp="{old_ts}",nonce="n",signature="{sig_b64}""#
        );
        let header = parse_ssh_auth_header(&header_str).unwrap();
        let err = verify_ssh_signature(
            &header,
            "test-ns",
            "GET",
            "/",
            &[],
            &[provider],
            Duration::from_secs(300),
        )
        .unwrap_err();
        assert!(matches!(err, AuthError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn test_verify_rejects_revoked_key() {
        use rand_core::OsRng;
        let private_key = ssh_key::PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let comment = public_key.comment().to_string();
        let parsed = ParsedAuthorizedKey {
            fingerprint: fingerprint.clone(),
            public_key,
            comment,
        };

        let mut revoked = HashSet::new();
        revoked.insert(fingerprint.clone());
        let provider = CompiledSshProvider {
            name: "test".into(),
            keys: vec![parsed],
            revoked_fingerprints: revoked,
            identity_template: "{comment}".into(),
        };

        let now_ts = current_unix_ts();
        let message = build_signed_message(&now_ts, "nonce123", "GET", "/", &[]);
        let sshsig = private_key
            .sign("test-ns", HashAlg::Sha512, &message)
            .unwrap();
        let sig_b64 = encode_sshsig(&sshsig);

        let header_str = format!(
            r#"fingerprint="{fingerprint}",timestamp="{now_ts}",nonce="nonce123",signature="{sig_b64}""#
        );
        let header = parse_ssh_auth_header(&header_str).unwrap();

        let err = verify_ssh_signature(
            &header,
            "test-ns",
            "GET",
            "/",
            &[],
            &[provider],
            Duration::from_secs(300),
        )
        .unwrap_err();
        assert!(matches!(err, AuthError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn test_end_to_end_verify_succeeds() {
        use rand_core::OsRng;
        let private_key = ssh_key::PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let comment = public_key.comment().to_string();
        let parsed = ParsedAuthorizedKey {
            fingerprint: fingerprint.clone(),
            public_key,
            comment: comment.clone(),
        };
        let provider = CompiledSshProvider {
            name: "myservice".into(),
            keys: vec![parsed],
            revoked_fingerprints: HashSet::new(),
            identity_template: "ssh:{comment}".into(),
        };

        let now_ts = current_unix_ts();
        let body = b"request body";
        let message = build_signed_message(&now_ts, "unique-nonce", "POST", "/api/v1/action", body);
        let sshsig = private_key
            .sign("my-service-ns", HashAlg::Sha512, &message)
            .unwrap();
        let sig_b64 = encode_sshsig(&sshsig);

        let header_str = format!(
            r#"fingerprint="{fingerprint}",timestamp="{now_ts}",nonce="unique-nonce",signature="{sig_b64}""#
        );
        let header = parse_ssh_auth_header(&header_str).unwrap();

        let identity = verify_ssh_signature(
            &header,
            "my-service-ns",
            "POST",
            "/api/v1/action",
            body,
            &[provider],
            Duration::from_secs(300),
        )
        .unwrap();

        assert_eq!(identity.provider_name, "myservice");
        assert_eq!(identity.fingerprint, fingerprint);
        assert_eq!(identity.identity, format!("ssh:{comment}"));
    }

    #[tokio::test]
    async fn test_wrong_namespace_fails() {
        use rand_core::OsRng;
        let private_key = ssh_key::PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let comment = public_key.comment().to_string();
        let parsed = ParsedAuthorizedKey {
            fingerprint: fingerprint.clone(),
            public_key,
            comment,
        };
        let provider = CompiledSshProvider {
            name: "svc".into(),
            keys: vec![parsed],
            revoked_fingerprints: HashSet::new(),
            identity_template: "{fingerprint}".into(),
        };

        let now_ts = current_unix_ts();
        let message = build_signed_message(&now_ts, "n1", "GET", "/", &[]);
        // Sign with "service-a"
        let sshsig = private_key
            .sign("service-a", HashAlg::Sha512, &message)
            .unwrap();
        let sig_b64 = encode_sshsig(&sshsig);

        let header_str = format!(
            r#"fingerprint="{fingerprint}",timestamp="{now_ts}",nonce="n1",signature="{sig_b64}""#
        );
        let header = parse_ssh_auth_header(&header_str).unwrap();

        // Verify with "service-b" — should fail due to namespace mismatch.
        let err = verify_ssh_signature(
            &header,
            "service-b",
            "GET",
            "/",
            &[],
            &[provider],
            Duration::from_secs(300),
        )
        .unwrap_err();
        assert!(matches!(err, AuthError::Unauthorized(_)));
    }

    // ── Test helpers ─────────────────────────────────────────────────────────

    fn current_unix_ts() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    fn encode_sshsig(sshsig: &SshSig) -> String {
        let mut bytes = Vec::new();
        sshsig.encode(&mut bytes).unwrap();
        B64.encode(&bytes)
    }
}
