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
use tracing::warn;

use crate::common::AuthError;

/// Maximum tolerated future drift on a request timestamp.
///
/// Past drift is bounded by the caller-supplied `max_drift`. Future drift is
/// bounded by this constant -- a small fixed value just sufficient to absorb
/// reasonable client/server clock skew. Bounding future drift to a constant
/// (rather than `max_drift`) keeps the captured-request reuse window narrow,
/// so the [`NonceTracker`] only needs to remember a nonce for `max_drift +
/// MAX_FUTURE_CLOCK_SKEW` rather than `2 * max_drift` to defeat replay.
pub const MAX_FUTURE_CLOCK_SKEW: Duration = Duration::from_secs(5);

/// Truncate a `"SHA256:..."` fingerprint to a short prefix that is safe to
/// echo in unauthenticated error responses. The full value is kept in
/// server-side logs for forensics.
fn redact_fingerprint(fp: &str) -> String {
    // Keep the algorithm prefix (e.g. `"SHA256:"`) plus 8 characters.
    if let Some((prefix, rest)) = fp.split_once(':') {
        let head: String = rest.chars().take(8).collect();
        format!("{prefix}:{head}…")
    } else {
        let head: String = fp.chars().take(8).collect();
        format!("{head}…")
    }
}

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
            let value = strip_surrounding_quotes(value.trim());

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

/// Strip surrounding `"` from a value if both are present and the input
/// has length >= 2. Returns the inner string in that case, or the input
/// unchanged otherwise. Pure so the three-way `&&` chain is exercised
/// directly by unit tests -- mutation testing flagged the chain as
/// under-covered by header-level tests.
fn strip_surrounding_quotes(value: &str) -> &str {
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        &value[1..value.len() - 1]
    } else {
        value
    }
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
///
/// **Configuration contract**: pair `max_age` with the `max_drift` you pass
/// to [`verify_ssh_signature`]. A captured request stays drift-valid from
/// `ts - max_drift` until `ts + MAX_FUTURE_CLOCK_SKEW`, so the effective
/// replay window is `max_drift + MAX_FUTURE_CLOCK_SKEW` (≈ `max_drift + 5s`
/// at default `MAX_FUTURE_CLOCK_SKEW`). Set `max_age >= max_drift` to be
/// safe; setting `max_age` shorter creates a window where drift still
/// passes but the nonce has been forgotten -- a replay primitive.
pub struct NonceTracker {
    seen: RwLock<HashMap<String, Instant>>,
    max_age: Duration,
}

impl NonceTracker {
    /// Create a new tracker where nonces are valid for `max_age`.
    ///
    /// See [`NonceTracker`] type docs for the relationship with
    /// [`verify_ssh_signature`]'s `max_drift` parameter -- in short, prefer
    /// `max_age >= max_drift`.
    pub fn new(max_age: Duration) -> Self {
        Self {
            seen: RwLock::new(HashMap::new()),
            max_age,
        }
    }

    /// Check whether `nonce` has already been seen, atomically.
    ///
    /// Returns `true` if this is a replay (nonce already present and not yet
    /// expired). Returns `false` if the nonce is fresh; in that case the nonce
    /// is recorded and expired entries are purged inline.
    ///
    /// The check + insert runs under a single write lock to prevent a TOCTOU
    /// race where two concurrent requests both observe a nonce as fresh
    /// before either inserts.
    pub async fn check_and_insert(&self, nonce: &str) -> bool {
        let mut seen = self.seen.write().await;
        let now = Instant::now();

        // Replay only if we have seen this nonce AND it is still within the
        // window. Expired entries fall through to the cleanup + insert below,
        // same as never-seen nonces.
        if let Some(inserted_at) = seen.get(nonce)
            && nonce_is_within_window(inserted_at.elapsed(), self.max_age)
        {
            return true;
        }

        seen.retain(|_, inserted_at| nonce_is_within_window(inserted_at.elapsed(), self.max_age));
        seen.insert(nonce.to_string(), now);
        false
    }

    /// Evict all expired nonces from the tracker.
    pub async fn cleanup(&self) {
        let mut seen = self.seen.write().await;
        seen.retain(|_, inserted_at| nonce_is_within_window(inserted_at.elapsed(), self.max_age));
    }
}

/// Pure predicate for the replay window. Takes the already-computed elapsed
/// duration (rather than an `Instant`) so unit tests can pin the boundary
/// exactly -- with a wall-clock `Instant::elapsed()` inside the function,
/// the boundary moment can never be hit deterministically.
///
/// Mutation testing flagged the `<` operator: `<` -> `<=` would treat a
/// nonce inserted *exactly* `max_age` ago as still-replaying; `<` -> `>`
/// would invert the window. Tests `nonce_is_within_window_*` kill these.
fn nonce_is_within_window(elapsed: Duration, max_age: Duration) -> bool {
    elapsed < max_age
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

    // Drift check is asymmetric.
    //
    // - Past drift: allow up to `max_drift`. Network latency + retries.
    // - Future drift: allow only `MAX_FUTURE_CLOCK_SKEW` (a few seconds).
    //   Just enough to absorb client/server clock skew, not enough to
    //   meaningfully extend a captured request's lifetime.
    //
    // Why the asymmetry matters: a captured request stays drift-valid for
    // `[ts - max_drift, ts + max_drift]`. With symmetric drift, that's a
    // `2*max_drift` window. The replay-protection NonceTracker has its own
    // `max_age` configured by the caller; if `max_age < 2*max_drift`, the
    // nonce expires before the drift window closes -- replay-able. Bounding
    // future drift to a small constant collapses the effective window to
    // `max_drift + MAX_FUTURE_CLOCK_SKEW`, so any sane `max_age >= max_drift`
    // closes the loop.
    if ts_secs > now_secs {
        let future_drift = (ts_secs - now_secs) as u64;
        if future_drift > MAX_FUTURE_CLOCK_SKEW.as_secs() {
            return Err(AuthError::Unauthorized(format!(
                "timestamp is {future_drift}s in the future; max future skew is {}s",
                MAX_FUTURE_CLOCK_SKEW.as_secs()
            )));
        }
    } else {
        let past_drift = (now_secs - ts_secs) as u64;
        if past_drift > max_drift.as_secs() {
            return Err(AuthError::Unauthorized(format!(
                "timestamp is {past_drift}s in the past; max past drift is {}s",
                max_drift.as_secs()
            )));
        }
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

    let (parsed_key, provider) = match found_key {
        Some(v) => v,
        None => {
            warn!(
                fingerprint = %header.fingerprint,
                "SSH auth: no matching key for fingerprint"
            );
            return Err(AuthError::Unauthorized(format!(
                "no key found for fingerprint {}",
                redact_fingerprint(&header.fingerprint)
            )));
        }
    };

    // 3. Check revocation.
    if provider
        .revoked_fingerprints
        .contains(&parsed_key.fingerprint)
    {
        warn!(
            fingerprint = %parsed_key.fingerprint,
            provider = %provider.name,
            "SSH auth: revoked key presented"
        );
        return Err(AuthError::Unauthorized(format!(
            "key {} has been revoked",
            redact_fingerprint(&parsed_key.fingerprint)
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

    // Mutation-killer tests for the `&&` chain inside parse_ssh_auth_header
    // that strips surrounding quotes from a value:
    //
    //     value.starts_with('"') && value.ends_with('"') && value.len() >= 2
    //
    // Mutants: `&&` -> `||` would slice value[1..len-1] on inputs that don't
    // satisfy all three conditions, causing a panic on edge cases. These
    // tests exercise the malformed-quote shapes.

    #[test]
    fn test_parse_value_no_quotes_unwrapped_directly() {
        // A value with no quotes at all: must be accepted as-is, not crash.
        // Kills `len >= 2` -> `len > 2` (would slice empty/single-char).
        let sig_b64 = B64.encode(b"x");
        let hdr =
            format!("fingerprint=SHA256:abc,timestamp=1700000000,nonce=n,signature={sig_b64}");
        let parsed = parse_ssh_auth_header(&hdr).unwrap();
        assert_eq!(parsed.fingerprint, "SHA256:abc");
        assert_eq!(parsed.nonce, "n");
    }

    #[test]
    fn test_parse_value_only_leading_quote() {
        // value starts with `"` but doesn't end with one. Without the
        // && chain, slicing [1..len-1] would corrupt the value.
        let sig_b64 = B64.encode(b"x");
        let hdr = format!(
            r#"fingerprint="SHA256:abc,timestamp="1700000000",nonce="n",signature="{sig_b64}""#
        );
        // Whatever the parser does (accept literally, or error), it must
        // not panic. The fingerprint here has an unmatched `"` -- accepting
        // it with the leading `"` retained is the safe behaviour.
        let _ = parse_ssh_auth_header(&hdr);
    }

    #[test]
    fn test_parse_value_only_trailing_quote() {
        // value ends with `"` but doesn't start with one.
        let sig_b64 = B64.encode(b"x");
        let hdr = format!(
            r#"fingerprint=SHA256:abc",timestamp="1700000000",nonce="n",signature="{sig_b64}""#
        );
        let _ = parse_ssh_auth_header(&hdr);
    }

    #[test]
    fn test_parse_empty_quoted_value() {
        // value is exactly `""` (length 2). This satisfies the && chain,
        // so it slices to empty. Kills `len >= 2` -> `len > 2` (the
        // mutant would not slice, leaving the literal `""` instead of "").
        let sig_b64 = B64.encode(b"x");
        let hdr =
            format!(r#"fingerprint="",timestamp="1700000000",nonce="n",signature="{sig_b64}""#);
        let parsed = parse_ssh_auth_header(&hdr).unwrap();
        assert_eq!(parsed.fingerprint, "");
    }

    // Mutation-killer tests for `strip_surrounding_quotes`. Each case
    // requires a distinct combination of (starts_with `"`, ends_with `"`,
    // len >= 2) -- between them they pin every `&&` -> `||` and every
    // delete-condition mutant.

    #[test]
    fn strip_quotes_both_ends_long_enough() {
        assert_eq!(strip_surrounding_quotes(r#""x""#), "x");
    }

    #[test]
    fn strip_quotes_no_quotes_keeps_input() {
        // Kills `&&` -> `||` between starts and ends (would slice and
        // corrupt `SHA256:abc` -> `HA256:ab`).
        assert_eq!(strip_surrounding_quotes("SHA256:abc"), "SHA256:abc");
    }

    #[test]
    fn strip_quotes_only_leading_quote_keeps_input() {
        // starts_with=true, ends_with=false. Kills `&&` -> `||`.
        assert_eq!(strip_surrounding_quotes(r#""abc"#), r#""abc"#);
    }

    #[test]
    fn strip_quotes_only_trailing_quote_keeps_input() {
        // starts_with=false, ends_with=true. Kills `&&` -> `||`.
        assert_eq!(strip_surrounding_quotes(r#"abc""#), r#"abc""#);
    }

    #[test]
    fn strip_quotes_single_quote_does_not_panic() {
        // Single `"` (len=1): starts AND ends with `"`, but len<2.
        // Without the `len >= 2` guard, the slice [1..0] panics.
        // Kills `&&` -> `||` on the third condition.
        assert_eq!(strip_surrounding_quotes(r#"""#), r#"""#);
    }

    #[test]
    fn strip_quotes_just_two_quotes_yields_empty() {
        assert_eq!(strip_surrounding_quotes(r#""""#), "");
    }

    // Mutation-killer tests for `split_header_params`. The splitter must
    // not split on commas inside quoted strings.

    #[test]
    fn split_preserves_quoted_comma() {
        // The classic case: a `,` inside a quoted value. Kills:
        //   - delete '"' match arm  (in_quotes never toggles)
        //   - !in_quotes guard -> true (always splits)
        //   - delete `!` in `!in_quotes` (toggle becomes no-op)
        let input = r#"a="x,y",b="z""#;
        let parts = split_header_params(input);
        assert_eq!(
            parts,
            vec![r#"a="x,y""#.to_string(), r#"b="z""#.to_string()]
        );
    }

    #[test]
    fn split_handles_unquoted() {
        // Plain commas split as expected.
        let parts = split_header_params("a=1,b=2,c=3");
        assert_eq!(parts, vec!["a=1", "b=2", "c=3"]);
    }

    #[test]
    fn split_trims_whitespace() {
        let parts = split_header_params(" a=1 , b=2 ");
        assert_eq!(parts, vec!["a=1", "b=2"]);
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

    // Mutation-killer tests for the replay-window predicate. The signature
    // takes pre-computed `elapsed` so we can pin the boundary moment
    // exactly -- `Instant::elapsed()` inside the predicate would foil that.

    #[test]
    fn nonce_within_window_zero_elapsed() {
        // elapsed = 0 < 60s -> within. Kills `<` -> `>` (false) and
        // `<` -> `==` (false).
        assert!(nonce_is_within_window(
            Duration::ZERO,
            Duration::from_secs(60)
        ));
    }

    #[test]
    fn nonce_at_window_exact_is_outside() {
        // elapsed == max_age: the window is half-open [0, max_age). At the
        // boundary, the nonce is no longer within. Kills `<` -> `<=`
        // (would say still-within) and `<` -> `==` (would say within).
        assert!(!nonce_is_within_window(
            Duration::from_secs(60),
            Duration::from_secs(60),
        ));
    }

    #[test]
    fn nonce_past_window_is_outside() {
        // elapsed > max_age -> stale. Kills `<` -> `>` and `<` -> `>=`.
        assert!(!nonce_is_within_window(
            Duration::from_secs(120),
            Duration::from_secs(60),
        ));
    }

    #[test]
    fn nonce_just_inside_window_is_within() {
        // elapsed = max_age - 1ns -> within. Pins the strict-less-than
        // boundary from the inside.
        let max_age = Duration::from_secs(60);
        assert!(nonce_is_within_window(
            max_age - Duration::from_nanos(1),
            max_age,
        ));
    }

    /// Drive many concurrent insertions of the same nonce: exactly one must
    /// observe `false` (fresh); every other concurrent task must see `true`
    /// (replay). Guards against a TOCTOU race in `check_and_insert`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_nonce_concurrent_check_and_insert_is_atomic() {
        use std::sync::Arc;
        let tracker = Arc::new(NonceTracker::new(Duration::from_secs(60)));

        let mut handles = Vec::new();
        for _ in 0..32 {
            let t = tracker.clone();
            handles.push(tokio::spawn(async move {
                t.check_and_insert("contended-nonce").await
            }));
        }

        let mut fresh = 0usize;
        let mut replays = 0usize;
        for h in handles {
            if h.await.unwrap() {
                replays += 1;
            } else {
                fresh += 1;
            }
        }
        assert_eq!(fresh, 1, "exactly one task must observe a fresh nonce");
        assert_eq!(replays, 31, "all other tasks must observe a replay");
    }

    #[test]
    fn test_redact_fingerprint_with_prefix() {
        let r = redact_fingerprint("SHA256:0123456789abcdef0123456789abcdef0123456789abcdef");
        assert!(r.starts_with("SHA256:01234567"));
        assert!(r.ends_with('…'));
        assert!(!r.contains("89abcdef0123"));
    }

    #[test]
    fn test_redact_fingerprint_without_prefix() {
        let r = redact_fingerprint("plainfingerprintabcdef");
        assert!(r.starts_with("plainfin"));
        assert!(r.ends_with('…'));
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

    /// Boundary check: a drift of *exactly* `max_drift` seconds must still be
    /// accepted (`>` comparison, not `>=`).
    #[tokio::test]
    async fn test_verify_drift_at_boundary_accepted() {
        use rand_core::OsRng;
        let private_key = ssh_key::PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let parsed = ParsedAuthorizedKey {
            fingerprint: fingerprint.clone(),
            public_key,
            comment: "boundary@test".into(),
        };
        let provider = CompiledSshProvider {
            name: "svc".into(),
            keys: vec![parsed],
            revoked_fingerprints: HashSet::new(),
            identity_template: "{fingerprint}".into(),
        };

        let max_drift = Duration::from_secs(300);

        // Timestamp exactly at the boundary (300s in the past) -- should pass.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ts_boundary = (now_unix - max_drift.as_secs() as i64).to_string();

        let message = build_signed_message(&ts_boundary, "n-bd", "GET", "/", &[]);
        let sshsig = private_key
            .sign("svc-ns", HashAlg::Sha512, &message)
            .unwrap();
        let sig_b64 = encode_sshsig(&sshsig);

        let header_str = format!(
            r#"fingerprint="{fingerprint}",timestamp="{ts_boundary}",nonce="n-bd",signature="{sig_b64}""#
        );
        let header = parse_ssh_auth_header(&header_str).unwrap();

        let result =
            verify_ssh_signature(&header, "svc-ns", "GET", "/", &[], &[provider], max_drift);
        assert!(
            result.is_ok(),
            "drift == max_drift must be accepted: {result:?}"
        );
    }

    /// Boundary check: a drift of `max_drift + 1` seconds must be rejected.
    #[tokio::test]
    async fn test_verify_drift_one_past_boundary_rejected() {
        use rand_core::OsRng;
        let private_key = ssh_key::PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let parsed = ParsedAuthorizedKey {
            fingerprint: fingerprint.clone(),
            public_key,
            comment: "over@test".into(),
        };
        let provider = CompiledSshProvider {
            name: "svc".into(),
            keys: vec![parsed],
            revoked_fingerprints: HashSet::new(),
            identity_template: "{fingerprint}".into(),
        };

        let max_drift = Duration::from_secs(300);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // 1s past the limit.
        let ts_over = (now_unix - max_drift.as_secs() as i64 - 1).to_string();

        let message = build_signed_message(&ts_over, "n-over", "GET", "/", &[]);
        let sshsig = private_key
            .sign("svc-ns", HashAlg::Sha512, &message)
            .unwrap();
        let sig_b64 = encode_sshsig(&sshsig);

        let header_str = format!(
            r#"fingerprint="{fingerprint}",timestamp="{ts_over}",nonce="n-over",signature="{sig_b64}""#
        );
        let header = parse_ssh_auth_header(&header_str).unwrap();

        let err = verify_ssh_signature(&header, "svc-ns", "GET", "/", &[], &[provider], max_drift)
            .unwrap_err();
        assert!(matches!(err, AuthError::Unauthorized(_)));
    }

    /// Future timestamps within `MAX_FUTURE_CLOCK_SKEW` are accepted -- this
    /// allowance exists exactly to absorb harmless client/server clock skew.
    #[tokio::test]
    async fn test_verify_small_future_drift_accepted() {
        use rand_core::OsRng;
        let private_key = ssh_key::PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let parsed = ParsedAuthorizedKey {
            fingerprint: fingerprint.clone(),
            public_key,
            comment: "skew@test".into(),
        };
        let provider = CompiledSshProvider {
            name: "svc".into(),
            keys: vec![parsed],
            revoked_fingerprints: HashSet::new(),
            identity_template: "{fingerprint}".into(),
        };

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // 2 seconds in the future -- under MAX_FUTURE_CLOCK_SKEW (5s).
        let ts_future = (now_unix + 2).to_string();
        let message = build_signed_message(&ts_future, "n-fut", "GET", "/", &[]);
        let sshsig = private_key
            .sign("svc-ns", HashAlg::Sha512, &message)
            .unwrap();
        let sig_b64 = encode_sshsig(&sshsig);

        let header_str = format!(
            r#"fingerprint="{fingerprint}",timestamp="{ts_future}",nonce="n-fut",signature="{sig_b64}""#
        );
        let header = parse_ssh_auth_header(&header_str).unwrap();

        let result = verify_ssh_signature(
            &header,
            "svc-ns",
            "GET",
            "/",
            &[],
            std::slice::from_ref(&provider),
            Duration::from_secs(300),
        );
        assert!(
            result.is_ok(),
            "small future drift must be accepted: {result:?}"
        );
    }

    /// Future timestamps beyond `MAX_FUTURE_CLOCK_SKEW` are rejected -- the
    /// hardening that prevents widening the replay window via future-dated
    /// captured requests. Past `max_drift` is generous (e.g. 300s) but
    /// future drift must stay tight.
    #[tokio::test]
    async fn test_verify_large_future_drift_rejected() {
        use rand_core::OsRng;
        let private_key = ssh_key::PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let public_key = private_key.public_key().clone();
        let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
        let parsed = ParsedAuthorizedKey {
            fingerprint: fingerprint.clone(),
            public_key,
            comment: "futuristic@test".into(),
        };
        let provider = CompiledSshProvider {
            name: "svc".into(),
            keys: vec![parsed],
            revoked_fingerprints: HashSet::new(),
            identity_template: "{fingerprint}".into(),
        };

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // 60s in the future -- past MAX_FUTURE_CLOCK_SKEW (5s) by a lot.
        // With the OLD symmetric drift check (max_drift = 300s) this would
        // have been accepted; a captured request with this timestamp would
        // have stayed drift-valid for ~600s, easily outliving any reasonable
        // NonceTracker.max_age.
        let ts_far_future = (now_unix + 60).to_string();
        let message = build_signed_message(&ts_far_future, "n-far", "GET", "/", &[]);
        let sshsig = private_key
            .sign("svc-ns", HashAlg::Sha512, &message)
            .unwrap();
        let sig_b64 = encode_sshsig(&sshsig);

        let header_str = format!(
            r#"fingerprint="{fingerprint}",timestamp="{ts_far_future}",nonce="n-far",signature="{sig_b64}""#
        );
        let header = parse_ssh_auth_header(&header_str).unwrap();

        let err = verify_ssh_signature(
            &header,
            "svc-ns",
            "GET",
            "/",
            &[],
            std::slice::from_ref(&provider),
            Duration::from_secs(300),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(matches!(err, AuthError::Unauthorized(_)));
        assert!(
            msg.contains("future"),
            "error should explain it's a future-drift issue: {msg}"
        );
    }

    /// The error returned for an unknown fingerprint must NOT contain the
    /// full fingerprint string sent by the client.
    #[tokio::test]
    async fn test_unknown_fingerprint_error_is_redacted() {
        let now_ts = current_unix_ts();
        let sig_b64 = B64.encode(b"dummy");
        let full_fp = "SHA256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let header_str = format!(
            r#"fingerprint="{full_fp}",timestamp="{now_ts}",nonce="n",signature="{sig_b64}""#
        );
        let header = parse_ssh_auth_header(&header_str).unwrap();

        let err = verify_ssh_signature(
            &header,
            "ns",
            "GET",
            "/",
            &[],
            &[],
            Duration::from_secs(300),
        )
        .unwrap_err();
        let msg = format!("{err}");
        assert!(
            !msg.contains(full_fp),
            "error must not echo full fingerprint: {msg}"
        );
        assert!(
            msg.contains("SHA256:"),
            "redacted form should keep prefix: {msg}"
        );
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
