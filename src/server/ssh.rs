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
                    let bytes = B64
                        .decode(value)
                        .map_err(|e| AuthError::Unauthorized(format!("invalid signature base64: {e}")))?;
                    signature_bytes = Some(bytes);
                }
                _ => {} // ignore unknown keys
            }
        }
    }

    Ok(SshSignatureHeader {
        fingerprint: fingerprint
            .ok_or_else(|| AuthError::Unauthorized("missing fingerprint in SSH-Signature header".into()))?,
        timestamp: timestamp
            .ok_or_else(|| AuthError::Unauthorized("missing timestamp in SSH-Signature header".into()))?,
        nonce: nonce
            .ok_or_else(|| AuthError::Unauthorized("missing nonce in SSH-Signature header".into()))?,
        signature: signature_bytes
            .ok_or_else(|| AuthError::Unauthorized("missing signature in SSH-Signature header".into()))?,
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
// Placeholders for Task 3 & 4 (added in subsequent commits)
// ──────────────────────────────────────────────────────────────────────────────

// NonceTracker — Task 3
pub struct NonceTracker {
    seen: RwLock<HashMap<String, Instant>>,
    max_age: Duration,
}

// ParsedAuthorizedKey — Task 4
pub struct ParsedAuthorizedKey {
    pub fingerprint: String,
    pub public_key: PublicKey,
    pub comment: String,
}

// CompiledSshProvider — Task 4
pub struct CompiledSshProvider {
    pub name: String,
    pub keys: Vec<ParsedAuthorizedKey>,
    pub revoked_fingerprints: HashSet<String>,
    pub identity_template: String,
}

// VerifiedSshIdentity — Task 4
pub struct VerifiedSshIdentity {
    pub provider_name: String,
    pub fingerprint: String,
    pub comment: String,
    pub identity: String,
}

// build_signed_message — Task 4
pub fn build_signed_message(
    _timestamp: &str,
    _nonce: &str,
    _method: &str,
    _path_with_query: &str,
    _body: &[u8],
) -> Vec<u8> {
    unimplemented!("Task 4")
}

// verify_ssh_signature — Task 4
pub fn verify_ssh_signature(
    _header: &SshSignatureHeader,
    _namespace: &str,
    _method: &str,
    _path_with_query: &str,
    _body: &[u8],
    _providers: &[CompiledSshProvider],
    _max_drift: Duration,
) -> Result<VerifiedSshIdentity, AuthError> {
    unimplemented!("Task 4")
}

// parse_authorized_key — Task 4
pub fn parse_authorized_key(_line: &str) -> Result<ParsedAuthorizedKey, AuthError> {
    unimplemented!("Task 4")
}

impl NonceTracker {
    pub fn new(_max_age: Duration) -> Self {
        unimplemented!("Task 3")
    }

    pub async fn check_and_insert(&self, _nonce: &str) -> bool {
        unimplemented!("Task 3")
    }

    pub async fn cleanup(&self) {
        unimplemented!("Task 3")
    }
}

// Suppress dead_code / unused warnings for placeholders
#[allow(unused)]
const _: () = {
    let _ = std::mem::size_of::<SshSig>();
    let _ = std::mem::size_of::<Sha256>();
};

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
}
