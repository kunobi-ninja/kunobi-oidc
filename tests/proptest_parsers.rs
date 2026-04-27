//! Property-based tests for the parsers in kunobi-auth.
//!
//! Unit tests check specific examples; these check **invariants that must
//! hold for arbitrary inputs**. The most important invariant for a parser
//! that runs on attacker-controlled data is *"never panics"* -- a single
//! reachable panic in `parse_ssh_auth_header` or `verify_dpop_proof` is a
//! denial-of-service primitive.
//!
//! Run with `cargo test --test proptest_parsers --all-features`.
//! `proptest` defaults to 256 cases per property, scaling slightly with
//! input size; adjust via the `PROPTEST_CASES` env var.

use kunobi_auth::server::ssh::{parse_authorized_key, parse_ssh_auth_header, split_header_params};
use kunobi_auth::server::{ath_for, verify_dpop_proof};
use proptest::prelude::*;
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// SSH-Signature header parser
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// `parse_ssh_auth_header` must never panic on arbitrary input. Either
    /// it returns a parsed header (when the input happens to be valid) or
    /// an `AuthError::Unauthorized` -- but never a panic.
    #[test]
    fn parse_ssh_auth_header_never_panics(s in ".{0,2048}") {
        let _ = parse_ssh_auth_header(&s);
    }

    /// Same invariant, restricted to "header-shaped" inputs that hit the
    /// quote-stripping and base64-decode paths more often. Using a
    /// targeted regex gives proptest a higher density of inputs that
    /// reach the deeper code paths than pure `.{0,N}`.
    #[test]
    fn parse_ssh_auth_header_header_shape_never_panics(
        s in r#"[a-z]+="?[A-Za-z0-9+/=,_:-]{0,200}"?(,[a-z]+="?[A-Za-z0-9+/=,_:-]{0,200}"?){0,5}"#,
    ) {
        let _ = parse_ssh_auth_header(&s);
    }

    /// `split_header_params` must always return at most `s.matches(',').count() + 1`
    /// parts, since each part is bounded by an unquoted comma. This is a
    /// loose invariant but it catches splitter bugs that produce extra
    /// parts (off-by-one when handling trailing commas, etc.).
    #[test]
    fn split_header_params_part_count_bounded(s in ".{0,512}") {
        let parts = split_header_params(&s);
        let comma_count = s.matches(',').count();
        prop_assert!(
            parts.len() <= comma_count + 1,
            "got {} parts from {} commas: {parts:?}",
            parts.len(), comma_count
        );
    }

    /// Splitter parts never contain a fully-unquoted `,`. A part *can*
    /// contain `,` if it's inside a balanced `"..."` block; outside of
    /// that, the splitter must have cut. This pins the in-quotes
    /// state-tracking from the property side.
    #[test]
    fn split_header_params_no_unquoted_comma_in_parts(s in r#"[a-zA-Z0-9=," ]{0,200}"#) {
        for part in split_header_params(&s) {
            let mut in_quotes = false;
            for ch in part.chars() {
                match ch {
                    '"' => in_quotes = !in_quotes,
                    ',' => prop_assert!(
                        in_quotes,
                        "part {part:?} contains an unquoted comma"
                    ),
                    _ => {}
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// authorized_keys parser
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// `parse_authorized_key` must never panic on arbitrary input. It can
    /// reject anything that isn't a valid Ed25519 OpenSSH key, but a panic
    /// would be a parser bug.
    #[test]
    fn parse_authorized_key_never_panics(s in ".{0,2048}") {
        let _ = parse_authorized_key(&s);
    }

    /// Inputs that *look like* an authorized_keys line (but aren't valid
    /// keys) are higher-density targets for the OpenSSH key parser.
    #[test]
    fn parse_authorized_key_ssh_shaped_never_panics(
        s in r#"ssh-(ed25519|rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]{0,500} [a-zA-Z0-9@.]{0,50}"#,
    ) {
        let _ = parse_authorized_key(&s);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DPoP proof verifier (RFC 9449)
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// `verify_dpop_proof` must never panic on arbitrary input. The DPoP
    /// proof is a JWT in a header sent by clients; a reachable panic
    /// would let an unauthenticated attacker DoS the service by
    /// crafting a malformed `DPoP:` header.
    #[test]
    fn verify_dpop_proof_never_panics(s in ".{0,2048}") {
        let _ = verify_dpop_proof(
            &s,
            "POST",
            "https://example.com/x",
            None,
            None,
            Duration::from_secs(60),
        );
    }

    /// JWT-shaped inputs (`header.payload.signature`, all base64url) hit
    /// deeper paths in the verifier than random strings.
    #[test]
    fn verify_dpop_proof_jwt_shaped_never_panics(
        h in "[A-Za-z0-9_-]{1,300}",
        p in "[A-Za-z0-9_-]{1,300}",
        s in "[A-Za-z0-9_-]{1,300}",
    ) {
        let jwt = format!("{h}.{p}.{s}");
        let _ = verify_dpop_proof(
            &jwt,
            "POST",
            "https://example.com/x",
            None,
            None,
            Duration::from_secs(60),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Determinism / idempotence properties
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// `ath_for` is a pure SHA-256 + base64url. Same input → same output,
    /// always. This is more of a "regression smoke test" than a deep
    /// property -- the value is in catching accidental dependency on
    /// global state (clock, RNG, etc.) if someone ever changes the impl.
    #[test]
    fn ath_for_deterministic(s in ".{0,512}") {
        prop_assert_eq!(ath_for(&s), ath_for(&s));
    }

    /// `ath_for` output is always 43 characters (32-byte SHA-256 in
    /// base64url-no-pad). Catches output-format regressions.
    #[test]
    fn ath_for_output_is_43_chars(s in ".{0,512}") {
        prop_assert_eq!(ath_for(&s).len(), 43);
    }
}
