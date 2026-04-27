#![no_main]
//! Fuzz target for `verify_dpop_proof`.
//!
//! Invariant: never panic on arbitrary input. The DPoP proof JWT comes
//! from the client's `DPoP:` header, processed before any auth check,
//! so a reachable panic is a remote-pre-auth DoS.
//!
//! Run with: cd fuzz && cargo +nightly fuzz run verify_dpop_proof

use libfuzzer_sys::fuzz_target;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = kunobi_auth::server::verify_dpop_proof(
            s,
            "POST",
            "https://example.com/api",
            None,
            None,
            Duration::from_secs(60),
        );
    }
});
