#![no_main]
//! Fuzz target for `parse_ssh_auth_header`.
//!
//! Invariant: never panic on arbitrary bytes. The parser runs on
//! attacker-controlled `SSH-Signature` headers before any auth check,
//! so a panic here is a remote-pre-auth DoS.
//!
//! Run with: cd fuzz && cargo +nightly fuzz run parse_ssh_auth_header

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = kunobi_auth::server::ssh::parse_ssh_auth_header(s);
    }
});
