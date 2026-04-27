#![no_main]
//! Fuzz target for `parse_authorized_key`.
//!
//! Invariant: never panic on arbitrary input. The parser is called on
//! provider-supplied authorized_keys data; a panic in the OpenSSH key
//! decoder would propagate through the whole verify_ssh_signature path.
//!
//! Run with: cd fuzz && cargo +nightly fuzz run parse_authorized_key

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = kunobi_auth::server::ssh::parse_authorized_key(s);
    }
});
