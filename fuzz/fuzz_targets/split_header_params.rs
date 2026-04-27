#![no_main]
//! Fuzz target for `split_header_params`.
//!
//! Invariants: never panic; returned parts never contain unquoted commas
//! at top level. The state-tracked splitter runs on every SSH-Signature
//! header parse.
//!
//! Run with: cd fuzz && cargo +nightly fuzz run split_header_params

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let parts = kunobi_auth::server::ssh::split_header_params(s);

        // Property: in each part, every `,` is inside a balanced `"..."`.
        for part in &parts {
            let mut in_quotes = false;
            for ch in part.chars() {
                match ch {
                    '"' => in_quotes = !in_quotes,
                    ',' => assert!(in_quotes, "unquoted comma in part {part:?} from input {s:?}"),
                    _ => {}
                }
            }
        }
    }
});
