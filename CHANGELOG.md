# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this crate adheres
to [SemVer](https://semver.org/) for the public API surface.

## [Unreleased]

## [0.2.0]

### Breaking

- `JwksManager::validate_jwt` now requires an `issuer: &str` argument (third
  positional). Previously the issuer was not bound and an empty `audience`
  silently disabled `aud` validation. Both are now required and refuse empty
  values.

### Added — security

- **OIDC**: ID-token nonce is now verified on the auth-code response. The
  generated `Nonce` was previously discarded; tokens were accepted without
  binding to the originating session. The crate now validates signature, expiry,
  audience, issuer, and nonce before persisting any token.
- **OIDC refresh-token flow** (`oidc::refresh`, wired into `AuthClient::token`).
  Cached ID tokens past their expiry are silently exchanged for a fresh token;
  only failures fall through to interactive browser login. The crate now
  requests `offline_access` scope so providers actually issue refresh tokens.
- **JWKS hardening**: forced refetch when an unknown `kid` is presented, with a
  30-second cooldown to avoid amplifying garbage `kid`s into requests against
  the IdP. Added support for PS256/384/512, EdDSA, and OKP (Ed25519) JWKs.
- **SSH-signature replay**: `NonceTracker::check_and_insert` is now atomic
  under contention. The previous implementation used a read-then-write pattern
  that could let two concurrent requests with the same nonce both pass the
  freshness check.
- **Fingerprint redaction**: SSH-signature error responses now redact key
  fingerprints (`SHA256:01234567…`); full fingerprints remain in
  `tracing::warn!` logs for forensics.
- **TOFU store**: process-local `Mutex` around `verify`/`trust` to remove TOCTOU
  between concurrent calls. Atomic write via `tempfile::persist` (write to
  sibling temp + fsync + rename). `0o600` on the file, `0o700` on
  `~/.config/kunobi/`.
- **Token store**: same atomic-write + `0o700` directory treatment.

### Added — features

- `tempfile` is now a (feature-gated) dependency under `client` for atomic
  writes.
- E2E test suite (`tests/e2e_dex.rs`) against a real Dex instance; CI runs it
  in a dedicated `e2e` job.

### Changed

- `validate_jwt` now sets `validate_exp = true` and `validate_nbf = true`.
- The OIDC client now sends both `audience` (Auth0-style) and `resource`
  (RFC 8707) parameters when an audience is configured, for cross-IdP
  compatibility.

### Fixed

- Pre-existing clippy lints (`map_or` → `is_some_and`, needless lifetime in
  `extract_bearer_token`).
- Refreshed `Cargo.lock` to clear three known advisories:
  RUSTSEC-2026-0097/0098/0099/0104 (in `rand`, `rustls-webpki`) and the yanked
  `fastrand 2.4.0`. RUSTSEC-2023-0071 (`rsa` Marvin attack) remains unpatched
  upstream and is suppressed in CI's `cargo audit`.

[Unreleased]: https://github.com/kunobi-ninja/kunobi-auth/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kunobi-ninja/kunobi-auth/releases/tag/v0.2.0
