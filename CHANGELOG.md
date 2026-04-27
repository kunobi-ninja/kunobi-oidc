# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this crate adheres
to [SemVer](https://semver.org/) for the public API surface.

## [Unreleased]

## [0.3.0]

### Added — client

- **Per-shell CLI session state** (`client::session`, [#8]) — parent-PID-keyed
  state for any Kunobi CLI that needs an "active target" / "active context"
  per terminal window. Different shells get independent state without env-var
  plumbing or shell hooks. Stale files are GC'd automatically when their owning
  PID exits. Generic over any `Serialize + DeserializeOwned`, namespaced per
  product so kobe and (future) kunobi-sync don't collide on PID keys.
  Cross-platform via `sysinfo`.
- **RFC 8628 Device Authorization Grant** (`AuthClient::device_login`, [#9]) —
  for headless/SSH/CI sessions where a local browser can't open. The CLI
  prints a verification URL + user code; the user authorizes on any
  browser-equipped device while the client polls.
- **RFC 7009 token revocation** (`oidc::revoke`, `AuthClient::logout_async`,
  [#10]) — logout now revokes refresh + access tokens at the IdP, not just
  deletes them locally. Closes the leaked-laptop window.
- **RFC 7662 token introspection** (`oidc::introspect`,
  `AuthClient::introspect`, [#10]) — fresh "is this revoked right now"
  validation that bypasses the local JWKS cache; useful for opaque tokens or
  high-value ops.

### Added — server

- **`tower::Layer` integration** for `AuthnProvider` ([#11]) —
  `server::AuthLayer<P>` drops straight into an axum/tower middleware stack
  without per-route extractor wiring. Existing `OptionalAuth` extractor pattern
  is unchanged and remains supported.
- **Per-token validated-claims cache** (`JwksManager::with_validation_cache`,
  [#12]) — opt-in LRU cache keyed by token + audience that skips re-validation
  of recently-seen JWTs. Bounded by both size and time-to-live; safe to enable
  on high-RPS surfaces with low token diversity.
- **RFC 9449 DPoP proof verification** (`server::dpop`, [#13]) — token-binding
  to a specific HTTP request via DPoP-proof JWT. Anti-replay measure for
  bearer-token flows.

### Internal

- E2E CI job hardened against missing host build tools (separate runner image
  + `build-essential` install on the bare runner where applicable). No surface
  change.

[#8]: https://github.com/kunobi-ninja/kunobi-auth/pull/8
[#9]: https://github.com/kunobi-ninja/kunobi-auth/pull/9
[#10]: https://github.com/kunobi-ninja/kunobi-auth/pull/10
[#11]: https://github.com/kunobi-ninja/kunobi-auth/pull/11
[#12]: https://github.com/kunobi-ninja/kunobi-auth/pull/12
[#13]: https://github.com/kunobi-ninja/kunobi-auth/pull/13

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
