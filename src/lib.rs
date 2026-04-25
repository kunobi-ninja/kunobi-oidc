//! Authentication framework for Kunobi services.
//!
//! Handles **authn** (who are you?) — OIDC login, JWT validation, token verification.
//! AuthZ (what can you do?) is left to the consuming service.
//!
//! # Client usage (CLI, apps)
//! ```rust,no_run
//! use kunobi_auth::client::{AuthClient, ServiceConfig};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = ServiceConfig::discover("https://kobe.kunobi.ninja").await?;
//! let client = AuthClient::new(config)?;
//! let token = client.token().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Server usage (API services)
//! ```rust,no_run
//! use kunobi_auth::server::JwksManager;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let jwks = JwksManager::new();
//! let claims = jwks
//!     .validate_jwt(
//!         "eyJ...",                                       // bearer token
//!         "https://auth.example.com/.well-known/jwks.json",
//!         "https://auth.example.com",                     // issuer (required)
//!         &["https://api.example.com".to_string()],       // audience (required)
//!         &["RS256".to_string()],
//!     )
//!     .await?;
//! let _sub = claims["sub"].as_str().unwrap_or_default();
//! # Ok(()) }
//! ```
//!
//! See [`server::AuthnProvider`] / [`server::RequiredAuth`] for the recommended
//! axum integration, and [`server::ssh`] for SSH-signature verification.

pub mod common;

#[cfg(feature = "client")]
pub mod client;

pub mod server;

// Re-export common types at crate root
pub use common::{AuthError, AuthIdentity, AuthMethod, StatusResponse};
