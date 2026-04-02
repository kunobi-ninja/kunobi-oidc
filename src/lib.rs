//! OIDC authentication library for Kunobi services.
//!
//! # Usage
//!
//! ```rust,no_run
//! use kunobi_oidc::{AuthClient, ServiceConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Discover auth config from service
//!     let config = ServiceConfig::discover("https://kobe.kunobi.ninja").await?;
//!
//!     // Get a valid token (loads cached, refreshes, or browser login)
//!     let client = AuthClient::new(config)?;
//!     let token = client.token().await?;
//!
//!     println!("Bearer {}", token);
//!     Ok(())
//! }
//! ```

mod auth;
mod config;
mod discovery;
mod oidc;
mod store;
mod token;

pub use auth::{AuthClient, TokenProvider};
pub use config::ServiceConfig;
pub use discovery::discover;
pub use store::TokenStore;
pub use token::StaticTokenAuth;
