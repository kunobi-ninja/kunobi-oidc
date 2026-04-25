mod config;
mod discovery;
mod oidc;
pub mod ssh;
mod store;
pub mod tofu;
mod token;

pub use config::ServiceConfig;
pub use discovery::discover;
pub use ssh::{SshAgentAuth, SshKeyInfo};
pub use store::{StoredToken, TokenStore};
pub use tofu::{TofuResult, TofuStore};
pub use token::StaticTokenAuth;

use anyhow::Result;
use tracing::info;

/// Token provider -- either OIDC, static token, or SSH key.
pub enum TokenProvider {
    Oidc(ServiceConfig),
    Static(StaticTokenAuth),
    Ssh(SshAgentAuth),
}

/// Main authentication client.
///
/// Handles token lifecycle: load cached -> refresh if expired -> browser login if needed.
pub struct AuthClient {
    provider: TokenProvider,
    store: TokenStore,
}

impl AuthClient {
    /// Create a new auth client with OIDC provider.
    pub fn new(config: ServiceConfig) -> Result<Self> {
        Ok(Self {
            provider: TokenProvider::Oidc(config),
            store: TokenStore::new()?,
        })
    }

    /// Create a new auth client with a static token.
    pub fn with_static_token(token: String) -> Result<Self> {
        Ok(Self {
            provider: TokenProvider::Static(StaticTokenAuth::new(token)),
            store: TokenStore::new()?,
        })
    }

    /// Create a new auth client that signs requests with an SSH key.
    ///
    /// If `fingerprint` is `Some`, the loaded key must match that fingerprint.
    /// If `None`, `~/.ssh/id_ed25519` is used without fingerprint validation.
    pub fn with_ssh(fingerprint: Option<String>) -> Result<Self> {
        Ok(Self {
            provider: TokenProvider::Ssh(SshAgentAuth::new(fingerprint)),
            store: TokenStore::new()?,
        })
    }

    /// Get a valid token. Loads from cache, refreshes if expired, or initiates login.
    pub async fn token(&self) -> Result<String> {
        match &self.provider {
            TokenProvider::Static(auth) => Ok(auth.token().to_string()),
            TokenProvider::Oidc(config) => self.oidc_token(config).await,
            TokenProvider::Ssh(_) => {
                anyhow::bail!("SSH provider does not issue bearer tokens — use authorize() instead")
            }
        }
    }

    /// Produce an HTTP `Authorization` header value for a request.
    ///
    /// - OIDC / Static → `"Bearer <token>"`
    /// - SSH           → `"SSH-Signature fingerprint=…,timestamp=…,nonce=…,signature=…"`
    pub async fn authorize(
        &self,
        namespace: &str,
        method: &str,
        path_with_query: &str,
        body: &[u8],
    ) -> Result<String> {
        match &self.provider {
            TokenProvider::Static(auth) => Ok(format!("Bearer {}", auth.token())),
            TokenProvider::Oidc(config) => {
                let token = self.oidc_token(config).await?;
                Ok(format!("Bearer {token}"))
            }
            TokenProvider::Ssh(ssh) => ssh.authorize(namespace, method, path_with_query, body),
        }
    }

    /// Perform interactive login (always opens browser).
    pub async fn login(&self) -> Result<StoredToken> {
        match &self.provider {
            TokenProvider::Static(_) => anyhow::bail!("Cannot login with static token"),
            TokenProvider::Ssh(_) => anyhow::bail!("Cannot login with SSH provider"),
            TokenProvider::Oidc(config) => {
                let token = oidc::browser_login(
                    &config.issuer,
                    &config.client_id,
                    config.audience.as_deref(),
                    &config.redirect_uri,
                )
                .await?;
                self.store.save(&token)?;
                info!("Login successful, token stored");
                Ok(token)
            }
        }
    }

    /// Remove stored tokens.
    pub fn logout(&self) -> Result<()> {
        match &self.provider {
            TokenProvider::Static(_) | TokenProvider::Ssh(_) => Ok(()),
            TokenProvider::Oidc(config) => {
                self.store.remove(&config.issuer)?;
                info!("Logged out, token removed");
                Ok(())
            }
        }
    }

    async fn oidc_token(&self, config: &ServiceConfig) -> Result<String> {
        // Try cached token
        if let Some(stored) = self.store.load(&config.issuer)? {
            if !stored.is_expired() {
                return Ok(stored.id_token);
            }
            info!("Token expired, need to re-authenticate");
            // TODO: implement refresh token flow
        }

        // No valid cached token -- interactive login
        let token = self.login().await?;
        Ok(token.id_token)
    }
}
