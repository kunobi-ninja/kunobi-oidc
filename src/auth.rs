use anyhow::Result;
use tracing::info;

use crate::config::ServiceConfig;
use crate::oidc;
use crate::store::{StoredToken, TokenStore};
use crate::token::StaticTokenAuth;

/// Token provider -- either OIDC or static token.
pub enum TokenProvider {
    Oidc(ServiceConfig),
    Static(StaticTokenAuth),
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

    /// Get a valid token. Loads from cache, refreshes if expired, or initiates login.
    pub async fn token(&self) -> Result<String> {
        match &self.provider {
            TokenProvider::Static(auth) => Ok(auth.token().to_string()),
            TokenProvider::Oidc(config) => self.oidc_token(config).await,
        }
    }

    /// Perform interactive login (always opens browser).
    pub async fn login(&self) -> Result<StoredToken> {
        match &self.provider {
            TokenProvider::Static(_) => anyhow::bail!("Cannot login with static token"),
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
            TokenProvider::Static(_) => Ok(()),
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
