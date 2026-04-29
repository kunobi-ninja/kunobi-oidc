use serde::{Deserialize, Serialize};

/// Configuration for connecting to a Kunobi service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Service endpoint URL (e.g. "<https://kobe.kunobi.ninja>").
    pub endpoint: String,

    /// OIDC issuer URL.
    pub issuer: String,

    /// OAuth2 client ID for the CLI (public client, no secret).
    pub client_id: String,

    /// Token audience.
    #[serde(default)]
    pub audience: Option<String>,

    /// Redirect URI for the browser callback.
    #[serde(default = "default_redirect_uri")]
    pub redirect_uri: String,
}

fn default_redirect_uri() -> String {
    "http://localhost:8329/callback".to_string()
}

impl ServiceConfig {
    /// Discover auth configuration from a service endpoint.
    pub async fn discover(endpoint: &str) -> anyhow::Result<Self> {
        super::discovery::discover(endpoint).await
    }

    /// Create config manually.
    pub fn new(endpoint: &str, issuer: &str, client_id: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
            audience: None,
            redirect_uri: default_redirect_uri(),
        }
    }
}
