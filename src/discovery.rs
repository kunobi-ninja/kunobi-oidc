use crate::config::ServiceConfig;
use serde::Deserialize;

/// Response from the service's auth discovery endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthDiscovery {
    issuer: String,
    client_id: String,
    #[serde(default)]
    audience: Option<String>,
}

/// Fetch auth configuration from a Kunobi service.
///
/// Calls `GET {endpoint}/.well-known/kunobi-auth` to discover the OIDC
/// provider and client configuration.
pub async fn discover(endpoint: &str) -> anyhow::Result<ServiceConfig> {
    let endpoint = endpoint.trim_end_matches('/');
    let url = format!("{endpoint}/.well-known/kunobi-auth");

    tracing::info!(url = %url, "Discovering auth configuration");

    let response = reqwest::get(&url).await?;
    if !response.status().is_success() {
        anyhow::bail!(
            "Auth discovery failed (HTTP {}): {}",
            response.status(),
            response.text().await.unwrap_or_default()
        );
    }

    let discovery: AuthDiscovery = response.json().await?;

    Ok(ServiceConfig {
        endpoint: endpoint.to_string(),
        issuer: discovery.issuer,
        client_id: discovery.client_id,
        audience: discovery.audience,
        redirect_uri: "http://localhost:8329/callback".to_string(),
    })
}
