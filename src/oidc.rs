use anyhow::{Context, Result};
use axum::extract::Query;
use axum::response::Html;
use axum::routing::get;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
};
use std::collections::HashMap;
use tokio::sync::oneshot;
use tracing::info;

use crate::store::StoredToken;

/// Perform browser-based OIDC login with PKCE.
///
/// 1. Discovers the OIDC provider
/// 2. Generates a PKCE challenge
/// 3. Opens the browser to the authorization URL
/// 4. Starts a localhost server to receive the callback
/// 5. Exchanges the auth code for tokens
/// 6. Returns the stored token
pub async fn browser_login(
    issuer: &str,
    client_id: &str,
    audience: Option<&str>,
    redirect_uri: &str,
) -> Result<StoredToken> {
    info!(issuer = %issuer, "Starting OIDC browser login");

    // Build an HTTP client for OIDC operations (no redirects for SSRF safety)
    let http_client = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build HTTP client")?;

    // Discover provider
    let issuer_url =
        IssuerUrl::new(issuer.to_string()).context("Invalid issuer URL")?;
    let provider_metadata =
        CoreProviderMetadata::discover_async(issuer_url, &http_client)
            .await
            .context("Failed to discover OIDC provider")?;

    // Create client
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        None, // No client secret (public client)
    )
    .set_redirect_uri(
        RedirectUrl::new(redirect_uri.to_string())
            .context("Invalid redirect URI")?,
    );

    // Generate PKCE
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Build auth URL
    let mut auth_request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()));

    if let Some(aud) = audience {
        auth_request = auth_request.add_extra_param("audience", aud);
    }

    let (auth_url, csrf_token, _nonce) = auth_request.url();

    // Start localhost callback server
    let (tx, rx) = oneshot::channel::<(String, String)>();
    let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let expected_state = csrf_token.secret().clone();
    let tx_clone = tx.clone();

    let app = axum::Router::new().route(
        "/callback",
        get(move |Query(params): Query<HashMap<String, String>>| {
            let tx = tx_clone.clone();
            let expected = expected_state.clone();
            async move {
                let code = params.get("code").cloned().unwrap_or_default();
                let state = params.get("state").cloned().unwrap_or_default();

                if state != expected {
                    return Html(
                        "<h1>Error</h1><p>Invalid state parameter.</p>"
                            .to_string(),
                    );
                }

                if let Some(sender) = tx.lock().await.take() {
                    let _ = sender.send((code, state));
                }

                Html(
                    "<h1>Authenticated!</h1><p>You can close this tab.</p>\
                     <script>window.close()</script>"
                        .to_string(),
                )
            }
        }),
    );

    // Parse port from redirect URI
    let port: u16 = redirect_uri
        .split(':')
        .next_back()
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(8329);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .context(format!("Failed to bind to port {port}"))?;

    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    // Open browser
    info!(url = %auth_url, "Opening browser for authentication");
    open::that(auth_url.to_string()).context("Failed to open browser")?;

    println!("Waiting for authentication in browser...");

    // Wait for callback
    let (code, _state) = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        rx,
    )
    .await
    .context("Login timed out after 120 seconds")?
    .context("Callback channel closed")?;

    server.abort();

    // Exchange code for tokens
    info!("Exchanging authorization code for tokens");
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await
        .context("Token exchange failed")?;

    // Extract tokens
    let id_token = token_response
        .id_token()
        .map(|t| t.to_string())
        .unwrap_or_else(|| token_response.access_token().secret().clone());

    let refresh_token = token_response.refresh_token().map(|t| t.secret().clone());

    let expires_at = token_response
        .expires_in()
        .map(|d| chrono::Utc::now().timestamp() + d.as_secs() as i64);

    Ok(StoredToken {
        id_token,
        refresh_token,
        expires_at,
        issuer: issuer.to_string(),
    })
}
