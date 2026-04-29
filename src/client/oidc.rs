use anyhow::{Context, Result};
use axum::extract::Query;
use axum::response::Html;
use axum::routing::get;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, RedirectUrl, RefreshToken, Scope, TokenResponse,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tracing::{info, warn};

use super::store::StoredToken;

fn build_http_client() -> Result<openidconnect::reqwest::Client> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build HTTP client")
}

/// Perform browser-based OIDC login with PKCE.
///
/// 1. Discovers the OIDC provider
/// 2. Generates a PKCE challenge + nonce
/// 3. Opens the browser to the authorization URL
/// 4. Starts a localhost server to receive the callback
/// 5. Exchanges the auth code for tokens
/// 6. Validates the ID token (signature, expiry, aud, iss, nonce)
/// 7. Returns the stored token
pub async fn browser_login(
    issuer: &str,
    client_id: &str,
    audience: Option<&str>,
    redirect_uri: &str,
) -> Result<StoredToken> {
    info!(issuer = %issuer, "Starting OIDC browser login");

    let http_client = build_http_client()?;

    let issuer_url = IssuerUrl::new(issuer.to_string()).context("Invalid issuer URL")?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .context("Failed to discover OIDC provider")?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        None, // public client (PKCE)
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).context("Invalid redirect URI")?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the nonce up-front so we can verify it on the returned ID token.
    let nonce = Nonce::new_random();
    let nonce_for_check = nonce.clone();

    let mut auth_request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            move || nonce.clone(),
        )
        .set_pkce_challenge(pkce_challenge)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("offline_access".to_string()));

    if let Some(aud) = audience {
        // Send both the RFC 8707 `resource` and the Auth0-style `audience`
        // parameter so different IdPs all bind a token to this audience.
        auth_request = auth_request
            .add_extra_param("audience", aud)
            .add_extra_param("resource", aud);
    }

    let (auth_url, csrf_token, _nonce) = auth_request.url();

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
                    return Html("<h1>Error</h1><p>Invalid state parameter.</p>".to_string());
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

    let port: u16 = redirect_uri
        .split(':')
        .next_back()
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(8329);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .with_context(|| {
            format!(
                "Failed to bind to port {port} (already in use?). Adjust ServiceConfig.redirect_uri or free the port."
            )
        })?;

    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    info!(url = %auth_url, "Opening browser for authentication");
    open::that(auth_url.to_string()).context("Failed to open browser")?;

    println!("Waiting for authentication in browser...");

    let (code, _state) = tokio::time::timeout(std::time::Duration::from_secs(120), rx)
        .await
        .context("Login timed out after 120 seconds")?
        .context("Callback channel closed")?;

    server.abort();

    info!("Exchanging authorization code for tokens");
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await
        .context("Token exchange failed")?;

    let id_token = token_response
        .id_token()
        .context("OIDC token response did not contain an id_token")?;

    let claims = id_token
        .claims(&client.id_token_verifier(), &nonce_for_check)
        .context("ID token validation failed (signature/expiry/aud/iss/nonce)")?;

    let claim_issuer = claims.issuer().to_string();
    if claim_issuer != issuer {
        warn!(
            expected = %issuer,
            actual = %claim_issuer,
            "ID token issuer differs from configured issuer (using validated claim)"
        );
    }

    let id_token_str = id_token.to_string();
    let refresh_token = token_response.refresh_token().map(|t| t.secret().clone());
    let expires_at = Some(claims.expiration().timestamp());

    Ok(StoredToken {
        id_token: id_token_str,
        refresh_token,
        expires_at,
        issuer: claim_issuer,
    })
}

/// Refresh an OIDC session using the stored refresh token.
pub async fn refresh(
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
    refresh_token: &str,
) -> Result<StoredToken> {
    info!(issuer = %issuer, "Refreshing OIDC token");

    let http_client = build_http_client()?;

    let issuer_url = IssuerUrl::new(issuer.to_string()).context("Invalid issuer URL")?;
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .context("Failed to discover OIDC provider")?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        None,
    )
    .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string()).context("Invalid redirect URI")?);

    let response = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))?
        .request_async(&http_client)
        .await
        .context("Refresh-token exchange failed")?;

    let id_token = response
        .id_token()
        .context("Refresh-token response did not contain an id_token")?;

    // Refresh responses don't carry a nonce; signature/expiry/aud/iss still
    // validated.
    let claims = id_token
        .claims(&client.id_token_verifier(), |_: Option<&Nonce>| Ok(()))
        .context("Refreshed ID token validation failed")?;

    let claim_issuer = claims.issuer().to_string();
    let id_token_str = id_token.to_string();
    let new_refresh = response.refresh_token().map(|t| t.secret().clone());
    let expires_at = Some(claims.expiration().timestamp());

    Ok(StoredToken {
        id_token: id_token_str,
        refresh_token: new_refresh.or_else(|| Some(refresh_token.to_string())),
        expires_at,
        issuer: claim_issuer,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Token revocation (RFC 7009) and introspection (RFC 7662).
//
// Revocation closes the leaked-laptop window: today logout() just removes the
// local file, the token stays valid at the IdP until expiry. Introspection
// lets us support opaque (non-JWT) tokens or check "is this token still
// valid right now" at the IdP. Both endpoints are advertised in the OIDC
// discovery doc; we discover them on demand.
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RevocationDiscovery {
    issuer: String,
    revocation_endpoint: Option<String>,
    introspection_endpoint: Option<String>,
}

/// What kind of token we're acting on (RFC 7009/7662 `token_type_hint`).
/// Most IdPs accept either hint and figure it out; some require it.
#[derive(Debug, Clone, Copy)]
pub enum TokenKind {
    /// `access_token` -- the bearer the API consumes.
    Access,
    /// `refresh_token` -- exchange-for-new-access.
    Refresh,
}

impl TokenKind {
    fn hint(self) -> &'static str {
        match self {
            TokenKind::Access => "access_token",
            TokenKind::Refresh => "refresh_token",
        }
    }
}

/// Revoke a token at the OIDC provider (RFC 7009).
///
/// Looks up the `revocation_endpoint` from the issuer's discovery doc and
/// POSTs the token there. On success the token is invalidated server-side.
/// Idempotent and silent on tokens that are already invalid.
///
/// Per RFC 7009 §2.2 the server SHOULD also revoke any related tokens
/// (e.g. revoking a refresh token revokes the access tokens it spawned).
pub async fn revoke(issuer: &str, client_id: &str, token: &str, kind: TokenKind) -> Result<()> {
    let endpoint = revocation_endpoint(issuer).await?.with_context(|| {
        format!("OIDC issuer {issuer} does not advertise a revocation_endpoint")
    })?;

    let http = build_basic_http()?;
    let resp = http
        .post(&endpoint)
        .form(&[
            ("token", token),
            ("token_type_hint", kind.hint()),
            ("client_id", client_id),
        ])
        .send()
        .await
        .context("revocation request failed")?;

    let status = resp.status();
    if !status.is_success() {
        // RFC 7009 §2.2: 200 OK is the only success code. Some IdPs return
        // 200 even for unknown tokens (intentionally indistinguishable), so
        // any non-2xx is a real error.
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("revocation endpoint returned {status}: {body}");
    }
    info!(issuer = %issuer, kind = ?kind, "token revoked at IdP");
    Ok(())
}

/// Result of an RFC 7662 token introspection. The fields mirror the wire
/// format; consumers should check `active` first -- when false, every other
/// field MUST be ignored per the RFC.
#[derive(Debug, Clone, Deserialize)]
pub struct IntrospectionResult {
    /// The only field that's authoritative when present. If false, the token
    /// is invalid (revoked, expired, never issued); other fields meaningless.
    pub active: bool,
    /// Space-separated scopes the token was issued for, if active.
    pub scope: Option<String>,
    /// `client_id` of the OAuth2 client to which the token was issued.
    pub client_id: Option<String>,
    /// Human-readable username, if the IdP exposes one.
    pub username: Option<String>,
    /// Hint at the token's type (e.g. `Bearer`).
    pub token_type: Option<String>,
    /// Expiration as Unix epoch seconds.
    pub exp: Option<i64>,
    /// Issued-at as Unix epoch seconds.
    pub iat: Option<i64>,
    /// Subject identifier (the `sub` claim equivalent for opaque tokens).
    pub sub: Option<String>,
    /// Audience the token was issued for.
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
    /// Issuer URL.
    pub iss: Option<String>,
    /// JWT ID, if present.
    pub jti: Option<String>,
}

/// Ask the IdP whether `token` is still valid (RFC 7662).
///
/// Useful for opaque tokens (where local JWT validation isn't possible) or
/// when you need a fresh "is this revoked right now" check that bypasses
/// any client- or server-side validation cache.
pub async fn introspect(
    issuer: &str,
    client_id: &str,
    token: &str,
    kind: TokenKind,
) -> Result<IntrospectionResult> {
    let endpoint = introspection_endpoint(issuer).await?.with_context(|| {
        format!("OIDC issuer {issuer} does not advertise an introspection_endpoint")
    })?;

    let http = build_basic_http()?;
    let resp = http
        .post(&endpoint)
        .form(&[
            ("token", token),
            ("token_type_hint", kind.hint()),
            ("client_id", client_id),
        ])
        .send()
        .await
        .context("introspection request failed")?;

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("introspection endpoint returned {status}: {text}");
    }
    serde_json::from_str(&text).with_context(|| format!("bad introspection JSON: {text}"))
}

async fn revocation_endpoint(issuer: &str) -> Result<Option<String>> {
    Ok(fetch_revocation_disco(issuer).await?.revocation_endpoint)
}

async fn introspection_endpoint(issuer: &str) -> Result<Option<String>> {
    Ok(fetch_revocation_disco(issuer).await?.introspection_endpoint)
}

async fn fetch_revocation_disco(issuer: &str) -> Result<RevocationDiscovery> {
    let well_known = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let resp = build_basic_http()?
        .get(&well_known)
        .send()
        .await
        .with_context(|| format!("fetching {well_known}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("OIDC discovery {well_known} returned {}", resp.status());
    }
    let doc: RevocationDiscovery = resp
        .json()
        .await
        .with_context(|| format!("parsing {well_known}"))?;
    ensure_discovery_issuer_matches(issuer, &doc.issuer)?;
    Ok(doc)
}

fn build_basic_http() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build http client")
}
// ──────────────────────────────────────────────────────────────────────────────
// Device Authorization Grant (RFC 8628)
//
// For headless principals (Kubernetes operators, CI workers, TVs) that have no
// browser. The device displays a verification URL + user code to a human, who
// completes the authorization on a separate device. The device polls the token
// endpoint until the user finishes.
// ──────────────────────────────────────────────────────────────────────────────

/// What the user needs to do to complete a device-flow login. Surfaced by
/// [`DeviceFlowHandle`] before [`DeviceFlowHandle::poll`] starts.
#[derive(Debug, Clone)]
pub struct DeviceFlowPrompt {
    /// URL the user should visit on a browser-equipped device.
    pub verification_uri: String,
    /// Combined URL with the user code embedded, when the IdP provides one.
    /// Some IdPs (Auth0, Keycloak) return this as `verification_uri_complete`.
    pub verification_uri_complete: Option<String>,
    /// Short code the user types into the verification page.
    pub user_code: String,
    /// How long the device-code stays valid before the flow must be restarted.
    pub expires_in: Duration,
}

/// Live device-flow session. Hold this, show the prompt to the user, then
/// call [`Self::poll`] to wait for the user to authorize and receive tokens.
pub struct DeviceFlowHandle {
    /// User-facing prompt. Display this *before* polling.
    pub prompt: DeviceFlowPrompt,
    issuer: String,
    token_endpoint: String,
    jwks_uri: String,
    client_id: String,
    device_code: String,
    interval: Duration,
    expires_at: Instant,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct DiscoveryDoc {
    issuer: String,
    token_endpoint: String,
    jwks_uri: String,
    /// Not in core OIDC; defined by RFC 8414 / RFC 8628.
    device_authorization_endpoint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    /// Server-recommended polling interval in seconds. Default 5 per RFC 8628.
    interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenResponse {
    id_token: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenError {
    error: String,
}

/// Start an RFC 8628 Device Authorization flow.
///
/// Discovers the device-authorization endpoint via the OIDC discovery
/// document, requests a `device_code`, and returns a [`DeviceFlowHandle`]
/// whose `prompt` field tells the caller what to display. Once the user has
/// authorized in their browser, call [`DeviceFlowHandle::poll`] to receive
/// the tokens.
///
/// The IdP must publish `device_authorization_endpoint` in its
/// `.well-known/openid-configuration` (Auth0, Keycloak ≥ 8, Dex ≥ 2.36,
/// Okta, Google). For IdPs that don't, see [`begin_device_flow_with_url`].
pub async fn begin_device_flow(
    issuer: &str,
    client_id: &str,
    audience: Option<&str>,
    scope: &str,
) -> Result<DeviceFlowHandle> {
    let discovery = fetch_discovery(issuer).await?;
    let device_endpoint = discovery
        .device_authorization_endpoint
        .as_deref()
        .with_context(|| {
            format!(
                "OIDC issuer {issuer} does not advertise a device_authorization_endpoint; \
                 use begin_device_flow_with_url() to provide it explicitly"
            )
        })?
        .to_string();
    begin_device_flow_with_url(
        issuer,
        &device_endpoint,
        &discovery.token_endpoint,
        &discovery.jwks_uri,
        client_id,
        audience,
        scope,
    )
    .await
}

/// Like [`begin_device_flow`] but with explicit endpoints, for IdPs that
/// don't publish `device_authorization_endpoint` in their discovery doc.
pub async fn begin_device_flow_with_url(
    issuer: &str,
    device_endpoint: &str,
    token_endpoint: &str,
    jwks_uri: &str,
    client_id: &str,
    audience: Option<&str>,
    scope: &str,
) -> Result<DeviceFlowHandle> {
    info!(issuer = %issuer, "Starting OIDC device authorization flow");

    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build HTTP client")?;

    // RFC 8628 §3.1: POST client_id + scope (+ optional audience/resource).
    let mut form: Vec<(&str, &str)> = vec![("client_id", client_id), ("scope", scope)];
    if let Some(aud) = audience {
        form.push(("audience", aud));
        form.push(("resource", aud));
    }

    let resp = http
        .post(device_endpoint)
        .form(&form)
        .send()
        .await
        .context("Device-authorization request failed")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("Device-authorization request returned {status}: {text}");
    }
    let auth: DeviceAuthorizationResponse =
        serde_json::from_str(&text).with_context(|| format!("bad device-auth JSON: {text}"))?;

    // Clamp the server-supplied poll interval. RFC 8628 §3.2 recommends 5s
    // as the default; some IdPs misbehave (return 0, return very large
    // numbers, etc.). 5s..=60s keeps us well-behaved under both a misconfigured
    // IdP that wants tight polling (which would DoS them) and one that wants
    // glacial polling (which would make the user wait forever).
    let server_interval = auth.interval.unwrap_or(5);
    let interval = Duration::from_secs(server_interval.clamp(5, 60));
    let expires_at = Instant::now() + Duration::from_secs(auth.expires_in);

    Ok(DeviceFlowHandle {
        prompt: DeviceFlowPrompt {
            verification_uri: auth.verification_uri,
            verification_uri_complete: auth.verification_uri_complete,
            user_code: auth.user_code,
            expires_in: Duration::from_secs(auth.expires_in),
        },
        issuer: issuer.to_string(),
        token_endpoint: token_endpoint.to_string(),
        jwks_uri: jwks_uri.to_string(),
        client_id: client_id.to_string(),
        device_code: auth.device_code,
        interval,
        expires_at,
        http,
    })
}

impl DeviceFlowHandle {
    /// Poll the token endpoint until the user authorizes (returns tokens) or
    /// the device code expires (returns Err).
    ///
    /// Honours RFC 8628 §3.5: backs off on `slow_down`, retries on
    /// `authorization_pending`, surfaces all other errors immediately.
    /// Validates the resulting ID token against the IdP's JWKS.
    pub async fn poll(self) -> Result<StoredToken> {
        let mut interval = self.interval;
        loop {
            if Instant::now() >= self.expires_at {
                anyhow::bail!("Device authorization expired before user completed login");
            }

            tokio::time::sleep(interval).await;

            let resp = self
                .http
                .post(&self.token_endpoint)
                .form(&[
                    ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                    ("device_code", &self.device_code),
                    ("client_id", &self.client_id),
                ])
                .send()
                .await
                .context("Device token request failed")?;

            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();

            if status.is_success() {
                let body: DeviceTokenResponse = serde_json::from_str(&text)
                    .with_context(|| format!("bad token JSON: {text}"))?;
                return finalize_device_token(body, &self.issuer, &self.jwks_uri, &self.client_id)
                    .await;
            }

            // RFC 8628 §3.5: token endpoint returns 400 with one of these
            // OAuth2 error codes during the wait.
            let err: DeviceTokenError = match serde_json::from_str(&text) {
                Ok(e) => e,
                Err(_) => anyhow::bail!("Device token endpoint returned {status}: {text}"),
            };
            match err.error.as_str() {
                "authorization_pending" => continue,
                "slow_down" => {
                    interval += Duration::from_secs(5);
                    info!(
                        ?interval,
                        "device flow: slow_down, increasing poll interval"
                    );
                    continue;
                }
                "expired_token" => anyhow::bail!("Device code expired before user completed login"),
                "access_denied" => anyhow::bail!("User denied the device authorization request"),
                other => anyhow::bail!("Device token endpoint returned error: {other} -- {text}"),
            }
        }
    }
}

async fn finalize_device_token(
    body: DeviceTokenResponse,
    issuer: &str,
    jwks_uri: &str,
    client_id: &str,
) -> Result<StoredToken> {
    let id_token = body
        .id_token
        .or(body.access_token)
        .context("Device token response had neither id_token nor access_token")?;

    // Validate the ID token via JwksManager (signature, exp, aud=client_id, iss).
    // Device flow does not carry a nonce, so we don't check one.
    let jwks = crate::server::JwksManager::new();
    let claims = jwks
        .validate_jwt(
            &id_token,
            jwks_uri,
            issuer,
            &[client_id.to_string()],
            &["RS256".to_string()],
        )
        .await
        .context("Device-flow ID token validation failed")?;

    let claim_issuer = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or(issuer)
        .to_string();
    if claim_issuer != issuer {
        warn!(
            expected = %issuer,
            actual = %claim_issuer,
            "Device-flow ID token issuer differs from configured issuer (using validated claim)"
        );
    }

    let expires_at = claims.get("exp").and_then(|v| v.as_i64()).or_else(|| {
        body.expires_in
            .map(|s| chrono::Utc::now().timestamp() + s as i64)
    });

    Ok(StoredToken {
        id_token,
        refresh_token: body.refresh_token,
        expires_at,
        issuer: claim_issuer,
    })
}

async fn fetch_discovery(issuer: &str) -> Result<DiscoveryDoc> {
    let well_known = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let resp = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build http client")?
        .get(&well_known)
        .send()
        .await
        .with_context(|| format!("fetching {well_known}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("OIDC discovery {well_known} returned {}", resp.status());
    }
    let doc: DiscoveryDoc = resp
        .json()
        .await
        .with_context(|| format!("parsing {well_known}"))?;
    ensure_discovery_issuer_matches(issuer, &doc.issuer)?;
    Ok(doc)
}

fn ensure_discovery_issuer_matches(configured: &str, advertised: &str) -> Result<()> {
    if advertised != configured {
        anyhow::bail!(
            "OIDC discovery issuer mismatch: configured {configured}, advertised {advertised}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_issuer_match_accepts_exact_value() {
        ensure_discovery_issuer_matches("https://issuer.example.com", "https://issuer.example.com")
            .unwrap();
    }

    #[test]
    fn discovery_issuer_match_rejects_mismatch() {
        let err = ensure_discovery_issuer_matches(
            "https://issuer.example.com",
            "https://attacker.example.com",
        )
        .unwrap_err();
        assert!(err.to_string().contains("issuer mismatch"));
    }
}
