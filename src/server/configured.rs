use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::common::{AuthError, AuthIdentity};
use crate::server::{AuthnProvider, JwksManager};

/// Builder for common server-side auth configuration.
///
/// This implements the usual "products declare what they accept" path:
/// JWT/OIDC/static Bearer tokens in, normalized [`AuthIdentity`] out.
#[derive(Debug, Default)]
pub struct AuthBuilder {
    jwt: Vec<JwtAuthConfig>,
    static_tokens: Vec<StaticTokenConfig>,
    validation_cache_ttl: Option<Duration>,
}

/// A ready-to-use auth provider for [`AuthLayer`](crate::server::AuthLayer)
/// and axum extractors.
#[derive(Clone)]
pub struct ConfiguredAuth {
    jwks: Arc<JwksManager>,
    jwt: Arc<Vec<JwtAuthConfig>>,
    static_tokens: Arc<Vec<StaticTokenConfig>>,
}

/// JWT validation config for one issuer/provider.
#[derive(Debug, Clone)]
pub struct JwtAuthConfig {
    pub provider: String,
    pub method: String,
    pub issuer: String,
    pub jwks_url: String,
    pub audience: Vec<String>,
    pub algorithms: Vec<String>,
    pub identity_claim: String,
}

/// Static Bearer token config.
#[derive(Clone)]
pub struct StaticTokenConfig {
    pub provider: String,
    pub token: String,
    pub identity: String,
    pub claims: HashMap<String, Value>,
}

impl AuthBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validation_cache(mut self, ttl: Duration) -> Self {
        self.validation_cache_ttl = Some(ttl);
        self
    }

    pub fn jwt(mut self, config: JwtAuthConfig) -> Self {
        self.jwt.push(config);
        self
    }

    pub fn oidc(
        self,
        provider: impl Into<String>,
        issuer: impl Into<String>,
        jwks_url: impl Into<String>,
        audience: Vec<String>,
    ) -> Self {
        self.jwt(JwtAuthConfig::oidc(provider, issuer, jwks_url, audience))
    }

    pub fn static_token(
        mut self,
        provider: impl Into<String>,
        token: impl Into<String>,
        identity: impl Into<String>,
    ) -> Self {
        self.static_tokens
            .push(StaticTokenConfig::new(provider, token, identity));
        self
    }

    pub fn build(self) -> ConfiguredAuth {
        let jwks = match self.validation_cache_ttl {
            Some(ttl) => JwksManager::new().with_validation_cache(ttl),
            None => JwksManager::new(),
        };

        ConfiguredAuth {
            jwks: Arc::new(jwks),
            jwt: Arc::new(self.jwt),
            static_tokens: Arc::new(self.static_tokens),
        }
    }
}

impl JwtAuthConfig {
    pub fn oidc(
        provider: impl Into<String>,
        issuer: impl Into<String>,
        jwks_url: impl Into<String>,
        audience: Vec<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            method: "jwt".into(),
            issuer: issuer.into(),
            jwks_url: jwks_url.into(),
            audience,
            algorithms: vec!["RS256".into()],
            identity_claim: "sub".into(),
        }
    }

    pub fn algorithms(mut self, algorithms: Vec<String>) -> Self {
        self.algorithms = algorithms;
        self
    }

    pub fn identity_claim(mut self, claim: impl Into<String>) -> Self {
        self.identity_claim = claim.into();
        self
    }

    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }
}

impl StaticTokenConfig {
    pub fn new(
        provider: impl Into<String>,
        token: impl Into<String>,
        identity: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            token: token.into(),
            identity: identity.into(),
            claims: HashMap::new(),
        }
    }

    pub fn claims(mut self, claims: HashMap<String, Value>) -> Self {
        self.claims = claims;
        self
    }
}

impl fmt::Debug for StaticTokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticTokenConfig")
            .field("provider", &self.provider)
            .field("token", &"<redacted>")
            .field("identity", &self.identity)
            .field("claims", &self.claims)
            .finish()
    }
}

impl AuthnProvider for ConfiguredAuth {
    async fn authenticate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
        for config in self.static_tokens.iter() {
            if token_matches(&config.token, token) {
                return Ok(AuthIdentity {
                    provider: config.provider.clone(),
                    identity: config.identity.clone(),
                    method: "token".into(),
                    claims: config.claims.clone(),
                });
            }
        }

        for config in self.jwt.iter() {
            if config.audience.is_empty() {
                return Err(AuthError::Internal(format!(
                    "JWT auth provider {} has no audience configured",
                    config.provider
                )));
            }

            let claims = match self
                .jwks
                .validate_jwt(
                    token,
                    &config.jwks_url,
                    &config.issuer,
                    &config.audience,
                    &config.algorithms,
                )
                .await
            {
                Ok(claims) => claims,
                Err(_) => continue,
            };

            let identity = claims
                .get(&config.identity_claim)
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AuthError::Unauthorized(format!(
                        "JWT missing string identity claim {}",
                        config.identity_claim
                    ))
                })?
                .to_string();

            return Ok(AuthIdentity {
                provider: config.provider.clone(),
                identity,
                method: config.method.clone(),
                claims,
            });
        }

        Err(AuthError::Unauthorized("invalid bearer token".into()))
    }
}

fn token_matches(expected: &str, presented: &str) -> bool {
    if expected.len() != presented.len() {
        return false;
    }

    expected
        .as_bytes()
        .iter()
        .zip(presented.as_bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_config_sets_default_jwt_fields() {
        let config = JwtAuthConfig::oidc(
            "firebase",
            "https://securetoken.google.com/my-project",
            "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com",
            vec!["my-project".into()],
        );
        assert_eq!(config.provider, "firebase");
        assert_eq!(config.method, "jwt");
        assert_eq!(config.audience, vec!["my-project"]);
        assert_eq!(config.algorithms, vec!["RS256"]);
        assert_eq!(config.identity_claim, "sub");
    }

    #[tokio::test]
    async fn configured_auth_accepts_static_token() {
        let auth = AuthBuilder::new()
            .static_token("dev-token", "secret", "dev-user")
            .build();

        let identity = auth.authenticate("secret").await.unwrap();
        assert_eq!(identity.provider, "dev-token");
        assert_eq!(identity.identity, "dev-user");
        assert_eq!(identity.method, "token");
    }

    #[tokio::test]
    async fn configured_auth_rejects_unknown_token() {
        let auth = AuthBuilder::new()
            .static_token("dev-token", "secret", "dev-user")
            .build();

        let err = auth.authenticate("wrong").await.unwrap_err();
        assert!(matches!(err, AuthError::Unauthorized(_)));
    }

    #[test]
    fn static_token_debug_redacts_secret() {
        let config = StaticTokenConfig::new("dev-token", "super-secret", "dev-user");
        let rendered = format!("{config:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("super-secret"));
    }

    #[test]
    fn token_match_rejects_different_values() {
        assert!(token_matches("secret", "secret"));
        assert!(!token_matches("secret", "secrex"));
        assert!(!token_matches("secret", "secret-extra"));
    }
}
