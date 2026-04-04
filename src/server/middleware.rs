use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::common::{AuthError, AuthIdentity};

/// Trait for axum state types that can authenticate requests.
///
/// Implement this on your `AppState` to wire up `RequiredAuth` / `OptionalAuth` extractors.
///
/// # Example
///
/// ```rust,no_run
/// use kunobi_auth::server::AuthnProvider;
/// use kunobi_auth::{AuthIdentity, AuthError};
///
/// #[derive(Clone)]
/// struct AppState { /* ... */ }
///
/// impl AuthnProvider for AppState {
///     async fn authenticate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
///         // Validate JWT via JwksManager, static token check, etc.
///         todo!()
///     }
/// }
/// ```
pub trait AuthnProvider: Clone + Send + Sync + 'static {
    /// Validate a bearer token and return the caller's identity.
    ///
    /// Called by the extractors after pulling the token from the `Authorization` header.
    /// Return `AuthError::Unauthorized` if the token is invalid.
    fn authenticate(
        &self,
        token: &str,
    ) -> impl std::future::Future<Output = Result<AuthIdentity, AuthError>> + Send;
}

/// Axum extractor — requires a valid Bearer token.
///
/// Returns 401 if the `Authorization` header is missing or the token is invalid.
///
/// # Usage
///
/// ```rust,ignore
/// async fn my_handler(RequiredAuth(identity): RequiredAuth) -> impl IntoResponse {
///     format!("Hello, {}", identity.identity)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RequiredAuth(pub AuthIdentity);

impl<S> FromRequestParts<S> for RequiredAuth
where
    S: AuthnProvider,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(parts)?;
        let identity = state.authenticate(token).await?;
        Ok(RequiredAuth(identity))
    }
}

/// Axum extractor — optionally authenticates if a Bearer token is present.
///
/// Returns `OptionalAuth(None)` if no `Authorization` header is present.
/// Returns 401 only if a token IS present but invalid.
///
/// # Usage
///
/// ```rust,ignore
/// async fn my_handler(OptionalAuth(maybe_identity): OptionalAuth) -> impl IntoResponse {
///     match maybe_identity {
///         Some(id) => format!("Hello, {}", id.identity),
///         None => "Hello, anonymous".to_string(),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OptionalAuth(pub Option<AuthIdentity>);

impl<S> FromRequestParts<S> for OptionalAuth
where
    S: AuthnProvider,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = match extract_bearer_token(parts) {
            Ok(token) => token,
            Err(_) => return Ok(OptionalAuth(None)),
        };
        let identity = state.authenticate(token).await?;
        Ok(OptionalAuth(Some(identity)))
    }
}

/// Extract the bearer token from the Authorization header.
fn extract_bearer_token<'a>(parts: &'a Parts) -> Result<&'a str, AuthError> {
    let header = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::Unauthorized("Missing Authorization header".into()))?;

    header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AuthError::Unauthorized("Expected Bearer token".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use std::collections::HashMap;

    /// Test state that accepts any token matching "valid-token".
    #[derive(Clone)]
    struct TestState;

    impl AuthnProvider for TestState {
        async fn authenticate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
            if token == "valid-token" {
                Ok(AuthIdentity {
                    provider: "test".to_string(),
                    identity: "user-1".to_string(),
                    method: "token".to_string(),
                    claims: HashMap::new(),
                })
            } else {
                Err(AuthError::Unauthorized("bad token".into()))
            }
        }
    }

    #[tokio::test]
    async fn required_auth_valid_token() {
        let req = Request::builder()
            .header("Authorization", "Bearer valid-token")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        let result = RequiredAuth::from_request_parts(&mut parts, &TestState).await;
        assert!(result.is_ok());
        let RequiredAuth(identity) = result.unwrap();
        assert_eq!(identity.identity, "user-1");
        assert_eq!(identity.provider, "test");
    }

    #[tokio::test]
    async fn required_auth_missing_header() {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();

        let result = RequiredAuth::from_request_parts(&mut parts, &TestState).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn required_auth_invalid_token() {
        let req = Request::builder()
            .header("Authorization", "Bearer wrong-token")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        let result = RequiredAuth::from_request_parts(&mut parts, &TestState).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn required_auth_non_bearer() {
        let req = Request::builder()
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        let result = RequiredAuth::from_request_parts(&mut parts, &TestState).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn optional_auth_valid_token() {
        let req = Request::builder()
            .header("Authorization", "Bearer valid-token")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        let result = OptionalAuth::from_request_parts(&mut parts, &TestState).await;
        assert!(result.is_ok());
        let OptionalAuth(maybe) = result.unwrap();
        assert!(maybe.is_some());
        assert_eq!(maybe.unwrap().identity, "user-1");
    }

    #[tokio::test]
    async fn optional_auth_no_header() {
        let req = Request::builder().body(()).unwrap();
        let (mut parts, _) = req.into_parts();

        let result = OptionalAuth::from_request_parts(&mut parts, &TestState).await;
        assert!(result.is_ok());
        let OptionalAuth(maybe) = result.unwrap();
        assert!(maybe.is_none());
    }

    #[tokio::test]
    async fn optional_auth_invalid_token_returns_error() {
        let req = Request::builder()
            .header("Authorization", "Bearer wrong-token")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();

        let result = OptionalAuth::from_request_parts(&mut parts, &TestState).await;
        assert!(result.is_err());
    }
}
