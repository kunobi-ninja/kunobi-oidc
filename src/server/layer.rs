//! Tower [`Layer`] integration for [`AuthnProvider`].
//!
//! The [`RequiredAuth`](crate::server::RequiredAuth) /
//! [`OptionalAuth`](crate::server::OptionalAuth) extractors require every
//! handler to declare the extractor in its signature, and the application
//! state to implement [`AuthnProvider`]. That works but doesn't compose well
//! with other tower middleware and forces handlers to know about auth even
//! when the only thing they want is "this route requires auth, give me the
//! identity if any."
//!
//! [`AuthLayer`] wraps an [`AuthnProvider`] as a `tower::Layer`. Apply it to
//! a `Router` (or a sub-router) and:
//!
//! - The `Authorization: Bearer <token>` header is extracted and validated.
//! - On success, the resulting [`AuthIdentity`](crate::AuthIdentity) is inserted into the request
//!   extensions. Handlers retrieve it with `Extension<AuthIdentity>`.
//! - On failure (or missing header in `required` mode), a 401 / 4xx
//!   [`AuthError`] response is returned without ever invoking the handler.
//!
//! ```rust,no_run
//! use kunobi_auth::server::{AuthLayer, AuthnProvider, JwksManager};
//! use kunobi_auth::{AuthIdentity, AuthError};
//! use axum::{routing::get, Router, Extension};
//! use std::sync::Arc;
//!
//! #[derive(Clone)]
//! struct MyAuth { jwks: Arc<JwksManager>, issuer: String, audience: Vec<String>, jwks_url: String }
//!
//! impl AuthnProvider for MyAuth {
//!     async fn authenticate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
//!         let claims = self.jwks
//!             .validate_jwt(token, &self.jwks_url, &self.issuer, &self.audience, &["RS256".into()])
//!             .await
//!             .map_err(|e| AuthError::Unauthorized(e.to_string()))?;
//!         Ok(AuthIdentity {
//!             provider: "oidc".into(),
//!             identity: claims["sub"].as_str().unwrap_or_default().into(),
//!             method: "jwt".into(),
//!             claims,
//!         })
//!     }
//! }
//!
//! async fn me(Extension(id): Extension<AuthIdentity>) -> String {
//!     format!("Hello, {}", id.identity)
//! }
//!
//! # fn _build(auth: MyAuth) -> Router {
//! Router::new()
//!     .route("/me", get(me))
//!     .layer(AuthLayer::required(auth))
//! # }
//! ```

use axum::body::Body;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use crate::common::AuthError;
use crate::server::middleware::AuthnProvider;

/// Tower [`Layer`] that authenticates requests via an [`AuthnProvider`] and
/// inserts the resulting identity into request extensions.
///
/// Use [`AuthLayer::required`] to reject unauthenticated requests with 401, or
/// [`AuthLayer::optional`] to let them through with no identity attached.
#[derive(Clone, Debug)]
pub struct AuthLayer<P> {
    provider: P,
    mode: Mode,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Required,
    Optional,
}

impl<P> AuthLayer<P> {
    /// Reject requests without a valid `Authorization: Bearer …` header (401).
    pub fn required(provider: P) -> Self {
        Self {
            provider,
            mode: Mode::Required,
        }
    }

    /// Pass requests through without authentication when no `Authorization`
    /// header is present. A *bad* token still produces a 401.
    pub fn optional(provider: P) -> Self {
        Self {
            provider,
            mode: Mode::Optional,
        }
    }
}

impl<S, P> Layer<S> for AuthLayer<P>
where
    P: AuthnProvider,
{
    type Service = AuthService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            provider: self.provider.clone(),
            mode: self.mode,
        }
    }
}

/// The [`Service`] produced by [`AuthLayer`]. Public so it can name itself in
/// generic bounds, but most consumers should use [`AuthLayer`] directly.
#[derive(Clone)]
pub struct AuthService<S, P> {
    inner: S,
    provider: P,
    mode: Mode,
}

impl<S, P> Service<Request<Body>> for AuthService<S, P>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    P: AuthnProvider,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        // Per the tower contract: clone the inner service into a ready copy
        // we own, leaving the freshly-not-ready clone in `self`. This is the
        // standard pattern for middleware that must own the service across
        // the await point.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let provider = self.provider.clone();
        let mode = self.mode;

        Box::pin(async move {
            let token = extract_bearer(&req);

            match (token, mode) {
                (Some(t), _) => match provider.authenticate(t).await {
                    Ok(identity) => {
                        req.extensions_mut().insert(identity);
                    }
                    Err(e) => return Ok(e.into_response()),
                },
                (None, Mode::Required) => {
                    return Ok(
                        AuthError::Unauthorized("Missing Authorization header".into())
                            .into_response(),
                    );
                }
                (None, Mode::Optional) => {
                    // No header, optional mode: pass through with no identity.
                }
            }

            inner.call(req).await
        })
    }
}

/// Reads the first `Authorization` header. See `middleware::extract_bearer_token`
/// for the reasoning -- multiple `Authorization` headers are forbidden by
/// RFC 7230 §3.2.2; we don't try to merge them.
fn extract_bearer<B>(req: &Request<B>) -> Option<&str> {
    req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{AuthError, AuthIdentity};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::{Extension, Router};
    use std::collections::HashMap;
    use tower::ServiceExt;

    /// Test provider that accepts only "valid-token".
    #[derive(Clone)]
    struct TestAuth;

    impl AuthnProvider for TestAuth {
        async fn authenticate(&self, token: &str) -> Result<AuthIdentity, AuthError> {
            if token == "valid-token" {
                Ok(AuthIdentity {
                    provider: "test".into(),
                    identity: "user-1".into(),
                    method: "token".into(),
                    claims: HashMap::new(),
                })
            } else {
                Err(AuthError::Unauthorized("bad token".into()))
            }
        }
    }

    async fn me_handler(Extension(id): Extension<AuthIdentity>) -> String {
        format!("hi {}", id.identity)
    }

    fn required_app() -> Router {
        Router::new()
            .route("/me", get(me_handler))
            .layer(AuthLayer::required(TestAuth))
    }

    fn optional_app() -> Router {
        async fn maybe(id: Option<Extension<AuthIdentity>>) -> String {
            match id {
                Some(Extension(i)) => format!("hi {}", i.identity),
                None => "anon".into(),
            }
        }
        Router::new()
            .route("/me", get(maybe))
            .layer(AuthLayer::optional(TestAuth))
    }

    #[tokio::test]
    async fn required_layer_passes_with_valid_token() {
        let app = required_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/me")
                    .header("authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn required_layer_401_without_header() {
        let app = required_app();
        let resp = app
            .oneshot(Request::builder().uri("/me").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn required_layer_401_with_bad_token() {
        let app = required_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/me")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn optional_layer_passes_without_header() {
        let app = optional_app();
        let resp = app
            .oneshot(Request::builder().uri("/me").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn optional_layer_401_with_bad_token() {
        // A bad token in optional mode is still rejected -- "optional" means
        // "missing auth is fine," not "bad auth is fine."
        let app = optional_app();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/me")
                    .header("authorization", "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
