use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Internal auth error: {0}")]
    Internal(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AuthError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AuthError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            AuthError::RateLimited(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
            AuthError::Internal(msg) => {
                tracing::error!(error = %msg, "internal auth error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal auth error".to_string(),
                )
            }
        };

        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;

    async fn response_parts(err: AuthError) -> (StatusCode, String) {
        let response = err.into_response();
        let status = response.status();
        let body = Body::new(response.into_body())
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        (status, text)
    }

    #[tokio::test]
    async fn test_unauthorized_produces_401() {
        let (status, _) = response_parts(AuthError::Unauthorized("bad token".into())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_forbidden_produces_403() {
        let (status, _) = response_parts(AuthError::Forbidden("no access".into())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_rate_limited_produces_429() {
        let (status, _) = response_parts(AuthError::RateLimited("slow down".into())).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_internal_produces_500() {
        let (status, _) = response_parts(AuthError::Internal("boom".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_error_message_in_body() {
        let (_, body) = response_parts(AuthError::Unauthorized("invalid jwt".into())).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["error"], "invalid jwt");
    }

    #[tokio::test]
    async fn test_internal_error_body_is_redacted() {
        let (_, body) = response_parts(AuthError::Internal(
            "db password=secret backend detail".into(),
        ))
        .await;
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["error"], "internal auth error");
        assert!(!body.contains("secret"));
        assert!(!body.contains("backend detail"));
    }

    #[test]
    fn test_display_messages() {
        assert_eq!(
            AuthError::Unauthorized("x".into()).to_string(),
            "Unauthorized: x"
        );
        assert_eq!(AuthError::Forbidden("y".into()).to_string(), "Forbidden: y");
        assert_eq!(
            AuthError::RateLimited("z".into()).to_string(),
            "Rate limited: z"
        );
        assert_eq!(
            AuthError::Internal("w".into()).to_string(),
            "Internal auth error: w"
        );
    }
}
