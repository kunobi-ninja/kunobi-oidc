use serde::{Deserialize, Serialize};

/// Response for GET /v1/status.
/// The `app` field is generic -- each service adds its own data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse<T = serde_json::Value> {
    pub version: String,
    pub auth: AuthStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthStatus {
    pub methods: Vec<AuthMethodInfo>,
    #[serde(default)]
    pub sessions: Vec<Session>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthMethodInfo {
    #[serde(rename = "type")]
    pub method_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Service audience for SSH signature binding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Supported SSH key algorithms (e.g., ["ssh-ed25519"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub algorithms: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub method: String,
    pub identity: String,
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_response_with_app_data() {
        let resp = StatusResponse {
            version: "1.0.0".to_string(),
            auth: AuthStatus {
                methods: vec![],
                sessions: vec![],
            },
            app: Some(serde_json::json!({"healthy": true})),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["version"], "1.0.0");
        assert_eq!(parsed["app"]["healthy"], true);
    }

    #[test]
    fn test_status_response_without_app_data() {
        let resp: StatusResponse = StatusResponse {
            version: "0.2.0".to_string(),
            auth: AuthStatus {
                methods: vec![],
                sessions: vec![],
            },
            app: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        // `app` should be absent due to skip_serializing_if
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("app").is_none());
    }

    #[test]
    fn test_auth_method_info_oidc_type() {
        let info = AuthMethodInfo {
            method_type: "oidc".to_string(),
            issuer: Some("https://accounts.google.com".to_string()),
            client_id: Some("client-123".to_string()),
            description: None,
            audience: None,
            algorithms: vec![],
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "oidc");
        assert_eq!(parsed["issuer"], "https://accounts.google.com");
        assert_eq!(parsed["clientId"], "client-123");
        // description is None, should be absent
        assert!(parsed.get("description").is_none());
    }

    #[test]
    fn test_auth_method_info_token_type_no_issuer() {
        let info = AuthMethodInfo {
            method_type: "token".to_string(),
            issuer: None,
            client_id: None,
            description: Some("Static API key".to_string()),
            audience: None,
            algorithms: vec![],
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "token");
        assert!(parsed.get("issuer").is_none());
        assert!(parsed.get("clientId").is_none());
        assert_eq!(parsed["description"], "Static API key");
    }

    #[test]
    fn test_session_serialization() {
        let session = Session {
            method: "oidc".to_string(),
            identity: "user@example.com".to_string(),
            resources: vec!["cluster-a".to_string(), "cluster-b".to_string()],
            expires_at: Some("2026-12-31T23:59:59Z".to_string()),
        };
        let json = serde_json::to_string(&session).unwrap();
        let back: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(back.method, "oidc");
        assert_eq!(back.identity, "user@example.com");
        assert_eq!(back.resources.len(), 2);
        assert_eq!(back.expires_at.unwrap(), "2026-12-31T23:59:59Z");
    }

    #[test]
    fn test_session_without_expiry() {
        let session = Session {
            method: "token".to_string(),
            identity: "svc".to_string(),
            resources: vec![],
            expires_at: None,
        };
        let json = serde_json::to_string(&session).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("expiresAt").is_none());
    }

    #[test]
    fn test_status_response_roundtrip() {
        let resp = StatusResponse {
            version: "0.2.0".to_string(),
            auth: AuthStatus {
                methods: vec![AuthMethodInfo {
                    method_type: "oidc".to_string(),
                    issuer: Some("https://issuer.example.com".to_string()),
                    client_id: None,
                    description: None,
                    audience: None,
                    algorithms: vec![],
                }],
                sessions: vec![Session {
                    method: "oidc".to_string(),
                    identity: "user".to_string(),
                    resources: vec!["res".to_string()],
                    expires_at: None,
                }],
            },
            app: Some(serde_json::json!({"key": "value"})),
        };
        let json = serde_json::to_value(&resp).unwrap();
        let back: StatusResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.version, "0.2.0");
        assert_eq!(back.auth.methods.len(), 1);
        assert_eq!(back.auth.sessions.len(), 1);
    }
}
