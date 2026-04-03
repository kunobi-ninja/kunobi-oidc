use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Validated identity extracted from a request.
///
/// Contains the authenticated caller's identity and raw claims.
/// AuthZ decisions are left to the consuming service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthIdentity {
    /// Provider identifier (e.g. access policy name).
    pub provider: String,
    /// Identity string (from template interpolation).
    pub identity: String,
    /// Method used to authenticate ("oidc", "token").
    pub method: String,
    /// Raw claims from the JWT (OIDC) or empty for token auth.
    /// Services use these for their own authorization decisions.
    #[serde(default)]
    pub claims: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_identity() -> AuthIdentity {
        let mut claims = HashMap::new();
        claims.insert("sub".to_string(), serde_json::json!("user-123"));
        claims.insert("email".to_string(), serde_json::json!("a@b.com"));
        AuthIdentity {
            provider: "my-oidc".to_string(),
            identity: "user-123".to_string(),
            method: "oidc".to_string(),
            claims,
        }
    }

    #[test]
    fn test_serialize_deserialize_with_claims() {
        let id = sample_identity();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: AuthIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.provider, "my-oidc");
        assert_eq!(deserialized.identity, "user-123");
        assert_eq!(deserialized.method, "oidc");
        assert_eq!(deserialized.claims.len(), 2);
        assert_eq!(deserialized.claims["sub"], serde_json::json!("user-123"));
        assert_eq!(deserialized.claims["email"], serde_json::json!("a@b.com"));
    }

    #[test]
    fn test_empty_claims() {
        let id = AuthIdentity {
            provider: "token-auth".to_string(),
            identity: "svc-account".to_string(),
            method: "token".to_string(),
            claims: HashMap::new(),
        };
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: AuthIdentity = serde_json::from_str(&json).unwrap();
        assert!(deserialized.claims.is_empty());
        assert_eq!(deserialized.method, "token");
    }

    #[test]
    fn test_deserialize_without_claims_field_uses_default() {
        let json = r#"{"provider":"p","identity":"i","method":"m"}"#;
        let id: AuthIdentity = serde_json::from_str(json).unwrap();
        assert!(id.claims.is_empty());
    }

    #[test]
    fn test_roundtrip_json() {
        let original = sample_identity();
        let json = serde_json::to_value(&original).unwrap();
        let back: AuthIdentity = serde_json::from_value(json).unwrap();
        assert_eq!(back.provider, original.provider);
        assert_eq!(back.identity, original.identity);
        assert_eq!(back.method, original.method);
        assert_eq!(back.claims.len(), original.claims.len());
    }
}
