use serde::{Deserialize, Serialize};

/// Authentication method configuration.
/// Exactly one field should be set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthMethod {
    /// OIDC provider authentication.
    #[serde(default)]
    pub oidc: Option<OidcAuth>,
    /// Static bearer token authentication.
    #[serde(default)]
    pub token: Option<TokenAuth>,
    /// Kubernetes ServiceAccount authentication.
    #[serde(default)]
    pub service_account: Option<ServiceAccountAuth>,
    /// SSH Ed25519 public key authentication.
    #[serde(default)]
    pub ssh: Option<SshAuth>,
}

/// OIDC provider configuration for JWT validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcAuth {
    /// OIDC issuer URL (must match `iss` claim).
    pub issuer: String,
    /// JWKS URL for key fetching. Defaults to `{issuer}/.well-known/jwks.json`.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Expected audience (`aud` claim). Empty = skip validation.
    #[serde(default)]
    pub audience: Vec<String>,
    /// Expected authorized parties (`azp` claim). Empty = skip validation.
    #[serde(default)]
    pub authorized_parties: Vec<String>,
    /// Allowed JWT signing algorithms. Defaults to `["RS256"]`.
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    /// OAuth2 client ID for CLI login flow.
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Static bearer token authentication via a named secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAuth {
    /// Reference to the secret containing the token.
    pub secret_ref: String,
}

/// Kubernetes ServiceAccount-based authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountAuth {
    /// ServiceAccount name.
    pub name: String,
    /// ServiceAccount namespace.
    pub namespace: String,
}

/// SSH Ed25519 public key authentication.
///
/// Public keys are stored in OpenSSH authorized_keys format.
/// Only Ed25519 keys are supported.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshAuth {
    /// Public keys in OpenSSH authorized_keys format.
    /// Example: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host"
    pub authorized_keys: Vec<String>,

    /// Revoked public keys (same format). Takes precedence over authorized_keys.
    #[serde(default)]
    pub revoked_keys: Vec<String>,
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_method_with_oidc() {
        let json = r#"{
            "oidc": {
                "issuer": "https://accounts.google.com"
            }
        }"#;
        let method: AuthMethod = serde_json::from_str(json).unwrap();
        assert!(method.oidc.is_some());
        assert!(method.token.is_none());
        assert!(method.service_account.is_none());
        assert_eq!(method.oidc.unwrap().issuer, "https://accounts.google.com");
    }

    #[test]
    fn test_auth_method_with_token() {
        let json = r#"{
            "token": {
                "secretRef": "my-secret"
            }
        }"#;
        let method: AuthMethod = serde_json::from_str(json).unwrap();
        assert!(method.token.is_some());
        assert!(method.oidc.is_none());
        assert_eq!(method.token.unwrap().secret_ref, "my-secret");
    }

    #[test]
    fn test_auth_method_with_service_account() {
        let json = r#"{
            "serviceAccount": {
                "name": "my-sa",
                "namespace": "default"
            }
        }"#;
        let method: AuthMethod = serde_json::from_str(json).unwrap();
        assert!(method.service_account.is_some());
        let sa = method.service_account.unwrap();
        assert_eq!(sa.name, "my-sa");
        assert_eq!(sa.namespace, "default");
    }

    #[test]
    fn test_oidc_defaults_algorithms_to_rs256() {
        let json = r#"{ "issuer": "https://issuer.example.com" }"#;
        let oidc: OidcAuth = serde_json::from_str(json).unwrap();
        assert_eq!(oidc.algorithms, vec!["RS256".to_string()]);
        assert!(oidc.audience.is_empty());
        assert!(oidc.authorized_parties.is_empty());
        assert!(oidc.jwks_url.is_none());
        assert!(oidc.client_id.is_none());
    }

    #[test]
    fn test_oidc_full_deserialization() {
        let json = r#"{
            "issuer": "https://issuer.example.com",
            "jwksUrl": "https://issuer.example.com/.well-known/jwks.json",
            "audience": ["aud1", "aud2"],
            "authorizedParties": ["azp1"],
            "algorithms": ["ES256"],
            "clientId": "my-client"
        }"#;
        let oidc: OidcAuth = serde_json::from_str(json).unwrap();
        assert_eq!(oidc.issuer, "https://issuer.example.com");
        assert_eq!(
            oidc.jwks_url.unwrap(),
            "https://issuer.example.com/.well-known/jwks.json"
        );
        assert_eq!(oidc.audience, vec!["aud1", "aud2"]);
        assert_eq!(oidc.authorized_parties, vec!["azp1"]);
        assert_eq!(oidc.algorithms, vec!["ES256"]);
        assert_eq!(oidc.client_id.unwrap(), "my-client");
    }

    #[test]
    fn test_ssh_auth_deserialize() {
        let json = r#"{
            "ssh": {
                "authorizedKeys": [
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest user@host"
                ],
                "revokedKeys": []
            }
        }"#;
        let method: AuthMethod = serde_json::from_str(json).unwrap();
        assert!(method.ssh.is_some());
        let ssh = method.ssh.unwrap();
        assert_eq!(ssh.authorized_keys.len(), 1);
        assert!(ssh.authorized_keys[0].starts_with("ssh-ed25519"));
        assert!(ssh.revoked_keys.is_empty());
    }

    #[test]
    fn test_ssh_auth_revoked_keys_default() {
        let json = r#"{
            "ssh": {
                "authorizedKeys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest user@host"]
            }
        }"#;
        let method: AuthMethod = serde_json::from_str(json).unwrap();
        let ssh = method.ssh.unwrap();
        assert!(ssh.revoked_keys.is_empty());
    }

    #[test]
    fn test_auth_method_all_none() {
        let json = r#"{}"#;
        let method: AuthMethod = serde_json::from_str(json).unwrap();
        assert!(method.oidc.is_none());
        assert!(method.token.is_none());
        assert!(method.service_account.is_none());
        assert!(method.ssh.is_none());
    }

    #[test]
    fn test_auth_method_serialization_roundtrip() {
        let method = AuthMethod {
            oidc: Some(OidcAuth {
                issuer: "https://issuer.example.com".to_string(),
                jwks_url: None,
                audience: vec!["aud1".to_string()],
                authorized_parties: vec![],
                algorithms: vec!["RS256".to_string()],
                client_id: Some("client-id".to_string()),
            }),
            token: None,
            service_account: None,
            ssh: None,
        };
        let json = serde_json::to_string(&method).unwrap();
        let back: AuthMethod = serde_json::from_str(&json).unwrap();
        let oidc = back.oidc.unwrap();
        assert_eq!(oidc.issuer, "https://issuer.example.com");
        assert_eq!(oidc.audience, vec!["aud1"]);
        assert_eq!(oidc.client_id.unwrap(), "client-id");
    }
}
