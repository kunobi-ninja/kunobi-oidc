use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Stored token data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    /// The ID token (JWT).
    pub id_token: String,
    /// Refresh token for obtaining new ID tokens.
    pub refresh_token: Option<String>,
    /// When the ID token expires (Unix timestamp).
    pub expires_at: Option<i64>,
    /// Issuer this token was obtained from.
    pub issuer: String,
}

impl StoredToken {
    /// Check if the token is expired (with 60s buffer).
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => chrono::Utc::now().timestamp() > (exp - 60),
            None => false, // No expiry info — assume valid
        }
    }
}

/// Manages token persistence in ~/.config/kunobi/tokens/
pub struct TokenStore {
    dir: PathBuf,
}

impl TokenStore {
    pub fn new() -> Result<Self> {
        let dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
            .join("kunobi")
            .join("tokens");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Load a stored token for the given issuer.
    pub fn load(&self, issuer: &str) -> Result<Option<StoredToken>> {
        let path = self.token_path(issuer);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)?;
        let token: StoredToken = serde_json::from_str(&data)?;
        Ok(Some(token))
    }

    /// Store a token for the given issuer.
    pub fn save(&self, token: &StoredToken) -> Result<()> {
        let path = self.token_path(&token.issuer);
        let data = serde_json::to_string_pretty(token)?;
        std::fs::write(&path, data)?;
        // Restrict permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Remove stored token for the given issuer.
    pub fn remove(&self, issuer: &str) -> Result<()> {
        let path = self.token_path(issuer);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    fn token_path(&self, issuer: &str) -> PathBuf {
        // Hash the issuer URL to create a safe filename
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        issuer.hash(&mut hasher);
        self.dir.join(format!("{:x}.json", hasher.finish()))
    }
}
