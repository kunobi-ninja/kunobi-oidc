use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

/// Stored token data.
#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for StoredToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredToken")
            .field("id_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("issuer", &self.issuer)
            .finish()
    }
}

impl StoredToken {
    /// Check if the token is expired (with 60s buffer).
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => chrono::Utc::now().timestamp() > (exp - 60),
            None => true,
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
        set_dir_mode_0700(&dir)?;
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

    /// Store a token for the given issuer using an atomic temp-file rename
    /// so a partial write can never be observed.
    pub fn save(&self, token: &StoredToken) -> Result<()> {
        let path = self.token_path(&token.issuer);
        let data = serde_json::to_string_pretty(token)?;

        let mut tmp = tempfile::NamedTempFile::new_in(&self.dir)?;
        use std::io::Write as _;
        tmp.write_all(data.as_bytes())?;
        tmp.as_file().sync_all()?;
        set_file_mode_0600(tmp.path())?;
        tmp.persist(&path)
            .map_err(|e| anyhow::anyhow!("Failed to persist token file: {}", e.error))?;
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

#[cfg(unix)]
fn set_file_mode_0600(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_mode_0600(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_dir_mode_0700(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_mode_0700(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn future_token() -> StoredToken {
        StoredToken {
            id_token: "eyJhbGciOiJSUzI1NiJ9.test".to_string(),
            refresh_token: Some("refresh-abc".to_string()),
            expires_at: Some(chrono::Utc::now().timestamp() + 3600),
            issuer: "https://issuer.example.com".to_string(),
        }
    }

    fn expired_token() -> StoredToken {
        StoredToken {
            id_token: "eyJhbGciOiJSUzI1NiJ9.expired".to_string(),
            refresh_token: None,
            expires_at: Some(chrono::Utc::now().timestamp() - 120),
            issuer: "https://issuer.example.com".to_string(),
        }
    }

    #[test]
    fn test_is_expired_false_for_future() {
        let token = future_token();
        assert!(!token.is_expired());
    }

    #[test]
    fn test_is_expired_true_for_past() {
        let token = expired_token();
        assert!(token.is_expired());
    }

    #[test]
    fn test_is_expired_with_60s_buffer() {
        // Token that expires in 30 seconds -- within the 60s buffer, should be "expired"
        let token = StoredToken {
            id_token: "jwt".to_string(),
            refresh_token: None,
            expires_at: Some(chrono::Utc::now().timestamp() + 30),
            issuer: "https://issuer.example.com".to_string(),
        };
        assert!(token.is_expired());
    }

    #[test]
    fn test_is_expired_none_returns_true() {
        let token = StoredToken {
            id_token: "jwt".to_string(),
            refresh_token: None,
            expires_at: None,
            issuer: "https://issuer.example.com".to_string(),
        };
        assert!(token.is_expired());
    }

    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_store() -> TokenStore {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join("kunobi-auth-test").join(format!(
            "{}-{}",
            std::process::id(),
            id
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TokenStore { dir }
    }

    fn cleanup_store(store: &TokenStore) {
        let _ = std::fs::remove_dir_all(&store.dir);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let store = temp_store();
        let token = future_token();
        store.save(&token).unwrap();

        let loaded = store.load(&token.issuer).unwrap().unwrap();
        assert_eq!(loaded.id_token, token.id_token);
        assert_eq!(loaded.refresh_token, token.refresh_token);
        assert_eq!(loaded.expires_at, token.expires_at);
        assert_eq!(loaded.issuer, token.issuer);

        cleanup_store(&store);
    }

    #[test]
    fn test_load_nonexistent_returns_none() {
        let store = temp_store();
        let result = store.load("https://no-such-issuer.example.com").unwrap();
        assert!(result.is_none());
        cleanup_store(&store);
    }

    #[test]
    fn test_remove_token() {
        let store = temp_store();
        let token = future_token();
        store.save(&token).unwrap();

        // Confirm it exists
        assert!(store.load(&token.issuer).unwrap().is_some());

        // Remove it
        store.remove(&token.issuer).unwrap();

        // Confirm it's gone
        assert!(store.load(&token.issuer).unwrap().is_none());

        cleanup_store(&store);
    }

    #[test]
    fn test_remove_nonexistent_does_not_error() {
        let store = temp_store();
        // Should not panic or error
        store.remove("https://nonexistent.example.com").unwrap();
        cleanup_store(&store);
    }

    #[test]
    fn test_stored_token_serialization() {
        let token = future_token();
        let json = serde_json::to_string(&token).unwrap();
        let back: StoredToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id_token, token.id_token);
        assert_eq!(back.issuer, token.issuer);
    }

    #[test]
    fn test_stored_token_debug_redacts_credentials() {
        let token = future_token();
        let debug = format!("{token:?}");
        assert!(debug.contains("StoredToken"));
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains(&token.issuer));
        assert!(!debug.contains(&token.id_token));
        assert!(!debug.contains(token.refresh_token.as_deref().unwrap()));
    }
}
