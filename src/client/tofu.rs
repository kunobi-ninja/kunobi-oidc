//! Trust-on-first-use (TOFU) store for SSH service audience pinning.
//!
//! On first connection to a service the audience claim is recorded.
//! Subsequent connections verify the audience matches what was stored.
//! A mismatch signals a potential MITM and is surfaced as
//! [`TofuResult::AudienceChanged`].

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// A record stored for a single service endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownService {
    pub audience: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Result of a TOFU verification check.
#[derive(Debug)]
pub enum TofuResult {
    /// The endpoint has never been seen before.
    FirstConnect { endpoint: String, audience: String },
    /// The endpoint is known and the audience matches.
    Trusted,
    /// The endpoint is known but the audience has changed.
    AudienceChanged {
        endpoint: String,
        previous: String,
        current: String,
    },
}

/// Persistent TOFU store backed by a JSON file.
pub struct TofuStore {
    path: PathBuf,
}

impl TofuStore {
    /// Create a store that uses the default path:
    /// `~/.config/kunobi/known_services.json`.
    pub fn new() -> Result<Self> {
        let path = dirs::home_dir()
            .context("No home directory found")?
            .join(".config/kunobi/known_services.json");
        Ok(Self { path })
    }

    /// Create a store backed by an arbitrary path (useful for tests).
    pub fn with_path(path: PathBuf) -> Self {
        Self { path }
    }

    /// Verify an endpoint + audience pair against the store.
    ///
    /// Does NOT automatically record the entry — call [`Self::trust`] after
    /// prompting the user.
    pub fn verify(&self, endpoint: &str, audience: &str) -> Result<TofuResult> {
        let known = self.load()?;

        match known.get(endpoint) {
            None => Ok(TofuResult::FirstConnect {
                endpoint: endpoint.to_string(),
                audience: audience.to_string(),
            }),
            Some(entry) if entry.audience == audience => Ok(TofuResult::Trusted),
            Some(entry) => Ok(TofuResult::AudienceChanged {
                endpoint: endpoint.to_string(),
                previous: entry.audience.clone(),
                current: audience.to_string(),
            }),
        }
    }

    /// Record (or update) trust for `endpoint` with `audience`.
    pub fn trust(&self, endpoint: &str, audience: &str) -> Result<()> {
        let mut known = self.load()?;

        let now = now_rfc3339();

        known
            .entry(endpoint.to_string())
            .and_modify(|e| {
                e.audience = audience.to_string();
                e.last_seen = now.clone();
            })
            .or_insert_with(|| KnownService {
                audience: audience.to_string(),
                first_seen: now.clone(),
                last_seen: now.clone(),
            });

        self.save(&known)
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn load(&self) -> Result<HashMap<String, KnownService>> {
        if !self.path.exists() {
            return Ok(HashMap::new());
        }

        let data = std::fs::read_to_string(&self.path)
            .with_context(|| format!("Failed to read {}", self.path.display()))?;

        serde_json::from_str(&data)
            .with_context(|| format!("Failed to parse {}", self.path.display()))
    }

    fn save(&self, known: &HashMap<String, KnownService>) -> Result<()> {
        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }

        let json =
            serde_json::to_string_pretty(known).context("Failed to serialise known services")?;

        std::fs::write(&self.path, json)
            .with_context(|| format!("Failed to write {}", self.path.display()))
    }
}

fn now_rfc3339() -> String {
    // Use chrono if available; fall back to a fixed format via SystemTime.
    chrono::Utc::now().to_rfc3339()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn temp_store() -> TofuStore {
        // Create a temp file path (we delete it so the store starts empty).
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_path_buf();
        drop(f); // delete the file — store should handle missing file gracefully
        TofuStore::with_path(path)
    }

    #[test]
    fn test_first_connect() {
        let store = temp_store();
        let result = store
            .verify("https://api.example.com", "api://example")
            .unwrap();
        assert!(
            matches!(result, TofuResult::FirstConnect { .. }),
            "expected FirstConnect, got {result:?}"
        );
    }

    #[test]
    fn test_trusted_after_trust() {
        let store = temp_store();
        store
            .trust("https://api.example.com", "api://example")
            .unwrap();

        let result = store
            .verify("https://api.example.com", "api://example")
            .unwrap();
        assert!(
            matches!(result, TofuResult::Trusted),
            "expected Trusted after trust(), got {result:?}"
        );
    }

    #[test]
    fn test_audience_changed() {
        let store = temp_store();
        store
            .trust("https://api.example.com", "api://old-audience")
            .unwrap();

        let result = store
            .verify("https://api.example.com", "api://new-audience")
            .unwrap();

        match result {
            TofuResult::AudienceChanged {
                previous, current, ..
            } => {
                assert_eq!(previous, "api://old-audience");
                assert_eq!(current, "api://new-audience");
            }
            other => panic!("expected AudienceChanged, got {other:?}"),
        }
    }
}
