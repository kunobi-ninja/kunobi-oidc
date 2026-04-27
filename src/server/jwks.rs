use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::debug;

const JWKS_CACHE_TTL: Duration = Duration::from_secs(300);

/// Minimum interval between forced JWKS refetches triggered by an unknown
/// `kid`. Prevents an attacker who sends garbage `kid` values from turning
/// the auth path into an amplification vector against the IdP.
const KID_MISS_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

/// Cap on the per-token validation cache. Beyond this we evict the oldest
/// entries on insert to keep memory bounded under unique-token churn.
const VALIDATION_CACHE_MAX: usize = 4096;

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
    #[allow(dead_code)]
    crv: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

struct CachedJwks {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

/// A validated JWT held in the per-token cache. Keyed by SHA-256 of the
/// raw token string -- the hash is for dedup, not security.
struct CachedValidation {
    claims: HashMap<String, serde_json::Value>,
    valid_until: Instant,
}

/// JWKS key manager -- fetches and caches signing keys from OIDC providers,
/// and (optionally) caches validated tokens to skip repeated crypto on hot
/// paths.
pub struct JwksManager {
    http: reqwest::Client,
    cache: RwLock<HashMap<String, CachedJwks>>,
    /// Per-token validation cache. `None` = disabled (default).
    validation_cache: Option<ValidationCache>,
}

struct ValidationCache {
    /// SHA-256(token) -> validated claims + expiration.
    entries: RwLock<HashMap<[u8; 32], CachedValidation>>,
    /// Maximum cache age, capped further by each token's own `exp` claim.
    ttl: Duration,
}

impl JwksManager {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");
        Self {
            http,
            cache: RwLock::new(HashMap::new()),
            validation_cache: None,
        }
    }

    /// Enable a per-token validation cache.
    ///
    /// Validated claims are kept for `min(token.exp, ttl)` and returned
    /// directly on subsequent calls with the same token. Skips signature
    /// verification, audience/issuer parsing, and JWKS lookup -- a 10×–100×
    /// speedup on auth'd hot paths at typical request rates.
    ///
    /// **Trade-off**: a token that's revoked at the IdP stays accepted by
    /// this validator until its cache entry expires (max `ttl`). For
    /// services that need instant revocation, leave the cache off and pair
    /// with periodic `oidc::introspect` calls instead.
    ///
    /// A reasonable default is `Duration::from_secs(30)`.
    pub fn with_validation_cache(mut self, ttl: Duration) -> Self {
        self.validation_cache = Some(ValidationCache {
            entries: RwLock::new(HashMap::new()),
            ttl,
        });
        self
    }

    /// Validate a JWT and return its claims.
    ///
    /// Both `issuer` and `audience` are required and validated against the `iss`
    /// / `aud` claims. Pass at least one audience.
    pub async fn validate_jwt(
        &self,
        token: &str,
        jwks_url: &str,
        issuer: &str,
        audience: &[String],
        algorithms: &[String],
    ) -> Result<HashMap<String, serde_json::Value>> {
        if issuer.is_empty() {
            anyhow::bail!("issuer must be set; refusing to validate JWT without issuer binding");
        }
        if audience.is_empty() {
            anyhow::bail!(
                "audience must be set; refusing to validate JWT without audience binding"
            );
        }

        // Fast path: per-token cache hit.
        if let Some(cache) = &self.validation_cache {
            let key = sha256_token(token);
            let now = Instant::now();
            let entries = cache.entries.read().await;
            if let Some(hit) = entries.get(&key)
                && cache_entry_is_fresh(hit.valid_until, now)
            {
                return Ok(hit.claims.clone());
            }
        }

        let header = decode_header(token).context("Invalid JWT header")?;
        let kid = header.kid.as_deref();

        let keys = self.get_keys(jwks_url, kid).await?;
        let key = find_matching_key(&keys, kid)?;

        let mut validation = Validation::new(parse_algorithm(algorithms)?);
        validation.set_audience(audience);
        validation.set_issuer(&[issuer]);
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let decoding_key = build_decoding_key(key)?;
        let token_data =
            decode::<HashMap<String, serde_json::Value>>(token, &decoding_key, &validation)
                .context("JWT validation failed")?;

        // Populate the validation cache, capping TTL by token.exp.
        if let Some(cache) = &self.validation_cache {
            insert_validated(cache, token, &token_data.claims).await;
        }

        Ok(token_data.claims)
    }

    /// Fetch JWKS keys, optionally forcing a refetch when `wanted_kid` isn't in
    /// the cached set (capped by [`KID_MISS_REFRESH_COOLDOWN`]).
    async fn get_keys(&self, jwks_url: &str, wanted_kid: Option<&str>) -> Result<Vec<Jwk>> {
        // Check cache.
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(jwks_url) {
                let kid_present = match wanted_kid {
                    Some(kid) => cached.keys.iter().any(|k| k.kid.as_deref() == Some(kid)),
                    None => true,
                };
                if jwks_cache_should_be_used(cached.fetched_at.elapsed(), kid_present) {
                    return Ok(cached.keys.clone());
                }
            }
        }

        // Miss / stale / forced rotation refetch.
        debug!(url = %jwks_url, kid = ?wanted_kid, "Fetching JWKS");
        let response: JwksResponse = self
            .http
            .get(jwks_url)
            .send()
            .await
            .context("Failed to fetch JWKS")?
            .json()
            .await
            .context("Failed to parse JWKS")?;

        let keys = response.keys;
        self.cache.write().await.insert(
            jwks_url.to_string(),
            CachedJwks {
                keys: keys.clone(),
                fetched_at: std::time::Instant::now(),
            },
        );

        Ok(keys)
    }
}

impl Default for JwksManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure predicate for the validation-cache hit check. Extracted from
/// [`JwksManager::validate_jwt`] so the comparison is exercised directly
/// by unit tests -- mutation operators (`>` -> `<`, `>=`, `==`) are pinned
/// by `test_cache_entry_is_fresh_*`.
fn cache_entry_is_fresh(valid_until: Instant, now: Instant) -> bool {
    valid_until > now
}

/// Pure predicate for the JWKS cache hit decision. Extracted so the two
/// boundary comparisons (`< JWKS_CACHE_TTL` and `>= KID_MISS_REFRESH_COOLDOWN`)
/// are pinned by unit tests. Returns true when the cached keys can be
/// returned directly (no refetch needed).
///
/// Logic: use the cache iff it is *fresh* (within TTL) AND either the kid
/// is present OR we have not yet cooled down enough to allow a kid-miss
/// refetch. The cooldown rate-limits refetches against the IdP when an
/// attacker fires garbage `kid`s at us.
fn jwks_cache_should_be_used(age: Duration, kid_present: bool) -> bool {
    let fresh = age < JWKS_CACHE_TTL;
    let cooled_down = age >= KID_MISS_REFRESH_COOLDOWN;
    fresh && (kid_present || !cooled_down)
}

fn sha256_token(token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.finalize().into()
}

async fn insert_validated(
    cache: &ValidationCache,
    token: &str,
    claims: &HashMap<String, serde_json::Value>,
) {
    let now = Instant::now();
    // Cap cache lifetime at the token's own exp claim. Tokens already
    // checked validate_exp, so exp is in the future; we just don't want
    // to keep them past it.
    let token_exp_in = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .map(|exp| {
            let now_unix = chrono::Utc::now().timestamp();
            Duration::from_secs(exp.saturating_sub(now_unix).max(0) as u64)
        })
        .unwrap_or(cache.ttl);
    let lifetime = std::cmp::min(token_exp_in, cache.ttl);
    let valid_until = now + lifetime;

    let mut entries = cache.entries.write().await;

    // Evict expired entries opportunistically. Cheap because the map is
    // bounded by VALIDATION_CACHE_MAX.
    entries.retain(|_, v| v.valid_until > now);

    // Hard cap on size: drop oldest-by-valid_until until under the limit.
    while entries.len() >= VALIDATION_CACHE_MAX {
        if let Some(oldest_key) = entries
            .iter()
            .min_by_key(|(_, v)| v.valid_until)
            .map(|(k, _)| *k)
        {
            entries.remove(&oldest_key);
        } else {
            break;
        }
    }

    entries.insert(
        sha256_token(token),
        CachedValidation {
            claims: claims.clone(),
            valid_until,
        },
    );
}

fn find_matching_key<'a>(keys: &'a [Jwk], kid: Option<&str>) -> Result<&'a Jwk> {
    if let Some(kid) = kid {
        keys.iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .ok_or_else(|| anyhow::anyhow!("No key found with kid: {kid}"))
    } else {
        keys.first()
            .ok_or_else(|| anyhow::anyhow!("JWKS has no keys"))
    }
}

fn parse_algorithm(algorithms: &[String]) -> Result<Algorithm> {
    let alg = algorithms.first().map(|s| s.as_str()).unwrap_or("RS256");
    match alg {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "EdDSA" => Ok(Algorithm::EdDSA),
        _ => anyhow::bail!("Unsupported algorithm: {alg}"),
    }
}

fn build_decoding_key(key: &Jwk) -> Result<DecodingKey> {
    match key.kty.as_str() {
        "RSA" => {
            let n = key
                .n
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("RSA key missing 'n'"))?;
            let e = key
                .e
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("RSA key missing 'e'"))?;
            Ok(DecodingKey::from_rsa_components(n, e)?)
        }
        "EC" => {
            let x = key
                .x
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("EC key missing 'x'"))?;
            let y = key
                .y
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("EC key missing 'y'"))?;
            Ok(DecodingKey::from_ec_components(x, y)?)
        }
        "OKP" => {
            let x = key
                .x
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("OKP key missing 'x'"))?;
            Ok(DecodingKey::from_ed_components(x)?)
        }
        kty => anyhow::bail!("Unsupported key type: {kty}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_algorithm_rs256() {
        let alg = parse_algorithm(&["RS256".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::RS256);
    }

    #[test]
    fn test_parse_algorithm_rs384() {
        let alg = parse_algorithm(&["RS384".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::RS384);
    }

    #[test]
    fn test_parse_algorithm_rs512() {
        let alg = parse_algorithm(&["RS512".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::RS512);
    }

    #[test]
    fn test_parse_algorithm_es256() {
        let alg = parse_algorithm(&["ES256".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::ES256);
    }

    #[test]
    fn test_parse_algorithm_es384() {
        let alg = parse_algorithm(&["ES384".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::ES384);
    }

    #[test]
    fn test_parse_algorithm_ps256() {
        let alg = parse_algorithm(&["PS256".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::PS256);
    }

    #[test]
    fn test_parse_algorithm_ps384() {
        let alg = parse_algorithm(&["PS384".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::PS384);
    }

    #[test]
    fn test_parse_algorithm_ps512() {
        let alg = parse_algorithm(&["PS512".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::PS512);
    }

    #[test]
    fn test_parse_algorithm_eddsa() {
        let alg = parse_algorithm(&["EdDSA".to_string()]).unwrap();
        assert_eq!(alg, Algorithm::EdDSA);
    }

    #[test]
    fn test_parse_algorithm_unsupported() {
        let result = parse_algorithm(&["HS256".to_string()]);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Unsupported algorithm"));
    }

    #[test]
    fn test_parse_algorithm_empty_defaults_to_rs256() {
        let alg = parse_algorithm(&[]).unwrap();
        assert_eq!(alg, Algorithm::RS256);
    }

    #[test]
    fn test_build_decoding_key_rsa() {
        // Use real base64url-encoded RSA components (small test values)
        let jwk = Jwk {
            kid: Some("rsa-key-1".to_string()),
            kty: "RSA".to_string(),
            // These are base64url-encoded values for a minimal RSA public key
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_decoding_key_rsa_missing_n() {
        let jwk = Jwk {
            kid: None,
            kty: "RSA".to_string(),
            n: None,
            e: Some("AQAB".to_string()),
            x: None,
            y: None,
            crv: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'n'"));
    }

    #[test]
    fn test_build_decoding_key_rsa_missing_e() {
        let jwk = Jwk {
            kid: None,
            kty: "RSA".to_string(),
            n: Some("abc".to_string()),
            e: None,
            x: None,
            y: None,
            crv: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'e'"));
    }

    #[test]
    fn test_build_decoding_key_ec_missing_x() {
        let jwk = Jwk {
            kid: None,
            kty: "EC".to_string(),
            n: None,
            e: None,
            x: None,
            y: Some("y-val".to_string()),
            crv: Some("P-256".to_string()),
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'x'"));
    }

    #[test]
    fn test_build_decoding_key_ec_missing_y() {
        let jwk = Jwk {
            kid: None,
            kty: "EC".to_string(),
            n: None,
            e: None,
            x: Some("x-val".to_string()),
            y: None,
            crv: Some("P-256".to_string()),
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'y'"));
    }

    #[test]
    fn test_build_decoding_key_okp_missing_x() {
        let jwk = Jwk {
            kid: None,
            kty: "OKP".to_string(),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: Some("Ed25519".to_string()),
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("missing 'x'"));
    }

    #[test]
    fn test_build_decoding_key_unsupported_kty() {
        let jwk = Jwk {
            kid: None,
            kty: "oct".to_string(),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
        };
        let result = build_decoding_key(&jwk);
        assert!(result.is_err());
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("Unsupported key type")
        );
    }

    #[test]
    fn test_find_matching_key_by_kid() {
        let keys = vec![
            Jwk {
                kid: Some("key-1".to_string()),
                kty: "RSA".to_string(),
                n: Some("n1".to_string()),
                e: Some("e1".to_string()),
                x: None,
                y: None,
                crv: None,
            },
            Jwk {
                kid: Some("key-2".to_string()),
                kty: "RSA".to_string(),
                n: Some("n2".to_string()),
                e: Some("e2".to_string()),
                x: None,
                y: None,
                crv: None,
            },
        ];
        let found = find_matching_key(&keys, Some("key-2")).unwrap();
        assert_eq!(found.kid.as_deref(), Some("key-2"));
        assert_eq!(found.n.as_deref(), Some("n2"));
    }

    #[test]
    fn test_find_matching_key_no_kid_returns_first() {
        let keys = vec![Jwk {
            kid: Some("only".to_string()),
            kty: "RSA".to_string(),
            n: Some("n".to_string()),
            e: Some("e".to_string()),
            x: None,
            y: None,
            crv: None,
        }];
        let found = find_matching_key(&keys, None).unwrap();
        assert_eq!(found.kid.as_deref(), Some("only"));
    }

    #[test]
    fn test_find_matching_key_empty_keys() {
        let keys: Vec<Jwk> = vec![];
        let result = find_matching_key(&keys, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_find_matching_key_kid_not_found() {
        let keys = vec![Jwk {
            kid: Some("key-1".to_string()),
            kty: "RSA".to_string(),
            n: None,
            e: None,
            x: None,
            y: None,
            crv: None,
        }];
        let result = find_matching_key(&keys, Some("nonexistent"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No key found"));
    }

    #[test]
    fn test_jwks_manager_new_does_not_panic() {
        let _manager = JwksManager::new();
    }

    #[test]
    fn test_jwks_manager_default() {
        let _manager = JwksManager::default();
    }

    #[tokio::test]
    async fn test_validate_jwt_rejects_empty_audience() {
        let mgr = JwksManager::new();
        let err = mgr
            .validate_jwt("token", "https://x/jwks", "https://issuer", &[], &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("audience"));
    }

    #[tokio::test]
    async fn test_validate_jwt_rejects_empty_issuer() {
        let mgr = JwksManager::new();
        let err = mgr
            .validate_jwt("token", "https://x/jwks", "", &["aud".to_string()], &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("issuer"));
    }

    // ── Validation-cache behaviour ────────────────────────────────────────

    #[test]
    fn test_validation_cache_disabled_by_default() {
        let mgr = JwksManager::new();
        assert!(mgr.validation_cache.is_none());
    }

    #[tokio::test]
    async fn test_validation_cache_capped_by_token_exp() {
        let cache = ValidationCache {
            entries: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(300),
        };

        let now_unix = chrono::Utc::now().timestamp();
        let mut claims: HashMap<String, serde_json::Value> = HashMap::new();
        // Token expires in 5s -- well below the 300s ttl.
        claims.insert("exp".into(), serde_json::Value::from(now_unix + 5));

        insert_validated(&cache, "token-A", &claims).await;

        let entries = cache.entries.read().await;
        let entry = entries.get(&sha256_token("token-A")).unwrap();
        let lifetime = entry.valid_until.saturating_duration_since(Instant::now());
        assert!(
            lifetime <= Duration::from_secs(6) && lifetime >= Duration::from_secs(4),
            "lifetime should be capped near the 5s token exp, got {lifetime:?}"
        );
    }

    #[tokio::test]
    async fn test_validation_cache_evicts_when_full() {
        let cache = ValidationCache {
            entries: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(300),
        };
        let now_unix = chrono::Utc::now().timestamp();

        // Pre-fill to the cap with synthetic entries that have varying exps
        // (so eviction can pick a clear "oldest" by valid_until).
        for i in 0..VALIDATION_CACHE_MAX {
            let mut claims: HashMap<String, serde_json::Value> = HashMap::new();
            claims.insert(
                "exp".into(),
                serde_json::Value::from(now_unix + 60 + i as i64),
            );
            insert_validated(&cache, &format!("token-{i}"), &claims).await;
        }
        assert_eq!(cache.entries.read().await.len(), VALIDATION_CACHE_MAX);

        // One more insert must evict to stay at the cap.
        let mut claims: HashMap<String, serde_json::Value> = HashMap::new();
        claims.insert("exp".into(), serde_json::Value::from(now_unix + 9999));
        insert_validated(&cache, "token-new", &claims).await;
        assert_eq!(cache.entries.read().await.len(), VALIDATION_CACHE_MAX);

        // The shortest-lived entry (token-0) should be the one evicted.
        let entries = cache.entries.read().await;
        assert!(
            !entries.contains_key(&sha256_token("token-0")),
            "expected token-0 to be evicted"
        );
        assert!(entries.contains_key(&sha256_token("token-new")));
    }

    #[test]
    fn test_sha256_token_deterministic() {
        // Same input → same digest. Sanity check on the cache key fn.
        assert_eq!(sha256_token("hello"), sha256_token("hello"));
        assert_ne!(sha256_token("hello"), sha256_token("world"));
    }

    // Mutation-killer tests for the cache freshness predicate. cargo-mutants
    // tries `>` -> `<`, `>=`, `==`; each of these tests fails for at least
    // one mutant.

    #[test]
    fn test_cache_entry_is_fresh_future_is_true() {
        // valid_until in the future -> fresh. Kills `>` -> `<` and `>` -> `==`.
        let now = Instant::now();
        assert!(cache_entry_is_fresh(now + Duration::from_secs(1), now));
    }

    #[test]
    fn test_cache_entry_is_fresh_past_is_false() {
        // valid_until in the past -> stale. Kills `>` -> `<` (would return
        // true) and `>` -> `>=` (still false here, but the future case
        // separately pins `>=`).
        let now = Instant::now();
        assert!(!cache_entry_is_fresh(now - Duration::from_secs(1), now));
    }

    #[test]
    fn test_cache_entry_is_fresh_equal_is_false() {
        // valid_until == now -> stale (the cache lifetime is half-open
        // (start, valid_until]; at the boundary moment, it's done). Kills
        // `>` -> `>=` (would return true) and `>` -> `==` (would return true).
        let now = Instant::now();
        assert!(!cache_entry_is_fresh(now, now));
    }

    // Mutation-killer tests for `jwks_cache_should_be_used`. The function
    // composes two comparisons (TTL check + cooldown check); these tests
    // exercise both sides of each boundary independently.

    #[test]
    fn jwks_cache_use_fresh_kid_present() {
        // Within TTL, kid present -> use cache.
        // Kills the TTL `<` operator (mutated to `>` would return false).
        assert!(jwks_cache_should_be_used(Duration::from_secs(10), true));
    }

    #[test]
    fn jwks_cache_no_use_when_stale() {
        // Past TTL -> never use cache, regardless of kid.
        // Kills the `&&` -> `||` mutation (would say "use" because kid_present=true).
        assert!(!jwks_cache_should_be_used(
            JWKS_CACHE_TTL + Duration::from_secs(1),
            true
        ));
    }

    #[test]
    fn jwks_cache_use_when_kid_missing_but_within_cooldown() {
        // Within TTL, kid missing, age < cooldown -> use cache (rate-limit
        // refetch). Kills cooldown `>=` -> `<` (would return false because
        // !cooled_down would flip).
        assert!(jwks_cache_should_be_used(
            Duration::from_secs(5), // < KID_MISS_REFRESH_COOLDOWN (30s)
            false,
        ));
    }

    #[test]
    fn jwks_cache_no_use_when_kid_missing_past_cooldown() {
        // Within TTL, kid missing, age >= cooldown -> refetch (don't use
        // cache). Kills cooldown `>=` -> `>` for the boundary moment, and
        // pins the inverted-meaning mutants.
        assert!(!jwks_cache_should_be_used(
            KID_MISS_REFRESH_COOLDOWN + Duration::from_secs(1),
            false,
        ));
    }

    #[test]
    fn jwks_cache_boundary_at_cooldown_exact() {
        // age == KID_MISS_REFRESH_COOLDOWN: `>=` says cooled_down=true,
        // so we refetch. Pins `>=` vs `>` distinction.
        assert!(!jwks_cache_should_be_used(KID_MISS_REFRESH_COOLDOWN, false,));
    }

    #[test]
    fn jwks_cache_boundary_at_ttl_exact() {
        // age == JWKS_CACHE_TTL: `<` says fresh=false (boundary is half-open),
        // so we refetch. Kills `<` -> `<=` (would say still-fresh).
        assert!(!jwks_cache_should_be_used(JWKS_CACHE_TTL, true));
    }
}
