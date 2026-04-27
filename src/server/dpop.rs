//! RFC 9449 DPoP (Demonstrating Proof-of-Possession) verifier.
//!
//! DPoP turns bearer access tokens into sender-constrained tokens. Instead
//! of sending `Authorization: Bearer <jwt>` (any holder of the JWT can
//! replay it), the client sends:
//!
//! ```text
//! Authorization: DPoP <jwt>
//! DPoP: <dpop-proof-jwt>
//! ```
//!
//! The proof JWT is signed with a per-client keypair and includes the HTTP
//! method, full URI, an `iat`, a unique `jti`, and (when an access token is
//! bound) a SHA-256 of the access token. The access token contains a
//! `cnf.jkt` confirmation claim binding it to the JWK thumbprint of the
//! client's key. A leaked access token alone is then useless to an attacker
//! because they can't produce a valid proof.
//!
//! This module verifies the proof. Use [`verify_dpop_proof`] from a tower
//! middleware or a handler. The full integration recipe:
//!
//! 1. Validate the access token (see [`crate::server::JwksManager`]).
//! 2. Extract `cnf.jkt` from the validated claims.
//! 3. Call [`verify_dpop_proof`] passing the access token + cnf.jkt.
//! 4. Track `proof.jti` against [`crate::server::NonceTracker`] to defeat
//!    proof replay.
//!
//! Only ES256 (P-256) keys are accepted. RSA and Ed25519 are explicitly out
//! of scope -- ES256 is the MUST-implement algorithm in RFC 9449 §3.1 and
//! supported by every IdP that speaks DPoP.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::common::AuthError;

/// Claims a DPoP proof must carry per RFC 9449 §4.2.
#[derive(Debug, Clone, Deserialize)]
struct DpopClaims {
    /// HTTP method (e.g. "POST"). Must match the request being authenticated.
    htm: String,
    /// HTTP URI (origin + path, no fragment). Must match the request URI.
    htu: String,
    /// Issued-at, Unix epoch seconds.
    iat: i64,
    /// Unique proof identifier. Used to detect replay of the proof JWT
    /// itself; track via NonceTracker.
    jti: String,
    /// SHA-256 of the access token, base64url-encoded. REQUIRED when the
    /// proof is sent alongside an access token bound by `cnf.jkt`.
    #[serde(default)]
    ath: Option<String>,
}

/// A successfully-verified DPoP proof.
#[derive(Debug, Clone)]
pub struct DpopProof {
    /// JWK thumbprint (RFC 7638) of the proof's signing key. This is what
    /// the access token's `cnf.jkt` claim binds to.
    pub jkt: String,
    /// Unique identifier from the proof. Track via NonceTracker.
    pub jti: String,
    /// Issued-at from the proof.
    pub iat: i64,
}

/// Verify a DPoP proof JWT carried in the `DPoP` HTTP header.
///
/// Steps (RFC 9449 §4.3):
/// 1. Parse JWT header; reject unless `typ=dpop+jwt`, `alg=ES256`, `jwk` is present.
/// 2. Verify signature using the embedded `jwk`.
/// 3. Verify `htm` matches `expected_method`.
/// 4. Verify `htu` matches `expected_url`.
/// 5. Verify `iat` is within `max_iat_skew` of now.
/// 6. If `expected_ath_for` is `Some(token)`, verify `ath == base64url(SHA256(token))`.
/// 7. If `expected_jkt` is `Some(jkt)`, verify the proof's JWK thumbprint matches.
///
/// Caller responsibilities (NOT done here, by design):
/// - Pass `proof.jti` to a NonceTracker to detect replay.
/// - Validate the access token itself separately (signature, exp, aud, iss).
pub fn verify_dpop_proof(
    proof_jwt: &str,
    expected_method: &str,
    expected_url: &str,
    expected_ath_for: Option<&str>,
    expected_jkt: Option<&str>,
    max_iat_skew: Duration,
) -> Result<DpopProof, AuthError> {
    // Step 1: parse + validate header.
    let header = decode_header(proof_jwt)
        .map_err(|e| AuthError::Unauthorized(format!("invalid DPoP JWT header: {e}")))?;

    // typ MUST be "dpop+jwt".
    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(AuthError::Unauthorized(format!(
            "DPoP proof typ must be 'dpop+jwt', got {:?}",
            header.typ
        )));
    }
    if header.alg != Algorithm::ES256 {
        return Err(AuthError::Unauthorized(format!(
            "DPoP proof alg must be ES256, got {:?}",
            header.alg
        )));
    }
    let jwk = header
        .jwk
        .ok_or_else(|| AuthError::Unauthorized("DPoP proof header is missing 'jwk'".into()))?;

    // Reject any JWK that isn't EC P-256 -- ES256 implies P-256.
    let ec = match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => ec,
        _ => {
            return Err(AuthError::Unauthorized(
                "DPoP proof jwk must be an EC key".into(),
            ));
        }
    };
    if format!("{:?}", ec.curve) != "P256" {
        return Err(AuthError::Unauthorized(format!(
            "DPoP proof jwk curve must be P-256, got {:?}",
            ec.curve
        )));
    }

    // Step 2: verify signature using embedded jwk.
    let decoding_key = DecodingKey::from_jwk(&jwk)
        .map_err(|e| AuthError::Unauthorized(format!("DPoP jwk could not be decoded: {e}")))?;
    let mut validation = Validation::new(Algorithm::ES256);
    // RFC 9449: no audience or issuer on DPoP proofs; we validate them
    // ourselves below.
    validation.validate_aud = false;
    validation.required_spec_claims = std::collections::HashSet::new();
    // exp is not required on DPoP proofs (iat + skew window is the lifetime
    // mechanism); turn off jsonwebtoken's exp check explicitly.
    validation.validate_exp = false;
    validation.validate_nbf = false;

    let claims = decode::<DpopClaims>(proof_jwt, &decoding_key, &validation)
        .map_err(|e| AuthError::Unauthorized(format!("DPoP signature invalid: {e}")))?
        .claims;

    // Step 3 + 4: htm + htu match.
    if !expected_method.eq_ignore_ascii_case(&claims.htm) {
        return Err(AuthError::Unauthorized(format!(
            "DPoP htm mismatch: proof says {:?}, request was {:?}",
            claims.htm, expected_method
        )));
    }
    if claims.htu != expected_url {
        return Err(AuthError::Unauthorized(format!(
            "DPoP htu mismatch: proof says {:?}, request was {:?}",
            claims.htu, expected_url
        )));
    }

    // Step 5: iat skew.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| AuthError::Internal(format!("system clock error: {e}")))?
        .as_secs() as i64;
    let drift = (now - claims.iat).unsigned_abs();
    if drift > max_iat_skew.as_secs() {
        return Err(AuthError::Unauthorized(format!(
            "DPoP iat drift of {drift}s exceeds maximum of {}s",
            max_iat_skew.as_secs()
        )));
    }

    // Step 6: ath binding to access token.
    if let Some(token) = expected_ath_for {
        let want = ath_for(token);
        match claims.ath.as_deref() {
            Some(got) if got == want => {}
            Some(other) => {
                return Err(AuthError::Unauthorized(format!(
                    "DPoP ath mismatch: proof says {other:?}, expected {want:?}"
                )));
            }
            None => {
                return Err(AuthError::Unauthorized(
                    "DPoP proof must include ath when bound to an access token".into(),
                ));
            }
        }
    }

    // Step 7: thumbprint binding (cnf.jkt).
    let computed_jkt = jkt_thumbprint(&jwk)?;
    if let Some(expected) = expected_jkt
        && computed_jkt != expected
    {
        return Err(AuthError::Unauthorized(format!(
            "DPoP jkt mismatch: proof key thumbprint {computed_jkt:?}, \
             access token cnf.jkt {expected:?}"
        )));
    }

    Ok(DpopProof {
        jkt: computed_jkt,
        jti: claims.jti,
        iat: claims.iat,
    })
}

/// SHA-256 of an access token, base64url-no-pad encoded. The value goes in
/// the DPoP proof's `ath` claim per RFC 9449 §4.2.
pub fn ath_for(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    B64.encode(digest)
}

/// JWK thumbprint per RFC 7638. The thumbprint is the base64url-no-pad
/// encoding of SHA-256 over a canonical, alphabetically-keyed JSON
/// representation of the public key. Only EC P-256 is supported.
pub fn jkt_thumbprint(jwk: &Jwk) -> Result<String, AuthError> {
    let ec = match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) => ec,
        _ => {
            return Err(AuthError::Unauthorized(
                "jkt thumbprint: only EC keys are supported".into(),
            ));
        }
    };
    // Canonical form per RFC 7638 §3.2 + RFC 9449: keys sorted, no whitespace.
    // For EC: {"crv","kty","x","y"}.
    let canonical = format!(
        r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
        ec_curve_str(&ec.curve)?,
        ec.x,
        ec.y,
    );
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(B64.encode(digest))
}

fn ec_curve_str(curve: &jsonwebtoken::jwk::EllipticCurve) -> Result<&'static str, AuthError> {
    use jsonwebtoken::jwk::EllipticCurve;
    match curve {
        EllipticCurve::P256 => Ok("P-256"),
        EllipticCurve::P384 => Ok("P-384"),
        EllipticCurve::P521 => Ok("P-521"),
        EllipticCurve::Ed25519 => Err(AuthError::Unauthorized(
            "Ed25519 in EC kty is not standard; not supported for jkt".into(),
        )),
    }
}

/// Extract the access token's `cnf.jkt` confirmation claim. Returns `None`
/// when the token is not DPoP-bound. Pair with the validated claims map
/// returned by `JwksManager::validate_jwt`.
pub fn cnf_jkt(claims: &std::collections::HashMap<String, serde_json::Value>) -> Option<String> {
    claims
        .get("cnf")?
        .get("jkt")?
        .as_str()
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::EncodingKey;
    use jsonwebtoken::jwk::{
        AlgorithmParameters, CommonParameters, EllipticCurve, EllipticCurveKeyParameters,
        EllipticCurveKeyType, Jwk,
    };
    use serde_json::json;

    /// Pre-generated P-256 keypair (PKCS#8 PEM private + matching public
    /// x/y). Generated once with:
    ///   openssl ecparam -name prime256v1 -genkey -noout -out k.pem
    ///   openssl pkcs8 -topk8 -nocrypt -in k.pem
    ///   openssl pkey -in k.pem -pubout -outform DER | tail -c 64 | …
    /// Keys are deterministic so the JWK + jkt are stable across CI runs.
    const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjCZ3enwwbi1sTMaE
CIAe12xZratKWzRoekhOUBIDCZChRANCAAQitjpgInyqDv9dQ4D0FZ4SiZX+KaqP
4uS/qxtTQoPfLryamFKS8SYa/uu0hcS+ASwxyTxsMBNuMpdBBC+mLBOO
-----END PRIVATE KEY-----
";
    const TEST_X: &str = "IrY6YCJ8qg7_XUOA9BWeEomV_imqj-Lkv6sbU0KD3y4";
    const TEST_Y: &str = "vJqYUpLxJhr-67SFxL4BLDHJPGwwE24yl0EEL6YsE44";

    fn test_jwk() -> Jwk {
        Jwk {
            common: CommonParameters {
                key_algorithm: Some(jsonwebtoken::jwk::KeyAlgorithm::ES256),
                ..Default::default()
            },
            algorithm: AlgorithmParameters::EllipticCurve(EllipticCurveKeyParameters {
                key_type: EllipticCurveKeyType::EC,
                curve: EllipticCurve::P256,
                x: TEST_X.into(),
                y: TEST_Y.into(),
            }),
        }
    }

    fn make_proof(htm: &str, htu: &str, iat: i64, jti: &str, ath: Option<&str>) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".into());
        header.jwk = Some(test_jwk());

        let mut claims = json!({
            "htm": htm,
            "htu": htu,
            "iat": iat,
            "jti": jti,
        });
        if let Some(a) = ath {
            claims["ath"] = json!(a);
        }

        let key = EncodingKey::from_ec_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    fn now_ts() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn ath_for_is_base64url_sha256() {
        // Known vector: SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        // base64url-no-pad: LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ
        assert_eq!(
            ath_for("hello"),
            "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"
        );
    }

    #[test]
    fn jkt_thumbprint_is_stable() {
        let t1 = jkt_thumbprint(&test_jwk()).unwrap();
        let t2 = jkt_thumbprint(&test_jwk()).unwrap();
        assert_eq!(t1, t2);
        // 32-byte SHA-256 in base64url-no-pad is 43 characters.
        assert_eq!(t1.len(), 43);
    }

    #[test]
    fn verify_proof_happy_path() {
        let proof = make_proof("POST", "https://api.example.com/x", now_ts(), "abc-1", None);
        let result = verify_dpop_proof(
            &proof,
            "POST",
            "https://api.example.com/x",
            None,
            None,
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(result.jti, "abc-1");
    }

    #[test]
    fn rejects_wrong_method() {
        let proof = make_proof("POST", "https://api.example.com/x", now_ts(), "j", None);
        let err = verify_dpop_proof(
            &proof,
            "GET",
            "https://api.example.com/x",
            None,
            None,
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("htm mismatch"));
    }

    #[test]
    fn rejects_wrong_url() {
        let proof = make_proof("POST", "https://api.example.com/x", now_ts(), "j", None);
        let err = verify_dpop_proof(
            &proof,
            "POST",
            "https://api.example.com/y",
            None,
            None,
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("htu mismatch"));
    }

    #[test]
    fn rejects_stale_iat() {
        // 5 minutes in the past.
        let proof = make_proof("POST", "https://api/x", now_ts() - 300, "j", None);
        let err = verify_dpop_proof(
            &proof,
            "POST",
            "https://api/x",
            None,
            None,
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("drift"));
    }

    #[test]
    fn ath_binding_required_when_token_provided() {
        let proof = make_proof("POST", "https://api/x", now_ts(), "j", None);
        let err = verify_dpop_proof(
            &proof,
            "POST",
            "https://api/x",
            Some("the-access-token"),
            None,
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("must include ath"));
    }

    #[test]
    fn ath_binding_matches_token_hash() {
        let token = "the-access-token";
        let proof = make_proof(
            "POST",
            "https://api/x",
            now_ts(),
            "j",
            Some(&ath_for(token)),
        );
        verify_dpop_proof(
            &proof,
            "POST",
            "https://api/x",
            Some(token),
            None,
            Duration::from_secs(60),
        )
        .unwrap();
    }

    #[test]
    fn ath_binding_rejects_mismatched_token() {
        let proof = make_proof(
            "POST",
            "https://api/x",
            now_ts(),
            "j",
            Some(&ath_for("attacker-substituted")),
        );
        let err = verify_dpop_proof(
            &proof,
            "POST",
            "https://api/x",
            Some("the-real-token"),
            None,
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("ath mismatch"));
    }

    #[test]
    fn jkt_binding_matches() {
        let proof = make_proof("POST", "https://api/x", now_ts(), "j", None);
        let expected_jkt = jkt_thumbprint(&test_jwk()).unwrap();
        let result = verify_dpop_proof(
            &proof,
            "POST",
            "https://api/x",
            None,
            Some(&expected_jkt),
            Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(result.jkt, expected_jkt);
    }

    #[test]
    fn jkt_binding_rejects_other_thumbprint() {
        let proof = make_proof("POST", "https://api/x", now_ts(), "j", None);
        let err = verify_dpop_proof(
            &proof,
            "POST",
            "https://api/x",
            None,
            Some("some-other-jkt-not-ours"),
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("jkt mismatch"));
    }

    #[test]
    fn cnf_jkt_extracts_thumbprint() {
        let mut claims = std::collections::HashMap::new();
        claims.insert("cnf".into(), json!({"jkt": "some-thumbprint"}));
        assert_eq!(cnf_jkt(&claims).as_deref(), Some("some-thumbprint"));

        claims.insert("cnf".into(), json!({}));
        assert!(cnf_jkt(&claims).is_none());

        claims.remove("cnf");
        assert!(cnf_jkt(&claims).is_none());
    }
}
