// Copyright 2021-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Verification of the JWTs issued by an identity provider, against its JSON Web Key Set.

use std::time::{Duration, Instant};

use anyhow::Context;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use quickwit_config::JwtConfig;
use serde_json::Value as JsonValue;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

use super::token_exchange::TokenExchangeError;

/// Asymmetric algorithms only: with a symmetric algorithm, anyone who can read the key set could
/// sign JWTs.
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// A fetched key set is refreshed after this delay, to pick up key rotations.
const JWKS_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

/// Minimum delay between two fetches of the key set, which a JWT with an unknown key ID triggers.
const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// The identity carried by a verified JWT.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct JwtIdentity {
    pub user: String,
    /// Values of the roles claim, before mapping to Quickwit roles.
    pub claim_roles: Vec<String>,
    /// Expiration of the JWT, in seconds since the Unix epoch.
    pub expires_at_secs: i64,
}

struct CachedJwks {
    jwk_set: JwkSet,
    fetched_at: Instant,
}

enum JwksSource {
    /// Loaded from `jwks_path` at startup.
    Static(JwkSet),
    /// Fetched from `jwks_url`, lazily, then cached.
    Remote {
        jwks_url: String,
        http_client: reqwest::Client,
        cached_jwks_opt: RwLock<Option<CachedJwks>>,
        /// Serializes the fetches, and holds the time of the last one.
        last_fetch_opt: Mutex<Option<Instant>>,
    },
}

pub(crate) struct JwtVerifier {
    jwks_source: JwksSource,
    issuer: String,
    audience: String,
    user_claim: String,
    roles_claim: String,
}

impl JwtVerifier {
    pub fn try_new(jwt_config: &JwtConfig) -> anyhow::Result<Self> {
        let jwks_source = match (&jwt_config.jwks_url, &jwt_config.jwks_path) {
            (Some(jwks_url), None) => {
                let http_client = reqwest::Client::builder()
                    .timeout(JWKS_FETCH_TIMEOUT)
                    .build()
                    .context("failed to build JWKS HTTP client")?;
                JwksSource::Remote {
                    jwks_url: jwks_url.clone(),
                    http_client,
                    cached_jwks_opt: RwLock::new(None),
                    last_fetch_opt: Mutex::new(None),
                }
            }
            (None, Some(jwks_path)) => {
                let jwks_json = std::fs::read_to_string(jwks_path)
                    .with_context(|| format!("failed to read JWKS file `{jwks_path}`"))?;
                let jwk_set: JwkSet = serde_json::from_str(&jwks_json)
                    .with_context(|| format!("failed to parse JWKS file `{jwks_path}`"))?;
                JwksSource::Static(jwk_set)
            }
            // Validated with the node config.
            _ => anyhow::bail!("exactly one of `jwks_url` and `jwks_path` must be set"),
        };
        Ok(JwtVerifier {
            jwks_source,
            issuer: jwt_config.issuer.clone(),
            audience: jwt_config.audience.clone(),
            user_claim: jwt_config.user_claim.clone(),
            roles_claim: jwt_config.roles_claim.clone(),
        })
    }

    /// Verifies the signature, the issuer, the audience, and the validity period of `jwt`, then
    /// extracts the identity of the user.
    pub async fn verify(&self, jwt: &str) -> Result<JwtIdentity, TokenExchangeError> {
        let header = decode_header(jwt).map_err(|error| invalid_jwt(&error))?;
        if !ALLOWED_ALGORITHMS.contains(&header.alg) {
            return Err(TokenExchangeError::InvalidJwt(format!(
                "unsupported algorithm `{:?}`",
                header.alg
            )));
        }
        let jwk = self.find_key(header.kid.as_deref()).await?;
        if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
            return Err(TokenExchangeError::InvalidJwt(
                "symmetric keys are not supported".to_string(),
            ));
        }
        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|error| invalid_jwt(&error))?;
        // `decode` also checks that the algorithm matches the family of the key.
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_nbf = true;
        let claims = decode::<JsonValue>(jwt, &decoding_key, &validation)
            .map_err(|error| invalid_jwt(&error))?
            .claims;
        identity_from_claims(&claims, &self.user_claim, &self.roles_claim)
    }

    async fn find_key(&self, kid_opt: Option<&str>) -> Result<Jwk, TokenExchangeError> {
        match &self.jwks_source {
            JwksSource::Static(jwk_set) => find_key_in_set(jwk_set, kid_opt),
            JwksSource::Remote {
                jwks_url,
                http_client,
                cached_jwks_opt,
                last_fetch_opt,
            } => {
                if let Some(cached_jwks) = &*cached_jwks_opt.read().await {
                    let is_fresh = cached_jwks.fetched_at.elapsed() < JWKS_CACHE_TTL;
                    if let (true, Ok(jwk)) =
                        (is_fresh, find_key_in_set(&cached_jwks.jwk_set, kid_opt))
                    {
                        return Ok(jwk);
                    }
                }
                // The key set is missing, stale, or does not hold the key (rotation).
                let mut last_fetch_guard = last_fetch_opt.lock().await;
                let can_fetch = match *last_fetch_guard {
                    Some(last_fetch) => last_fetch.elapsed() >= JWKS_MIN_REFRESH_INTERVAL,
                    None => true,
                };
                if can_fetch {
                    *last_fetch_guard = Some(Instant::now());
                    match fetch_jwks(http_client, jwks_url).await {
                        Ok(jwk_set) => {
                            info!(jwks_url, num_keys = jwk_set.keys.len(), "fetched JWKS");
                            *cached_jwks_opt.write().await = Some(CachedJwks {
                                jwk_set,
                                fetched_at: Instant::now(),
                            });
                        }
                        Err(error) => {
                            // A stale key set is still used below: the keys of an identity
                            // provider outlive the refresh interval by far.
                            warn!(jwks_url, %error, "failed to fetch JWKS");
                        }
                    }
                }
                drop(last_fetch_guard);
                match &*cached_jwks_opt.read().await {
                    Some(cached_jwks) => find_key_in_set(&cached_jwks.jwk_set, kid_opt),
                    None => Err(TokenExchangeError::JwksUnavailable(format!(
                        "failed to fetch the JSON Web Key Set from `{jwks_url}`"
                    ))),
                }
            }
        }
    }
}

async fn fetch_jwks(http_client: &reqwest::Client, jwks_url: &str) -> anyhow::Result<JwkSet> {
    let jwk_set = http_client
        .get(jwks_url)
        .send()
        .await?
        .error_for_status()?
        .json::<JwkSet>()
        .await?;
    Ok(jwk_set)
}

fn find_key_in_set(jwk_set: &JwkSet, kid_opt: Option<&str>) -> Result<Jwk, TokenExchangeError> {
    let jwk_opt = match kid_opt {
        Some(kid) => jwk_set.find(kid),
        // Without key ID, the key set must hold a single key.
        None if jwk_set.keys.len() == 1 => jwk_set.keys.first(),
        None => {
            return Err(TokenExchangeError::InvalidJwt(
                "the JWT has no key ID (`kid`) and the key set holds several keys".to_string(),
            ));
        }
    };
    jwk_opt.cloned().ok_or_else(|| {
        TokenExchangeError::InvalidJwt("the JWT is signed by an unknown key".to_string())
    })
}

fn invalid_jwt(error: &jsonwebtoken::errors::Error) -> TokenExchangeError {
    TokenExchangeError::InvalidJwt(error.to_string())
}

/// Returns the claim at `claim_path`, where dots separate the names of nested claims.
fn get_claim<'a>(claims: &'a JsonValue, claim_path: &str) -> Option<&'a JsonValue> {
    claim_path
        .split('.')
        .try_fold(claims, |claim, claim_name| claim.get(claim_name))
}

fn identity_from_claims(
    claims: &JsonValue,
    user_claim: &str,
    roles_claim: &str,
) -> Result<JwtIdentity, TokenExchangeError> {
    let Some(user) = get_claim(claims, user_claim).and_then(JsonValue::as_str) else {
        return Err(TokenExchangeError::InvalidJwt(format!(
            "missing user claim `{user_claim}`"
        )));
    };
    if user.is_empty() {
        return Err(TokenExchangeError::InvalidJwt(format!(
            "empty user claim `{user_claim}`"
        )));
    }
    let claim_roles: Vec<String> = match get_claim(claims, roles_claim) {
        None | Some(JsonValue::Null) => Vec::new(),
        Some(JsonValue::String(roles_str)) => {
            roles_str.split_whitespace().map(str::to_string).collect()
        }
        Some(JsonValue::Array(roles_array)) => roles_array
            .iter()
            .filter_map(|role| role.as_str().map(str::to_string))
            .collect(),
        Some(_) => {
            return Err(TokenExchangeError::InvalidJwt(format!(
                "roles claim `{roles_claim}` must be a string or an array of strings"
            )));
        }
    };
    // `exp` is required and validated by `decode`.
    let expires_at_secs = claims
        .get("exp")
        .and_then(JsonValue::as_f64)
        .ok_or_else(|| TokenExchangeError::InvalidJwt("invalid `exp` claim".to_string()))?
        as i64;
    Ok(JwtIdentity {
        user: user.to_string(),
        claim_roles,
        expires_at_secs,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    use super::*;

    /// Signs JWTs with an Ed25519 key, and exposes the matching key set.
    pub(crate) struct TestIdentityProvider {
        encoding_key: EncodingKey,
        pub jwks_json: String,
    }

    pub(crate) const TEST_ISSUER: &str = "https://idp.example.com";
    pub(crate) const TEST_AUDIENCE: &str = "quickwit";

    impl TestIdentityProvider {
        pub fn new() -> Self {
            // Any Ed25519 key pair does: reuse the key generation of the biscuit root keys.
            let (private_key_hex, public_key_hex) = quickwit_authorize::generate_root_key_pair();
            let seed = hex::decode(private_key_hex).unwrap();
            // PKCS#8 v1 encoding of an Ed25519 private key: fixed prefix followed by the seed.
            let mut pkcs8_der = hex::decode("302e020100300506032b657004220420").unwrap();
            pkcs8_der.extend(seed);
            let public_key = hex::decode(public_key_hex).unwrap();
            let public_key_base64 = base64_url(&public_key);
            let jwks_json = json!({"keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "test-key",
                "alg": "EdDSA",
                "use": "sig",
                "x": public_key_base64,
            }]})
            .to_string();
            TestIdentityProvider {
                encoding_key: EncodingKey::from_ed_der(&pkcs8_der),
                jwks_json,
            }
        }

        pub fn sign(&self, claims: &JsonValue) -> String {
            let mut header = Header::new(Algorithm::EdDSA);
            header.kid = Some("test-key".to_string());
            encode(&header, claims, &self.encoding_key).unwrap()
        }

        /// Claims of a valid JWT, expiring in an hour.
        pub fn claims(&self, user: &str, roles: &[&str]) -> JsonValue {
            json!({
                "iss": TEST_ISSUER,
                "aud": TEST_AUDIENCE,
                "sub": user,
                "exp": now_secs() + 3600,
                "roles": roles,
            })
        }
    }

    fn base64_url(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    pub(crate) fn now_secs() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }

    fn make_verifier(identity_provider: &TestIdentityProvider) -> JwtVerifier {
        JwtVerifier {
            jwks_source: JwksSource::Static(
                serde_json::from_str(&identity_provider.jwks_json).unwrap(),
            ),
            issuer: TEST_ISSUER.to_string(),
            audience: TEST_AUDIENCE.to_string(),
            user_claim: "sub".to_string(),
            roles_claim: "roles".to_string(),
        }
    }

    #[tokio::test]
    async fn test_jwt_verifier_accepts_valid_jwt() {
        let identity_provider = TestIdentityProvider::new();
        let verifier = make_verifier(&identity_provider);
        let claims = identity_provider.claims("alice", &["admins", "devs"]);
        let jwt = identity_provider.sign(&claims);
        let identity = verifier.verify(&jwt).await.unwrap();
        assert_eq!(identity.user, "alice");
        assert_eq!(identity.claim_roles, vec!["admins", "devs"]);
        assert_eq!(identity.expires_at_secs, claims["exp"].as_i64().unwrap());
    }

    #[tokio::test]
    async fn test_jwt_verifier_rejects_invalid_jwts() {
        let identity_provider = TestIdentityProvider::new();
        let verifier = make_verifier(&identity_provider);
        let mut claims_variants = Vec::new();
        for (claim_name, claim_value) in [
            ("aud", json!("other-application")),
            ("iss", json!("https://other-idp.example.com")),
            ("exp", json!(now_secs() - 3600)),
            ("nbf", json!(now_secs() + 3600)),
        ] {
            let mut claims = identity_provider.claims("alice", &["admins"]);
            claims[claim_name] = claim_value;
            claims_variants.push(claims);
        }
        for claims in claims_variants {
            let jwt = identity_provider.sign(&claims);
            let error = verifier.verify(&jwt).await.unwrap_err();
            assert!(
                matches!(error, TokenExchangeError::InvalidJwt(_)),
                "{claims}: {error:?}"
            );
        }
        // Signed by another key.
        let other_identity_provider = TestIdentityProvider::new();
        let jwt = other_identity_provider.sign(&identity_provider.claims("alice", &["admins"]));
        assert!(matches!(
            verifier.verify(&jwt).await.unwrap_err(),
            TokenExchangeError::InvalidJwt(_)
        ));
        // Not a JWT.
        assert!(matches!(
            verifier.verify("not-a-jwt").await.unwrap_err(),
            TokenExchangeError::InvalidJwt(_)
        ));
    }

    #[test]
    fn test_identity_from_claims() {
        let claims = json!({
            "sub": "alice",
            "exp": 1_000,
            "scope": "openid quickwit:read",
            "realm_access": {"roles": ["admins"]},
        });
        let identity = identity_from_claims(&claims, "sub", "realm_access.roles").unwrap();
        assert_eq!(identity.claim_roles, vec!["admins"]);
        let identity = identity_from_claims(&claims, "sub", "scope").unwrap();
        assert_eq!(identity.claim_roles, vec!["openid", "quickwit:read"]);
        let identity = identity_from_claims(&claims, "sub", "groups").unwrap();
        assert!(identity.claim_roles.is_empty());
        identity_from_claims(&claims, "email", "groups").unwrap_err();
        identity_from_claims(&claims, "sub", "exp").unwrap_err();
    }
}
