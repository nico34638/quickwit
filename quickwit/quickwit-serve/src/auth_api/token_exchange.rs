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

//! Exchange of a JWT issued by an identity provider for a Quickwit token (biscuit).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, ensure};
use quickwit_authorize::{TokenIssuer, UserTokenSpec};
use quickwit_config::AuthorizationConfig;
use quickwit_proto::{ServiceError, ServiceErrorCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::info;

use super::jwt::{JwtIdentity, JwtVerifier};

#[derive(Debug, thiserror::Error)]
pub(crate) enum TokenExchangeError {
    #[error(
        "token exchange is not enabled on this node: it requires the `authorization.jwt` and \
         `authorization.root_private_key` settings"
    )]
    NotEnabled,
    #[error("missing JWT: expected an `Authorization: Bearer <JWT>` header")]
    MissingJwt,
    #[error("invalid JWT: {0}")]
    InvalidJwt(String),
    #[error("the JWT does not grant any Quickwit role")]
    NoRole,
    #[error("{0}")]
    JwksUnavailable(String),
    #[error("failed to issue token: {0}")]
    Internal(String),
}

impl ServiceError for TokenExchangeError {
    fn error_code(&self) -> ServiceErrorCode {
        match self {
            Self::NotEnabled => ServiceErrorCode::NotFound,
            Self::MissingJwt | Self::InvalidJwt(_) => ServiceErrorCode::Unauthenticated,
            Self::NoRole => ServiceErrorCode::Forbidden,
            Self::JwksUnavailable(_) => ServiceErrorCode::Unavailable,
            Self::Internal(_) => ServiceErrorCode::Internal,
        }
    }
}

/// Response of `POST /api/v1/auth/token`.
#[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct TokenExchangeResponse {
    /// Quickwit token, to send in the `Authorization: Bearer <token>` header.
    pub token: String,
    pub user: String,
    pub roles: Vec<String>,
    /// Expiration of the token (RFC 3339).
    pub expires_at: String,
}

// No `Debug` derive: the token issuer holds the root private key.
pub(crate) struct TokenExchange {
    jwt_verifier: JwtVerifier,
    token_issuer: TokenIssuer,
    /// Claim value -> Quickwit roles. Empty: the claim values are used as role names.
    role_mapping: BTreeMap<String, Vec<String>>,
    /// Roles of the node config: the other claim values grant nothing.
    known_roles: BTreeSet<String>,
    token_ttl: Duration,
}

impl TokenExchange {
    /// Returns `None` when the node does not serve the exchange: the `jwt` section is absent, or
    /// the node does not hold the root private key.
    pub fn try_new(authorization_config: &AuthorizationConfig) -> anyhow::Result<Option<Self>> {
        let Some(jwt_config) = &authorization_config.jwt else {
            return Ok(None);
        };
        if authorization_config.root_private_key.is_empty() {
            info!(
                "JWT token exchange not served by this node: `authorization.root_private_key` is \
                 not set"
            );
            return Ok(None);
        }
        let token_issuer =
            TokenIssuer::from_private_key_hex(&authorization_config.root_private_key)
                .context("invalid `authorization.root_private_key`")?;
        ensure!(
            token_issuer.public_key_hex() == authorization_config.root_public_key,
            "`authorization.root_private_key` does not match `authorization.root_public_key`"
        );
        let jwt_verifier = JwtVerifier::try_new(jwt_config)?;
        info!(issuer = jwt_config.issuer, "JWT token exchange enabled");
        Ok(Some(TokenExchange {
            jwt_verifier,
            token_issuer,
            role_mapping: jwt_config.role_mapping.clone(),
            known_roles: authorization_config.roles.keys().cloned().collect(),
            token_ttl: *jwt_config.token_ttl,
        }))
    }

    /// Verifies `jwt` and issues a token with the Quickwit roles granted by its claims. The token
    /// expires with the JWT at the latest.
    pub async fn exchange(&self, jwt: &str) -> Result<TokenExchangeResponse, TokenExchangeError> {
        let jwt_identity = self.jwt_verifier.verify(jwt).await?;
        let roles = self.map_roles(&jwt_identity);
        if roles.is_empty() {
            return Err(TokenExchangeError::NoRole);
        }
        let remaining_secs =
            jwt_identity.expires_at_secs - OffsetDateTime::now_utc().unix_timestamp();
        if remaining_secs <= 0 {
            // Accepted by the leeway of the JWT validation, but expired.
            return Err(TokenExchangeError::InvalidJwt("expired JWT".to_string()));
        }
        let ttl = self
            .token_ttl
            .min(Duration::from_secs(remaining_secs as u64));
        let spec = UserTokenSpec {
            user_opt: Some(jwt_identity.user.clone()),
            roles: roles.clone(),
            services: Vec::new(),
            ttl_opt: Some(ttl),
        };
        let issued_token = self
            .token_issuer
            .issue(&spec)
            .map_err(|error| TokenExchangeError::Internal(error.to_string()))?;
        let expires_at = issued_token
            .expires_at_opt
            .ok_or_else(|| {
                TokenExchangeError::Internal("issued token has no expiration".to_string())
            })?
            .format(&Rfc3339)
            .map_err(|error| TokenExchangeError::Internal(error.to_string()))?;
        info!(user = jwt_identity.user, roles = ?roles, "issued token for JWT");
        Ok(TokenExchangeResponse {
            token: issued_token.token_base64,
            user: jwt_identity.user,
            roles,
            expires_at,
        })
    }

    fn map_roles(&self, jwt_identity: &JwtIdentity) -> Vec<String> {
        let mut roles = BTreeSet::new();
        for claim_role in &jwt_identity.claim_roles {
            if self.role_mapping.is_empty() {
                roles.insert(claim_role.clone());
            } else if let Some(mapped_roles) = self.role_mapping.get(claim_role) {
                roles.extend(mapped_roles.iter().cloned());
            }
        }
        roles.retain(|role| self.known_roles.contains(role));
        roles.into_iter().collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use quickwit_authorize::generate_root_key_pair;
    use quickwit_config::{JwtConfig, RoleConfig};

    use super::*;
    use crate::auth_api::jwt::tests::{TEST_AUDIENCE, TEST_ISSUER, TestIdentityProvider};

    pub(crate) fn make_token_exchange(
        identity_provider: &TestIdentityProvider,
        role_mapping: BTreeMap<String, Vec<String>>,
    ) -> (TokenExchange, tempfile::NamedTempFile) {
        let jwks_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(jwks_file.path(), &identity_provider.jwks_json).unwrap();
        let (root_private_key, root_public_key) = generate_root_key_pair();
        let authorization_config = AuthorizationConfig {
            root_public_key,
            node_token: "unused".to_string(),
            root_private_key,
            roles: BTreeMap::from([
                (
                    "admin".to_string(),
                    RoleConfig::Rights(vec!["cluster".to_string()]),
                ),
                (
                    "reader".to_string(),
                    RoleConfig::Rights(vec!["index:read".to_string()]),
                ),
            ]),
            jwt: Some(JwtConfig {
                issuer: TEST_ISSUER.to_string(),
                audience: TEST_AUDIENCE.to_string(),
                jwks_url: None,
                jwks_path: Some(jwks_file.path().to_string_lossy().to_string()),
                user_claim: "sub".to_string(),
                roles_claim: "roles".to_string(),
                role_mapping,
                token_ttl: quickwit_config::HumanDuration::try_from("1h".to_string()).unwrap(),
            }),
        };
        let token_exchange = TokenExchange::try_new(&authorization_config)
            .unwrap()
            .unwrap();
        (token_exchange, jwks_file)
    }

    #[tokio::test]
    async fn test_token_exchange_maps_roles() {
        let identity_provider = TestIdentityProvider::new();
        let role_mapping = BTreeMap::from([
            ("qw-admins".to_string(), vec!["admin".to_string()]),
            ("qw-readers".to_string(), vec!["reader".to_string()]),
        ]);
        let (token_exchange, _jwks_file) = make_token_exchange(&identity_provider, role_mapping);
        let jwt = identity_provider.sign(
            &identity_provider.claims("alice@example.com", &["qw-readers", "unrelated-group"]),
        );
        let response = token_exchange.exchange(&jwt).await.unwrap();
        assert_eq!(response.user, "alice@example.com");
        assert_eq!(response.roles, vec!["reader".to_string()]);
        assert!(!response.token.is_empty());

        let jwt = identity_provider.sign(&identity_provider.claims("bob", &["unrelated-group"]));
        assert!(matches!(
            token_exchange.exchange(&jwt).await.unwrap_err(),
            TokenExchangeError::NoRole
        ));
    }

    #[tokio::test]
    async fn test_token_exchange_without_mapping_keeps_known_roles() {
        let identity_provider = TestIdentityProvider::new();
        let (token_exchange, _jwks_file) = make_token_exchange(&identity_provider, BTreeMap::new());
        let jwt = identity_provider.sign(&identity_provider.claims("alice", &["admin", "intern"]));
        let response = token_exchange.exchange(&jwt).await.unwrap();
        assert_eq!(response.roles, vec!["admin".to_string()]);
    }

    #[test]
    fn test_token_exchange_requires_matching_private_key() {
        let (_, root_public_key) = generate_root_key_pair();
        let (other_private_key, _) = generate_root_key_pair();
        let authorization_config = AuthorizationConfig {
            root_public_key,
            root_private_key: other_private_key,
            jwt: Some(JwtConfig {
                issuer: TEST_ISSUER.to_string(),
                audience: TEST_AUDIENCE.to_string(),
                jwks_url: Some("http://localhost/jwks.json".to_string()),
                jwks_path: None,
                user_claim: "sub".to_string(),
                roles_claim: "roles".to_string(),
                role_mapping: BTreeMap::new(),
                token_ttl: quickwit_config::HumanDuration::try_from("1h".to_string()).unwrap(),
            }),
            ..Default::default()
        };
        assert!(TokenExchange::try_new(&authorization_config).is_err());
        // Without private key, the node does not serve the exchange.
        let authorization_config = AuthorizationConfig {
            root_private_key: String::new(),
            ..authorization_config
        };
        assert!(
            TokenExchange::try_new(&authorization_config)
                .unwrap()
                .is_none()
        );
    }
}
