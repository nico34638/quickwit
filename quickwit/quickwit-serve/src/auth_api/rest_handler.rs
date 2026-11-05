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

use std::sync::Arc;

use quickwit_authorize::{AuthorizationError, Identity, current_identity};
use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection};

use super::token_exchange::{TokenExchange, TokenExchangeError, TokenExchangeResponse};
use crate::format::BodyFormat;
use crate::rest::recover_fn;
use crate::rest_api_response::into_rest_api_response;

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(exchange_token, whoami),
    components(schemas(TokenExchangeResponse, WhoamiResponse, WhoamiGrant))
)]
pub struct AuthApi;

/// Response of `GET /api/v1/auth/whoami`.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct WhoamiResponse {
    /// When `false`, no token is required and every operation is allowed.
    pub authorization_enabled: bool,
    pub user: Option<String>,
    pub roles: Vec<String>,
    /// The token is a node token, granted every right.
    pub node: bool,
    /// Grants of the roles: rights, and the index ID patterns they apply to.
    pub grants: Vec<WhoamiGrant>,
    /// Whether the `cluster` right is granted (cluster state, node config, developer API).
    pub cluster: bool,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct WhoamiGrant {
    pub rights: Vec<String>,
    pub indexes: Vec<String>,
}

impl WhoamiResponse {
    fn from_identity_opt(identity_opt: Option<Identity>) -> Self {
        let Some(identity) = identity_opt else {
            return WhoamiResponse {
                authorization_enabled: false,
                user: None,
                roles: Vec::new(),
                node: false,
                grants: Vec::new(),
                cluster: true,
            };
        };
        let grants = identity
            .grants
            .into_iter()
            .map(|grant| WhoamiGrant {
                rights: grant.rights,
                indexes: grant.indexes,
            })
            .collect();
        WhoamiResponse {
            authorization_enabled: true,
            user: identity.user_opt,
            roles: identity.roles,
            node: identity.is_node,
            grants,
            cluster: identity.has_cluster_right,
        }
    }
}

/// `GET /api/v1/auth/whoami`: describes the identity and the rights of the token of the request.
///
/// Hidden contract: served under the routes that require a valid token, so that the token of the
/// request is scoped in the task.
pub(crate) fn whoami_handler()
-> impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone {
    warp::path!("auth" / "whoami")
        .and(warp::get())
        .then(whoami)
        .map(|result| into_rest_api_response(result, BodyFormat::default()))
        .recover(recover_fn)
        .boxed()
}

#[utoipa::path(
    get,
    tag = "Authorization",
    path = "/auth/whoami",
    responses(
        (status = 200, description = "Identity and rights of the token.", body = WhoamiResponse),
        (status = 401, description = "The token is missing, invalid, or expired."),
    ),
)]
/// Describes the identity and the rights of the token of the request.
async fn whoami() -> Result<WhoamiResponse, AuthorizationError> {
    let identity_opt = current_identity()?;
    Ok(WhoamiResponse::from_identity_opt(identity_opt))
}

/// `POST /api/v1/auth/token`: exchanges the JWT of the `Authorization` header for a Quickwit
/// token.
///
/// Hidden contract: this route must be served outside of the routes that require a Quickwit
/// token, since its `Authorization` header carries a JWT.
pub(crate) fn auth_token_handler(
    token_exchange_opt: Option<Arc<TokenExchange>>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone {
    warp::path!("api" / "v1" / "auth" / "token")
        .and(warp::post())
        .and(warp::header::optional::<String>(
            http::header::AUTHORIZATION.as_str(),
        ))
        .then(move |authorization_header_opt: Option<String>| {
            let token_exchange_opt = token_exchange_opt.clone();
            async move { exchange_token(token_exchange_opt, authorization_header_opt).await }
        })
        .map(|result| into_rest_api_response(result, BodyFormat::default()))
        .recover(recover_fn)
        .boxed()
}

#[utoipa::path(
    post,
    tag = "Authorization",
    path = "/auth/token",
    responses(
        (status = 200, description = "Successfully exchanged the JWT.", body = TokenExchangeResponse),
        (status = 401, description = "The JWT is missing or invalid."),
        (status = 403, description = "The JWT does not grant any Quickwit role."),
        (status = 404, description = "The node does not serve the token exchange."),
    ),
)]
/// Exchanges a JWT for a Quickwit token.
///
/// The JWT is sent in the `Authorization: Bearer <JWT>` header. Its signature, issuer, audience,
/// and validity period are verified, and its roles claim is mapped to Quickwit roles.
async fn exchange_token(
    token_exchange_opt: Option<Arc<TokenExchange>>,
    authorization_header_opt: Option<String>,
) -> Result<TokenExchangeResponse, TokenExchangeError> {
    let Some(token_exchange) = token_exchange_opt else {
        return Err(TokenExchangeError::NotEnabled);
    };
    let jwt = authorization_header_opt
        .as_deref()
        .and_then(|header_value| header_value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|jwt| !jwt.is_empty())
        .ok_or(TokenExchangeError::MissingJwt)?;
    token_exchange.exchange(jwt).await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::auth_api::jwt::tests::TestIdentityProvider;
    use crate::auth_api::token_exchange::tests::make_token_exchange;

    #[tokio::test]
    async fn test_auth_token_handler() {
        let identity_provider = TestIdentityProvider::new();
        let (token_exchange, _jwks_file) = make_token_exchange(&identity_provider, BTreeMap::new());
        let handler = auth_token_handler(Some(Arc::new(token_exchange)));

        let jwt = identity_provider.sign(&identity_provider.claims("alice", &["reader"]));
        let response = warp::test::request()
            .path("/api/v1/auth/token")
            .method("POST")
            .header("authorization", format!("Bearer {jwt}"))
            .reply(&handler)
            .await;
        assert_eq!(response.status(), 200);
        let exchange_response: TokenExchangeResponse =
            serde_json::from_slice(response.body()).unwrap();
        assert_eq!(exchange_response.user, "alice");
        assert_eq!(exchange_response.roles, vec!["reader".to_string()]);

        let response = warp::test::request()
            .path("/api/v1/auth/token")
            .method("POST")
            .reply(&handler)
            .await;
        assert_eq!(response.status(), 401);

        let response = warp::test::request()
            .path("/api/v1/auth/token")
            .method("POST")
            .header("authorization", "Bearer not-a-jwt")
            .reply(&handler)
            .await;
        assert_eq!(response.status(), 401);
    }

    #[tokio::test]
    async fn test_whoami_handler_without_authorization() {
        // `init_authorization` is never called in this test binary: authorization is disabled.
        let response = warp::test::request()
            .path("/auth/whoami")
            .method("GET")
            .reply(&whoami_handler())
            .await;
        assert_eq!(response.status(), 200);
        let whoami_response: WhoamiResponse = serde_json::from_slice(response.body()).unwrap();
        assert!(!whoami_response.authorization_enabled);
        assert!(whoami_response.cluster);
    }

    #[test]
    fn test_whoami_response_from_identity() {
        let identity = Identity {
            user_opt: Some("alice".to_string()),
            roles: vec!["app-reader".to_string()],
            is_node: false,
            grants: vec![quickwit_authorize::RoleGrantSettings {
                rights: vec!["index:read".to_string()],
                indexes: vec!["app-*".to_string()],
            }],
            has_cluster_right: false,
        };
        assert_eq!(
            WhoamiResponse::from_identity_opt(Some(identity)),
            WhoamiResponse {
                authorization_enabled: true,
                user: Some("alice".to_string()),
                roles: vec!["app-reader".to_string()],
                node: false,
                grants: vec![WhoamiGrant {
                    rights: vec!["index:read".to_string()],
                    indexes: vec!["app-*".to_string()],
                }],
                cluster: false,
            }
        );
    }

    #[tokio::test]
    async fn test_auth_token_handler_not_enabled() {
        let handler = auth_token_handler(None);
        let response = warp::test::request()
            .path("/api/v1/auth/token")
            .method("POST")
            .header("authorization", "Bearer some-jwt")
            .reply(&handler)
            .await;
        assert_eq!(response.status(), 404);
    }
}
