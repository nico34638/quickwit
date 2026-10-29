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

use std::str::FromStr;

use anyhow::bail;
use biscuit_auth::{Authorizer, AuthorizerBuilder};
use tracing::debug;

use crate::context::current_token;
use crate::state::{EnabledState, enabled_state};
use crate::{AuthorizationError, AuthorizationToken};

/// Coarse-grained family of operations a request belongs to.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum RequestFamily {
    #[default]
    IndexRead,
    IndexWrite,
    IndexAdmin,
    Cluster,
}

impl RequestFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IndexRead => "index:read",
            Self::IndexWrite => "index:write",
            Self::IndexAdmin => "index:admin",
            Self::Cluster => "cluster",
        }
    }
}

impl FromStr for RequestFamily {
    type Err = anyhow::Error;

    fn from_str(request_family_str: &str) -> anyhow::Result<Self> {
        match request_family_str {
            "index:read" => Ok(Self::IndexRead),
            "index:write" => Ok(Self::IndexWrite),
            "index:admin" => Ok(Self::IndexAdmin),
            "cluster" => Ok(Self::Cluster),
            _ => bail!(
                "unknown right `{request_family_str}`, expected one of `index:read`, \
                 `index:write`, `index:admin`, `cluster`"
            ),
        }
    }
}

/// Implemented by every request type that goes through an [`crate::AuthorizationLayer`].
pub trait Authorization {
    fn request_family(&self) -> RequestFamily;
}

/// Without a request family, only the checks of the token itself (expiration) are evaluated.
fn build_authorizer(
    state: &EnabledState,
    request_family_opt: Option<RequestFamily>,
    token: &AuthorizationToken,
) -> Result<Authorizer, AuthorizationError> {
    // A `check all` without any matching fact fails, so the check is only added with a request.
    let request_datalog = match request_family_opt {
        Some(request_family) => format!(
            "request(\"{}\");\ncheck all request($request), right($request);",
            request_family.as_str()
        ),
        None => String::new(),
    };
    // Node tokens (`service(...)` facts) are granted every right: nodes act on behalf of
    // background tasks and of users whose rights were already checked at the edge.
    let datalog = format!(
        r#"
        {request_datalog}

        right($request) <- role($role), role_right($role, $request);
        right($request) <- service($service), request($request);

        {}

        allow if true;
        "#,
        state.role_rights_datalog
    );
    let authorizer = AuthorizerBuilder::new()
        .code(datalog)
        .map_err(|_| AuthorizationError::PermissionDenied)?
        .time()
        .build(token.biscuit())
        .map_err(|_| AuthorizationError::InvalidToken)?;
    Ok(authorizer)
}

pub(crate) fn authorize_with_token(
    state: &EnabledState,
    request_family: RequestFamily,
    token: &AuthorizationToken,
) -> Result<(), AuthorizationError> {
    authorize_with_optional_family(state, Some(request_family), token)
}

pub(crate) fn authorize_with_optional_family(
    state: &EnabledState,
    request_family_opt: Option<RequestFamily>,
    token: &AuthorizationToken,
) -> Result<(), AuthorizationError> {
    let mut authorizer = build_authorizer(state, request_family_opt, token)?;
    authorizer.authorize().map_err(|error| {
        debug!(
            request_family = request_family_opt.map(|request_family| request_family.as_str()),
            error = %error,
            "permission denied"
        );
        AuthorizationError::PermissionDenied
    })?;
    Ok(())
}

/// Checks the request against the token of the current task. Fails if there is none: see
/// [`crate::context::current_token`].
///
/// Always succeeds when authorization is disabled.
pub fn authorize_request<R: Authorization>(request: &R) -> Result<(), AuthorizationError> {
    let Some(state) = enabled_state() else {
        return Ok(());
    };
    let Some(token) = current_token(std::any::type_name::<R>()) else {
        return Err(AuthorizationError::AuthorizationTokenMissing);
    };
    authorize_with_token(state, request.request_family(), &token)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use biscuit_auth::PublicKey;

    use super::*;
    use crate::state::build_enabled_state_for_tests;
    use crate::{AuthorizationSettings, UserTokenSpec, generate_root_key_pair, generate_token};

    fn make_state() -> (String, EnabledState) {
        let (private_key_hex, public_key_hex) = generate_root_key_pair();
        let node_token_base64 = generate_token(
            &private_key_hex,
            &UserTokenSpec {
                services: vec!["searcher".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        let mut roles = BTreeMap::new();
        roles.insert("reader".to_string(), vec!["index:read".to_string()]);
        roles.insert(
            "admin".to_string(),
            vec![
                "index:read".to_string(),
                "index:write".to_string(),
                "index:admin".to_string(),
                "cluster".to_string(),
            ],
        );
        let settings = AuthorizationSettings {
            root_public_key_hex: public_key_hex,
            node_token_base64,
            roles,
        };
        (private_key_hex, build_enabled_state_for_tests(&settings))
    }

    fn make_user_token(
        private_key_hex: &str,
        public_key: PublicKey,
        roles: &[&str],
        ttl_opt: Option<std::time::Duration>,
    ) -> AuthorizationToken {
        let spec = UserTokenSpec {
            user_opt: Some("alice".to_string()),
            roles: roles.iter().map(|role| role.to_string()).collect(),
            ttl_opt,
            ..Default::default()
        };
        let token_base64 = generate_token(private_key_hex, &spec).unwrap();
        AuthorizationToken::parse(&token_base64, public_key).unwrap()
    }

    #[test]
    fn test_request_family_from_str() {
        for request_family in [
            RequestFamily::IndexRead,
            RequestFamily::IndexWrite,
            RequestFamily::IndexAdmin,
            RequestFamily::Cluster,
        ] {
            assert_eq!(
                RequestFamily::from_str(request_family.as_str()).unwrap(),
                request_family
            );
        }
        RequestFamily::from_str("index:delete").unwrap_err();
    }

    #[test]
    fn test_role_rights() {
        let (private_key_hex, state) = make_state();
        let reader = make_user_token(&private_key_hex, state.root_public_key, &["reader"], None);
        authorize_with_token(&state, RequestFamily::IndexRead, &reader).unwrap();
        assert_eq!(
            authorize_with_token(&state, RequestFamily::IndexAdmin, &reader).unwrap_err(),
            AuthorizationError::PermissionDenied
        );
        let admin = make_user_token(&private_key_hex, state.root_public_key, &["admin"], None);
        authorize_with_token(&state, RequestFamily::IndexAdmin, &admin).unwrap();
        authorize_with_token(&state, RequestFamily::Cluster, &admin).unwrap();
    }

    #[test]
    fn test_unknown_role_has_no_right() {
        let (private_key_hex, state) = make_state();
        let token = make_user_token(&private_key_hex, state.root_public_key, &["intern"], None);
        assert_eq!(
            authorize_with_token(&state, RequestFamily::IndexRead, &token).unwrap_err(),
            AuthorizationError::PermissionDenied
        );
    }

    #[test]
    fn test_node_token_has_all_rights() {
        let (_, state) = make_state();
        authorize_with_token(&state, RequestFamily::IndexAdmin, &state.node_token).unwrap();
        authorize_with_token(&state, RequestFamily::Cluster, &state.node_token).unwrap();
    }

    #[test]
    fn test_expired_token() {
        let (private_key_hex, state) = make_state();
        let token = make_user_token(
            &private_key_hex,
            state.root_public_key,
            &["admin"],
            Some(std::time::Duration::ZERO),
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert_eq!(
            authorize_with_token(&state, RequestFamily::IndexRead, &token).unwrap_err(),
            AuthorizationError::PermissionDenied
        );
    }

    #[test]
    fn test_authorize_without_request_family_checks_expiration() {
        let (private_key_hex, state) = make_state();
        let reader = make_user_token(&private_key_hex, state.root_public_key, &["reader"], None);
        authorize_with_optional_family(&state, None, &reader).unwrap();
        let intern = make_user_token(&private_key_hex, state.root_public_key, &["intern"], None);
        authorize_with_optional_family(&state, None, &intern).unwrap();
        let expired = make_user_token(
            &private_key_hex,
            state.root_public_key,
            &["admin"],
            Some(std::time::Duration::ZERO),
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert_eq!(
            authorize_with_optional_family(&state, None, &expired).unwrap_err(),
            AuthorizationError::PermissionDenied
        );
    }

    struct ReadRequest;

    impl Authorization for ReadRequest {
        fn request_family(&self) -> RequestFamily {
            RequestFamily::IndexRead
        }
    }

    #[test]
    fn test_authorize_request_disabled() {
        // `init_authorization` is never called in this test binary: authorization is disabled.
        authorize_request(&ReadRequest).unwrap();
    }
}
