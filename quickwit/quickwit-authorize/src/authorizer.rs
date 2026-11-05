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
use std::time::Duration;

use anyhow::bail;
use biscuit_auth::{AuthorizerBuilder, AuthorizerLimits};
use tracing::debug;

use crate::context::current_token;
use crate::policy::IndexScope;
use crate::state::{EnabledState, enabled_state};
use crate::{AuthorizationError, AuthorizationToken};

/// Coarse-grained family of operations a request belongs to.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum RequestFamily {
    IndexRead,
    IndexWrite,
    IndexAdmin,
    /// Operations of the cluster operators: cluster state, node configuration, debug info.
    Cluster,
    /// Requests exchanged between the nodes of the cluster: splits publication, shard
    /// management, indexing plans, leaf searches, etc. Only node tokens are granted this family:
    /// it cannot be granted to a role, whatever its rights.
    Internal,
}

impl RequestFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IndexRead => "index:read",
            Self::IndexWrite => "index:write",
            Self::IndexAdmin => "index:admin",
            Self::Cluster => "cluster",
            Self::Internal => "internal",
        }
    }
}

/// Parses the rights that can be granted to a role: [`RequestFamily::Internal`] is not one of them.
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

/// Run limits of the datalog evaluation of a token.
///
/// The default limits of biscuit allow 1ms of evaluation, which a node under CPU pressure (a
/// searcher, typically) exceeds now and then: the request would then be denied. The number of
/// facts and iterations stay bounded: tokens can be attenuated by their holder, who controls the
/// datalog of the appended blocks.
const AUTHORIZER_LIMITS: AuthorizerLimits = AuthorizerLimits {
    max_facts: 1_000,
    max_iterations: 100,
    max_time: Duration::from_millis(100),
};

/// Returns the authorizer template shared by all the evaluations: it accepts any token whose own
/// checks (expiration, attenuation blocks) pass.
pub(crate) fn authorizer_template() -> anyhow::Result<AuthorizerBuilder> {
    let authorizer_builder = AuthorizerBuilder::new()
        .code("allow if true;")?
        .set_limits(AUTHORIZER_LIMITS);
    Ok(authorizer_builder)
}

/// Implemented by every request type that goes through an [`crate::AuthorizationLayer`].
pub trait Authorization {
    fn request_family(&self) -> RequestFamily;

    /// The indexes the request applies to. Hidden contract: a request whose index IDs cannot be
    /// extracted must return [`IndexScope::AllIndexes`], never a narrower scope.
    fn index_scope(&self) -> IndexScope;
}

/// Who a verified token was issued to.
#[derive(Debug)]
pub(crate) enum Principal {
    /// A node of the cluster (`service(...)` facts): it is granted every right.
    Node,
    /// A user with the `user(...)` and `role(...)` facts of the token.
    User {
        user_opt: Option<String>,
        roles: Vec<String>,
    },
}

/// Runs the checks of the token itself (expiration) and reads its identity facts.
///
/// Identity facts are only read from the authority block, signed by the root key: blocks
/// appended by the token holder cannot grant roles.
pub(crate) fn authenticate(
    state: &EnabledState,
    token: &AuthorizationToken,
) -> Result<Principal, AuthorizationError> {
    let mut authorizer = state
        .authorizer_template
        .clone()
        .time()
        .build(token.biscuit())
        .map_err(|error| {
            debug!(%error, "failed to load token in authorizer");
            AuthorizationError::InvalidToken
        })?;
    authorizer.authorize().map_err(|error| {
        debug!(%error, "token checks failed");
        AuthorizationError::ExpiredToken
    })?;
    // The checks passed: a failure from now on comes from the evaluation itself (run limits).
    let services: Vec<(String,)> = authorizer
        .query("data($service) <- service($service)")
        .map_err(|error| {
            debug!(%error, "failed to query token services");
            AuthorizationError::PermissionDenied
        })?;
    if !services.is_empty() {
        return Ok(Principal::Node);
    }
    let roles: Vec<(String,)> =
        authorizer
            .query("data($role) <- role($role)")
            .map_err(|error| {
                debug!(%error, "failed to query token roles");
                AuthorizationError::PermissionDenied
            })?;
    // The order of the query results is not specified.
    let mut roles: Vec<String> = roles.into_iter().map(|(role,)| role).collect();
    roles.sort();
    let users: Vec<(String,)> =
        authorizer
            .query("data($user) <- user($user)")
            .map_err(|error| {
                debug!(%error, "failed to query token user");
                AuthorizationError::PermissionDenied
            })?;
    let user_opt = users.into_iter().next().map(|(user,)| user);
    Ok(Principal::User { user_opt, roles })
}

pub(crate) fn authorize_with_token(
    state: &EnabledState,
    request_family: RequestFamily,
    index_scope: &IndexScope,
    token: &AuthorizationToken,
) -> Result<(), AuthorizationError> {
    let Principal::User { roles, .. } = authenticate(state, token)? else {
        return Ok(());
    };
    if state.policy.is_allowed(&roles, request_family, index_scope) {
        return Ok(());
    }
    debug!(
        request_family = request_family.as_str(),
        index_scope = ?index_scope,
        "permission denied"
    );
    Err(AuthorizationError::PermissionDenied)
}

/// Without a request family, only the checks of the token itself (expiration) are evaluated.
pub(crate) fn authorize_with_optional_family(
    state: &EnabledState,
    request_family_opt: Option<RequestFamily>,
    token: &AuthorizationToken,
) -> Result<(), AuthorizationError> {
    match request_family_opt {
        Some(request_family) => {
            authorize_with_token(state, request_family, &IndexScope::NoIndex, token)
        }
        None => authenticate(state, token).map(|_| ()),
    }
}

/// Checks the request against the token of the current task. Fails if there is none: see
/// [`crate::context::current_token`].
///
/// Always succeeds when authorization is disabled.
pub fn authorize_request<R: Authorization>(request: &R) -> Result<(), AuthorizationError> {
    authorize_operation(
        std::any::type_name::<R>(),
        request.request_family(),
        &request.index_scope(),
    )
}

/// Checks that the token of the current task grants `request_family` on `index_scope`, for
/// operations that are not a request going through an [`crate::AuthorizationLayer`] (for instance,
/// resuming a scroll whose indexes are only known once its context is loaded). `operation` names
/// the operation in the logs.
///
/// Always succeeds when authorization is disabled.
pub fn authorize_operation(
    operation: &str,
    request_family: RequestFamily,
    index_scope: &IndexScope,
) -> Result<(), AuthorizationError> {
    let Some(state) = enabled_state() else {
        return Ok(());
    };
    let Some(token) = current_token(operation) else {
        return Err(AuthorizationError::AuthorizationTokenMissing);
    };
    authorize_with_token(state, request_family, index_scope, &token)
}

/// Decides which indexes the current task may see in a listing.
pub enum IndexFilter {
    /// Authorization is disabled, or the current task runs on behalf of the node.
    AllowAll,
    /// The current task runs on behalf of a user with these roles.
    Roles {
        roles: Vec<String>,
        request_family: RequestFamily,
    },
    /// The current task has no valid token.
    DenyAll,
}

impl IndexFilter {
    pub fn is_index_allowed(&self, index_id: &str) -> bool {
        match self {
            IndexFilter::AllowAll => true,
            IndexFilter::Roles {
                roles,
                request_family,
            } => match enabled_state() {
                Some(state) => state
                    .policy
                    .is_index_allowed(roles, *request_family, index_id),
                None => true,
            },
            IndexFilter::DenyAll => false,
        }
    }

    pub fn is_allow_all(&self) -> bool {
        matches!(self, IndexFilter::AllowAll)
    }
}

/// Returns the filter to apply to the indexes listed for the current task, for `request_family`.
pub fn current_index_filter(request_family: RequestFamily) -> IndexFilter {
    let Some(state) = enabled_state() else {
        return IndexFilter::AllowAll;
    };
    let Some(token) = current_token("index listing") else {
        return IndexFilter::DenyAll;
    };
    match authenticate(state, &token) {
        Ok(Principal::Node) => IndexFilter::AllowAll,
        Ok(Principal::User { roles, .. }) => IndexFilter::Roles {
            roles,
            request_family,
        },
        Err(_) => IndexFilter::DenyAll,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use biscuit_auth::PublicKey;

    use super::*;
    use crate::policy::RoleGrantSettings;
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
        roles.insert(
            "reader".to_string(),
            vec![RoleGrantSettings {
                rights: vec!["index:read".to_string()],
                indexes: vec!["*".to_string()],
            }],
        );
        roles.insert(
            "admin".to_string(),
            vec![RoleGrantSettings {
                rights: vec![
                    "index:read".to_string(),
                    "index:write".to_string(),
                    "index:admin".to_string(),
                    "cluster".to_string(),
                ],
                indexes: vec!["*".to_string()],
            }],
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
        // The internal requests cannot be granted to a role.
        RequestFamily::from_str(RequestFamily::Internal.as_str()).unwrap_err();
    }

    #[test]
    fn test_internal_requests_are_reserved_to_nodes() {
        let (private_key_hex, state) = make_state();
        let admin = make_user_token(&private_key_hex, state.root_public_key, &["admin"], None);
        assert_eq!(
            authorize_with_token(
                &state,
                RequestFamily::Internal,
                &IndexScope::NoIndex,
                &admin
            )
            .unwrap_err(),
            AuthorizationError::PermissionDenied
        );
        authorize_with_token(
            &state,
            RequestFamily::Internal,
            &IndexScope::NoIndex,
            &state.node_token,
        )
        .unwrap();
    }

    #[test]
    fn test_role_rights() {
        let (private_key_hex, state) = make_state();
        let reader = make_user_token(&private_key_hex, state.root_public_key, &["reader"], None);
        authorize_with_token(
            &state,
            RequestFamily::IndexRead,
            &IndexScope::AnyIndex,
            &reader,
        )
        .unwrap();
        assert_eq!(
            authorize_with_token(
                &state,
                RequestFamily::IndexAdmin,
                &IndexScope::AnyIndex,
                &reader
            )
            .unwrap_err(),
            AuthorizationError::PermissionDenied
        );
        let admin = make_user_token(&private_key_hex, state.root_public_key, &["admin"], None);
        authorize_with_token(
            &state,
            RequestFamily::IndexAdmin,
            &IndexScope::AnyIndex,
            &admin,
        )
        .unwrap();
        authorize_with_token(
            &state,
            RequestFamily::Cluster,
            &IndexScope::AnyIndex,
            &admin,
        )
        .unwrap();
    }

    #[test]
    fn test_unknown_role_has_no_right() {
        let (private_key_hex, state) = make_state();
        let token = make_user_token(&private_key_hex, state.root_public_key, &["intern"], None);
        assert_eq!(
            authorize_with_token(
                &state,
                RequestFamily::IndexRead,
                &IndexScope::AnyIndex,
                &token
            )
            .unwrap_err(),
            AuthorizationError::PermissionDenied
        );
    }

    #[test]
    fn test_node_token_has_all_rights() {
        let (_, state) = make_state();
        authorize_with_token(
            &state,
            RequestFamily::IndexAdmin,
            &IndexScope::AnyIndex,
            &state.node_token,
        )
        .unwrap();
        authorize_with_token(
            &state,
            RequestFamily::Cluster,
            &IndexScope::AnyIndex,
            &state.node_token,
        )
        .unwrap();
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
            authorize_with_token(
                &state,
                RequestFamily::IndexRead,
                &IndexScope::AnyIndex,
                &token
            )
            .unwrap_err(),
            AuthorizationError::ExpiredToken
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
            AuthorizationError::ExpiredToken
        );
    }

    struct ReadRequest;

    impl Authorization for ReadRequest {
        fn request_family(&self) -> RequestFamily {
            RequestFamily::IndexRead
        }

        fn index_scope(&self) -> IndexScope {
            IndexScope::AnyIndex
        }
    }

    #[test]
    fn test_authorize_request_disabled() {
        // `init_authorization` is never called in this test binary: authorization is disabled.
        authorize_request(&ReadRequest).unwrap();
    }
}
