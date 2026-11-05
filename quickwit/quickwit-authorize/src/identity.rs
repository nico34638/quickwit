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

//! Description of the identity and the rights of the current task, for clients that adapt to them
//! (the UI, through `GET /api/v1/auth/whoami`).

use crate::authorizer::{Principal, authenticate};
use crate::context::current_token;
use crate::policy::{IndexScope, RoleGrantSettings};
use crate::state::{EnabledState, enabled_state};
use crate::{AuthorizationError, AuthorizationToken, RequestFamily};

/// Who the current task runs on behalf of, and what it is allowed to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    /// `None` for tokens issued without user name.
    pub user_opt: Option<String>,
    pub roles: Vec<String>,
    /// Node tokens are granted every right.
    pub is_node: bool,
    /// Grants of the roles, as configured. Empty for node tokens.
    pub grants: Vec<RoleGrantSettings>,
    /// Whether the `cluster` right is granted.
    pub has_cluster_right: bool,
}

fn identity_of_token(
    state: &EnabledState,
    token: &AuthorizationToken,
) -> Result<Identity, AuthorizationError> {
    match authenticate(state, token)? {
        Principal::Node => Ok(Identity {
            user_opt: None,
            roles: Vec::new(),
            is_node: true,
            grants: Vec::new(),
            has_cluster_right: true,
        }),
        Principal::User { user_opt, roles } => {
            let grants = state.policy.grant_settings(&roles);
            let has_cluster_right =
                state
                    .policy
                    .is_allowed(&roles, RequestFamily::Cluster, &IndexScope::NoIndex);
            Ok(Identity {
                user_opt,
                roles,
                is_node: false,
                grants,
                has_cluster_right,
            })
        }
    }
}

/// Returns the identity of the current task, or `None` when authorization is disabled.
///
/// Fails if the current task has no valid token.
pub fn current_identity() -> Result<Option<Identity>, AuthorizationError> {
    let Some(state) = enabled_state() else {
        return Ok(None);
    };
    let Some(token) = current_token("identity") else {
        return Err(AuthorizationError::AuthorizationTokenMissing);
    };
    identity_of_token(state, &token).map(Some)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::state::build_enabled_state_for_tests;
    use crate::{AuthorizationSettings, UserTokenSpec, generate_root_key_pair, generate_token};

    #[test]
    fn test_identity_of_token() {
        let (private_key_hex, public_key_hex) = generate_root_key_pair();
        let node_token_base64 = generate_token(
            &private_key_hex,
            &UserTokenSpec {
                services: vec!["node".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        let app_reader_grants = vec![RoleGrantSettings {
            rights: vec!["index:read".to_string()],
            indexes: vec!["app-*".to_string()],
        }];
        let settings = AuthorizationSettings {
            root_public_key_hex: public_key_hex,
            node_token_base64,
            roles: BTreeMap::from([("app-reader".to_string(), app_reader_grants.clone())]),
        };
        let state = build_enabled_state_for_tests(&settings);

        let user_token_base64 = generate_token(
            &private_key_hex,
            &UserTokenSpec {
                user_opt: Some("alice".to_string()),
                roles: vec!["app-reader".to_string(), "intern".to_string()],
                ..Default::default()
            },
        )
        .unwrap();
        let user_token =
            AuthorizationToken::parse(&user_token_base64, state.root_public_key).unwrap();
        let identity = identity_of_token(&state, &user_token).unwrap();
        assert_eq!(
            identity,
            Identity {
                user_opt: Some("alice".to_string()),
                roles: vec!["app-reader".to_string(), "intern".to_string()],
                is_node: false,
                grants: app_reader_grants,
                has_cluster_right: false,
            }
        );

        let node_identity = identity_of_token(&state, &state.node_token).unwrap();
        assert!(node_identity.is_node);
        assert!(node_identity.has_cluster_right);

        // A block appended by the holder of the token cannot grant roles nor the node identity.
        let attenuated_token_base64 = crate::attenuate_token(
            &user_token_base64,
            r#"role("admin"); service("node"); user("root");"#,
        )
        .unwrap();
        let attenuated_token =
            AuthorizationToken::parse(&attenuated_token_base64, state.root_public_key).unwrap();
        let attenuated_identity = identity_of_token(&state, &attenuated_token).unwrap();
        assert_eq!(attenuated_identity.user_opt.as_deref(), Some("alice"));
        assert_eq!(attenuated_identity.roles, identity.roles);
        assert!(!attenuated_identity.is_node);

        // Its checks restrict the token: a failing check rejects it.
        let restricted_token_base64 = crate::attenuate_token(
            &user_token_base64,
            "check if time($time), $time < 2000-01-01T00:00:00Z;",
        )
        .unwrap();
        let restricted_token =
            AuthorizationToken::parse(&restricted_token_base64, state.root_public_key).unwrap();
        assert_eq!(
            identity_of_token(&state, &restricted_token).unwrap_err(),
            AuthorizationError::ExpiredToken
        );
    }
}
