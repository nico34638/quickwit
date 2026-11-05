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

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use anyhow::{bail, ensure};
use serde::{Deserialize, Serialize};

use crate::serde_utils::HumanDuration;

const QW_AUTH_ROOT_PUBLIC_KEY: &str = "QW_AUTH_ROOT_PUBLIC_KEY";
const QW_AUTH_NODE_TOKEN: &str = "QW_AUTH_NODE_TOKEN";
const QW_AUTH_ROOT_PRIVATE_KEY: &str = "QW_AUTH_ROOT_PRIVATE_KEY";

/// The `authorization` section of the node config. Authorization is disabled when it is absent.
///
/// The keys and roles are validated when authorization is initialized at node startup.
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationConfig {
    /// Hex-encoded public key of the root key pair that signs every token.
    /// Can be overridden with the `QW_AUTH_ROOT_PUBLIC_KEY` environment variable.
    #[serde(default)]
    pub root_public_key: String,
    /// Base64-encoded token used by this node for its own gRPC calls.
    /// Can be overridden with the `QW_AUTH_NODE_TOKEN` environment variable.
    #[serde(default)]
    pub node_token: String,
    /// Hex-encoded private key of the root key pair, to sign the tokens issued by the JWT token
    /// exchange (`POST /api/v1/auth/token`). Only the nodes that serve the exchange need it: any
    /// node holding it can issue tokens with any role.
    /// Can be overridden with the `QW_AUTH_ROOT_PRIVATE_KEY` environment variable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub root_private_key: String,
    /// Role name -> rights granted to the role (`index:read`, `index:write`, `index:admin`,
    /// `cluster`), on all the indexes or on some index ID patterns.
    #[serde(default)]
    pub roles: BTreeMap<String, RoleConfig>,
    /// Exchange of JWTs issued by an identity provider (OIDC) for Quickwit tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt: Option<JwtConfig>,
}

/// Validation of the JWTs exchanged for Quickwit tokens, and mapping of their claims to roles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    /// Expected `iss` claim.
    pub issuer: String,
    /// Expected `aud` claim: without it, the JWTs issued by the identity provider to any other
    /// application would be accepted.
    pub audience: String,
    /// URL of the JSON Web Key Set of the identity provider. Exclusive with `jwks_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,
    /// Path of a JSON Web Key Set file. Exclusive with `jwks_url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_path: Option<String>,
    /// Claim holding the user name.
    #[serde(default = "JwtConfig::default_user_claim")]
    pub user_claim: String,
    /// Claim holding the groups or roles of the user: an array of strings, or a string of
    /// space-separated values. Nested claims are reached with dots (`realm_access.roles`).
    #[serde(default = "JwtConfig::default_roles_claim")]
    pub roles_claim: String,
    /// Claim value -> Quickwit roles. Without mapping, the claim values that are Quickwit role
    /// names are used as such.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub role_mapping: BTreeMap<String, Vec<String>>,
    /// Validity of the issued tokens, capped by the expiration of the JWT.
    #[serde(default = "JwtConfig::default_token_ttl")]
    pub token_ttl: HumanDuration,
}

impl JwtConfig {
    fn default_user_claim() -> String {
        "sub".to_string()
    }

    fn default_roles_claim() -> String {
        "roles".to_string()
    }

    fn default_token_ttl() -> HumanDuration {
        HumanDuration::try_from("1h".to_string()).expect("`1h` should be a valid human duration")
    }

    fn validate(&self, roles: &BTreeMap<String, RoleConfig>) -> anyhow::Result<()> {
        ensure!(
            !self.issuer.is_empty(),
            "`authorization.jwt.issuer` must not be empty"
        );
        ensure!(
            !self.audience.is_empty(),
            "`authorization.jwt.audience` must not be empty"
        );
        match (&self.jwks_url, &self.jwks_path) {
            (Some(_), None) | (None, Some(_)) => {}
            _ => bail!(
                "exactly one of `authorization.jwt.jwks_url` and `authorization.jwt.jwks_path` \
                 must be set"
            ),
        }
        ensure!(
            !self.token_ttl.is_zero(),
            "`authorization.jwt.token_ttl` must be greater than zero"
        );
        for (claim_value, mapped_roles) in &self.role_mapping {
            for role in mapped_roles {
                ensure!(
                    roles.contains_key(role),
                    "`authorization.jwt.role_mapping` maps `{claim_value}` to the unknown role \
                     `{role}`"
                );
            }
        }
        Ok(())
    }
}

/// The rights of a role:
/// - either a list of rights, granted on all the indexes: `[index:read, index:write]`;
/// - or a list of grants: `[{rights: [index:read], indexes: ["app-*", "-app-secret*"]}]`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RoleConfig {
    Rights(Vec<String>),
    Grants(Vec<RoleGrantConfig>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleGrantConfig {
    pub rights: Vec<String>,
    /// Index ID patterns the rights apply to. `*` matches any sequence of characters, and
    /// patterns starting with `-` exclude indexes.
    #[serde(default = "RoleGrantConfig::default_indexes")]
    pub indexes: Vec<String>,
}

impl RoleGrantConfig {
    fn default_indexes() -> Vec<String> {
        vec!["*".to_string()]
    }
}

impl RoleConfig {
    /// Returns the grants of the role. Rights given as a plain list apply to all the indexes.
    pub fn grants(&self) -> Vec<RoleGrantConfig> {
        match self {
            RoleConfig::Rights(rights) => vec![RoleGrantConfig {
                rights: rights.clone(),
                indexes: RoleGrantConfig::default_indexes(),
            }],
            RoleConfig::Grants(grants) => grants.clone(),
        }
    }
}

// The node token and the root private key are credentials: never print them (the node config is
// logged at startup).
impl fmt::Debug for AuthorizationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let root_private_key = if self.root_private_key.is_empty() {
            ""
        } else {
            "***redacted***"
        };
        formatter
            .debug_struct("AuthorizationConfig")
            .field("root_public_key", &self.root_public_key)
            .field("node_token", &"***redacted***")
            .field("root_private_key", &root_private_key)
            .field("roles", &self.roles)
            .field("jwt", &self.jwt)
            .finish()
    }
}

impl AuthorizationConfig {
    pub(crate) fn resolve(mut self, env_vars: &HashMap<String, String>) -> anyhow::Result<Self> {
        if let Some(root_public_key) = env_vars.get(QW_AUTH_ROOT_PUBLIC_KEY) {
            self.root_public_key = root_public_key.clone();
        }
        if let Some(node_token) = env_vars.get(QW_AUTH_NODE_TOKEN) {
            self.node_token = node_token.clone();
        }
        if let Some(root_private_key) = env_vars.get(QW_AUTH_ROOT_PRIVATE_KEY) {
            self.root_private_key = root_private_key.clone();
        }
        ensure!(
            !self.root_public_key.is_empty(),
            "`authorization.root_public_key` must be set when authorization is enabled"
        );
        ensure!(
            !self.node_token.is_empty(),
            "`authorization.node_token` must be set when authorization is enabled"
        );
        if let Some(jwt_config) = &self.jwt {
            jwt_config.validate(&self.roles)?;
        }
        Ok(self)
    }

    pub(crate) fn redact(&mut self) {
        self.node_token = "***redacted***".to_string();
        if !self.root_private_key.is_empty() {
            self.root_private_key = "***redacted***".to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_config_from_yaml() {
        let yaml = r#"
            root_public_key: abcd
            node_token: efgh
            roles:
              reader: [index:read]
        "#;
        let config: AuthorizationConfig = serde_yaml::from_str(yaml).unwrap();
        let config = config.resolve(&HashMap::new()).unwrap();
        assert_eq!(config.root_public_key, "abcd");
        assert_eq!(
            config.roles["reader"].grants(),
            vec![RoleGrantConfig {
                rights: vec!["index:read".to_string()],
                indexes: vec!["*".to_string()],
            }]
        );
    }

    #[test]
    fn test_authorization_config_role_grants_from_yaml() {
        let yaml = r#"
            root_public_key: abcd
            node_token: efgh
            roles:
              app-reader:
                - rights: [index:read]
                  indexes: ["app-*", "-app-secret*"]
                - rights: [index:write]
        "#;
        let config: AuthorizationConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            config.roles["app-reader"].grants(),
            vec![
                RoleGrantConfig {
                    rights: vec!["index:read".to_string()],
                    indexes: vec!["app-*".to_string(), "-app-secret*".to_string()],
                },
                RoleGrantConfig {
                    rights: vec!["index:write".to_string()],
                    indexes: vec!["*".to_string()],
                },
            ]
        );
        let unknown_field_yaml = r#"
            roles:
              app-reader:
                - rights: [index:read]
                  index: ["app-*"]
        "#;
        serde_yaml::from_str::<AuthorizationConfig>(unknown_field_yaml).unwrap_err();
    }

    #[test]
    fn test_authorization_config_env_override() {
        let config = AuthorizationConfig::default();
        let env_vars = HashMap::from([
            (QW_AUTH_ROOT_PUBLIC_KEY.to_string(), "abcd".to_string()),
            (QW_AUTH_NODE_TOKEN.to_string(), "efgh".to_string()),
        ]);
        let config = config.resolve(&env_vars).unwrap();
        assert_eq!(config.root_public_key, "abcd");
        assert_eq!(config.node_token, "efgh");
    }

    #[test]
    fn test_authorization_config_requires_keys() {
        AuthorizationConfig::default()
            .resolve(&HashMap::new())
            .unwrap_err();
    }

    #[test]
    fn test_authorization_config_debug_redacts_node_token() {
        let config = AuthorizationConfig {
            node_token: "secret-node-token".to_string(),
            ..Default::default()
        };
        let debug_str = format!("{config:?}");
        assert!(!debug_str.contains("secret-node-token"));
        assert!(debug_str.contains("***redacted***"));
    }

    #[test]
    fn test_authorization_config_jwt_from_yaml() {
        let yaml = r#"
            root_public_key: abcd
            node_token: efgh
            roles:
              admin: [index:read, index:write, index:admin, cluster]
            jwt:
              issuer: https://idp.example.com
              audience: quickwit
              jwks_url: https://idp.example.com/jwks.json
              roles_claim: realm_access.roles
              role_mapping:
                quickwit-admins: [admin]
        "#;
        let config: AuthorizationConfig = serde_yaml::from_str(yaml).unwrap();
        let config = config.resolve(&HashMap::new()).unwrap();
        let jwt_config = config.jwt.unwrap();
        assert_eq!(jwt_config.user_claim, "sub");
        assert_eq!(jwt_config.roles_claim, "realm_access.roles");
        assert_eq!(*jwt_config.token_ttl, std::time::Duration::from_secs(3600));
        assert_eq!(
            jwt_config.role_mapping["quickwit-admins"],
            vec!["admin".to_string()]
        );
    }

    #[test]
    fn test_authorization_config_jwt_validation() {
        let make_config = |jwt_yaml: &str| -> anyhow::Result<AuthorizationConfig> {
            let yaml = format!(
                "root_public_key: abcd\nnode_token: efgh\nroles:\n  admin: \
                 [index:read]\njwt:\n{jwt_yaml}"
            );
            serde_yaml::from_str::<AuthorizationConfig>(&yaml)?.resolve(&HashMap::new())
        };
        make_config("  issuer: iss\n  audience: aud\n  jwks_path: /jwks.json\n").unwrap();
        // Missing audience.
        make_config("  issuer: iss\n  jwks_path: /jwks.json\n").unwrap_err();
        // No key set, or both.
        make_config("  issuer: iss\n  audience: aud\n").unwrap_err();
        make_config(
            "  issuer: iss\n  audience: aud\n  jwks_path: /jwks.json\n  jwks_url: http://idp\n",
        )
        .unwrap_err();
        // Mapping to an unknown role.
        make_config(
            "  issuer: iss\n  audience: aud\n  jwks_path: /jwks.json\n  role_mapping:\n    \
             admins: [superuser]\n",
        )
        .unwrap_err();
    }

    #[test]
    fn test_authorization_config_redacts_root_private_key() {
        let mut config = AuthorizationConfig {
            root_private_key: "secret-private-key".to_string(),
            ..Default::default()
        };
        assert!(!format!("{config:?}").contains("secret-private-key"));
        config.redact();
        assert_eq!(config.root_private_key, "***redacted***");
        let env_vars = HashMap::from([
            (QW_AUTH_ROOT_PUBLIC_KEY.to_string(), "abcd".to_string()),
            (QW_AUTH_NODE_TOKEN.to_string(), "efgh".to_string()),
            (QW_AUTH_ROOT_PRIVATE_KEY.to_string(), "ijkl".to_string()),
        ]);
        let config = AuthorizationConfig::default().resolve(&env_vars).unwrap();
        assert_eq!(config.root_private_key, "ijkl");
    }

    #[test]
    fn test_authorization_config_rejects_unknown_fields() {
        serde_yaml::from_str::<AuthorizationConfig>("license: foo").unwrap_err();
    }
}
