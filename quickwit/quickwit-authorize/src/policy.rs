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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

use anyhow::{Context, bail};

use crate::RequestFamily;

/// The indexes a request applies to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexScope {
    /// The request applies to these indexes: each of them must be granted. An empty list is
    /// checked like [`IndexScope::AnyIndex`].
    Indexes(Vec<String>),
    /// The request lists indexes and its response is filtered (see [`crate::IndexFilter`]), or it
    /// reads data whose indexes were checked by an upstream request (leaf searches): the family
    /// must be granted on at least one index.
    AnyIndex,
    /// The request applies to all the indexes, present or future (index templates, splits of all
    /// the indexes): the family must be granted on all the indexes.
    AllIndexes,
    /// The request does not apply to indexes (`cluster` family).
    NoIndex,
}

/// Index ID patterns of a grant. `*` matches any sequence of characters. An index matches if it
/// matches at least one positive pattern and no negative pattern (starting with `-`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct IndexPatterns {
    positive_patterns: Vec<String>,
    negative_patterns: Vec<String>,
}

impl IndexPatterns {
    pub(crate) fn parse(patterns: &[String]) -> anyhow::Result<Self> {
        let mut index_patterns = IndexPatterns::default();
        for pattern in patterns {
            let (is_negative, pattern) = match pattern.strip_prefix('-') {
                Some(pattern) => (true, pattern),
                None => (false, pattern.as_str()),
            };
            let is_valid = !pattern.is_empty()
                && pattern
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '*'));
            if !is_valid {
                bail!("invalid index ID pattern `{pattern}`");
            }
            if is_negative {
                index_patterns.negative_patterns.push(pattern.to_string());
            } else {
                index_patterns.positive_patterns.push(pattern.to_string());
            }
        }
        if index_patterns.positive_patterns.is_empty() {
            bail!("index ID patterns must contain at least one positive pattern");
        }
        Ok(index_patterns)
    }

    pub(crate) fn matches(&self, index_id: &str) -> bool {
        self.positive_patterns
            .iter()
            .any(|pattern| glob_matches(pattern, index_id))
            && !self
                .negative_patterns
                .iter()
                .any(|pattern| glob_matches(pattern, index_id))
    }

    /// Returns true if the patterns match any index ID.
    pub(crate) fn matches_all(&self) -> bool {
        self.positive_patterns.iter().any(|pattern| pattern == "*")
            && self.negative_patterns.is_empty()
    }
}

/// Matches `text` against `pattern`, where `*` matches any (possibly empty) sequence of
/// characters.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first_part = parts.next().unwrap_or_default();
    let Some(mut remaining) = text.strip_prefix(first_part) else {
        return false;
    };
    let other_parts: Vec<&str> = parts.collect();
    let Some((last_part, middle_parts)) = other_parts.split_last() else {
        // No `*` in the pattern.
        return remaining.is_empty();
    };
    for middle_part in middle_parts {
        let Some(position) = remaining.find(middle_part) else {
            return false;
        };
        remaining = &remaining[position + middle_part.len()..];
    }
    remaining.ends_with(last_part)
}

#[derive(Clone, Debug)]
pub(crate) struct Grant {
    rights: HashSet<RequestFamily>,
    index_patterns: IndexPatterns,
}

/// Rights of a role, as configured: the rights are granted on the indexes matching `indexes`.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct RoleGrantSettings {
    pub rights: Vec<String>,
    pub indexes: Vec<String>,
}

/// The roles of the node config: role name -> grants.
#[derive(Clone, Debug, Default)]
pub(crate) struct RolePolicy {
    grants_per_role: HashMap<String, Vec<Grant>>,
    /// The grants as configured, to describe the rights of a user.
    settings_per_role: BTreeMap<String, Vec<RoleGrantSettings>>,
}

impl RolePolicy {
    pub(crate) fn from_settings(
        roles: &BTreeMap<String, Vec<RoleGrantSettings>>,
    ) -> anyhow::Result<Self> {
        let mut grants_per_role = HashMap::with_capacity(roles.len());
        for (role, grant_settings) in roles {
            let mut grants = Vec::with_capacity(grant_settings.len());
            for grant_setting in grant_settings {
                let rights = grant_setting
                    .rights
                    .iter()
                    .map(|right| RequestFamily::from_str(right))
                    .collect::<anyhow::Result<HashSet<RequestFamily>>>()
                    .with_context(|| format!("invalid right for role `{role}`"))?;
                let index_patterns = IndexPatterns::parse(&grant_setting.indexes)
                    .with_context(|| format!("invalid index ID patterns for role `{role}`"))?;
                if rights.contains(&RequestFamily::Cluster) && !index_patterns.matches_all() {
                    bail!(
                        "the `cluster` right of role `{role}` does not apply to indexes: grant it \
                         on `*`"
                    );
                }
                grants.push(Grant {
                    rights,
                    index_patterns,
                });
            }
            grants_per_role.insert(role.clone(), grants);
        }
        Ok(RolePolicy {
            grants_per_role,
            settings_per_role: roles.clone(),
        })
    }

    /// Returns the grants of `roles`, as configured. Unknown roles have no grant.
    pub(crate) fn grant_settings(&self, roles: &[String]) -> Vec<RoleGrantSettings> {
        roles
            .iter()
            .filter_map(|role| self.settings_per_role.get(role))
            .flatten()
            .cloned()
            .collect()
    }

    fn grants<'a>(&'a self, roles: &'a [String]) -> impl Iterator<Item = &'a Grant> + 'a {
        roles
            .iter()
            .filter_map(|role| self.grants_per_role.get(role))
            .flatten()
    }

    fn grants_with_right<'a>(
        &'a self,
        roles: &'a [String],
        request_family: RequestFamily,
    ) -> impl Iterator<Item = &'a Grant> + 'a {
        self.grants(roles)
            .filter(move |grant| grant.rights.contains(&request_family))
    }

    pub(crate) fn is_allowed(
        &self,
        roles: &[String],
        request_family: RequestFamily,
        index_scope: &IndexScope,
    ) -> bool {
        let mut grants = self.grants_with_right(roles, request_family);
        match index_scope {
            // Without index, `all` below would allow the request without any right: an empty list
            // requires the family on at least one index, like `AnyIndex`.
            IndexScope::Indexes(index_ids) if !index_ids.is_empty() => {
                index_ids.iter().all(|index_id| {
                    self.grants_with_right(roles, request_family)
                        .any(|grant| grant.index_patterns.matches(index_id))
                })
            }
            IndexScope::Indexes(_) | IndexScope::AnyIndex | IndexScope::NoIndex => {
                grants.next().is_some()
            }
            IndexScope::AllIndexes => grants.any(|grant| grant.index_patterns.matches_all()),
        }
    }

    pub(crate) fn is_index_allowed(
        &self,
        roles: &[String],
        request_family: RequestFamily,
        index_id: &str,
    ) -> bool {
        self.grants_with_right(roles, request_family)
            .any(|grant| grant.index_patterns.matches(index_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns(patterns: &[&str]) -> IndexPatterns {
        let patterns: Vec<String> = patterns.iter().map(|pattern| pattern.to_string()).collect();
        IndexPatterns::parse(&patterns).unwrap()
    }

    #[test]
    fn test_glob_matches() {
        assert!(glob_matches("*", ""));
        assert!(glob_matches("*", "logs"));
        assert!(glob_matches("logs", "logs"));
        assert!(!glob_matches("logs", "logs-2"));
        assert!(glob_matches("logs*", "logs-2"));
        assert!(glob_matches("*-prod", "app-prod"));
        assert!(!glob_matches("*-prod", "app-prod-2"));
        assert!(glob_matches("app-*-logs", "app-billing-logs"));
        assert!(!glob_matches("app-*-logs", "app-billing-traces"));
        assert!(glob_matches("a*b*c", "aXbYc"));
        assert!(!glob_matches("a*b*c", "aXcYb"));
    }

    #[test]
    fn test_index_patterns() {
        let app_patterns = patterns(&["app-*", "-app-secret*"]);
        assert!(app_patterns.matches("app-billing"));
        assert!(!app_patterns.matches("app-secret-keys"));
        assert!(!app_patterns.matches("otel-logs"));
        assert!(!app_patterns.matches_all());
        assert!(patterns(&["*"]).matches_all());
        assert!(!patterns(&["*", "-secret"]).matches_all());

        IndexPatterns::parse(&["-secret".to_string()]).unwrap_err();
        IndexPatterns::parse(&["app/*".to_string()]).unwrap_err();
        IndexPatterns::parse(&[]).unwrap_err();
    }

    fn make_policy() -> RolePolicy {
        let roles = BTreeMap::from([
            (
                "app-reader".to_string(),
                vec![RoleGrantSettings {
                    rights: vec!["index:read".to_string()],
                    indexes: vec!["app-*".to_string(), "-app-secret*".to_string()],
                }],
            ),
            (
                "admin".to_string(),
                vec![RoleGrantSettings {
                    rights: vec![
                        "index:read".to_string(),
                        "index:admin".to_string(),
                        "cluster".to_string(),
                    ],
                    indexes: vec!["*".to_string()],
                }],
            ),
        ]);
        RolePolicy::from_settings(&roles).unwrap()
    }

    #[test]
    fn test_role_policy_index_scopes() {
        let policy = make_policy();
        let app_reader = ["app-reader".to_string()];
        let read = RequestFamily::IndexRead;
        let indexes = |index_ids: &[&str]| {
            IndexScope::Indexes(
                index_ids
                    .iter()
                    .map(|index_id| index_id.to_string())
                    .collect(),
            )
        };
        assert!(policy.is_allowed(&app_reader, read, &indexes(&["app-billing"])));
        assert!(!policy.is_allowed(&app_reader, read, &indexes(&["app-billing", "otel"])));
        assert!(!policy.is_allowed(&app_reader, read, &indexes(&["app-secret"])));
        // An empty list of indexes still requires the family on some index.
        assert!(policy.is_allowed(&app_reader, read, &indexes(&[])));
        assert!(!policy.is_allowed(&app_reader, RequestFamily::IndexWrite, &indexes(&[])));
        assert!(policy.is_allowed(&app_reader, read, &IndexScope::AnyIndex));
        assert!(!policy.is_allowed(&app_reader, read, &IndexScope::AllIndexes));
        assert!(!policy.is_allowed(
            &app_reader,
            RequestFamily::IndexWrite,
            &IndexScope::AnyIndex
        ));
        assert!(!policy.is_allowed(&app_reader, RequestFamily::Cluster, &IndexScope::NoIndex));

        let admin = ["admin".to_string()];
        assert!(policy.is_allowed(&admin, read, &IndexScope::AllIndexes));
        assert!(policy.is_allowed(&admin, RequestFamily::Cluster, &IndexScope::NoIndex));

        // Rights of several roles add up.
        let both = ["app-reader".to_string(), "admin".to_string()];
        assert!(policy.is_allowed(&both, read, &indexes(&["app-secret"])));

        let unknown = ["intern".to_string()];
        assert!(!policy.is_allowed(&unknown, read, &IndexScope::AnyIndex));
    }

    #[test]
    fn test_role_policy_rejects_cluster_right_on_some_indexes() {
        let roles = BTreeMap::from([(
            "ops".to_string(),
            vec![RoleGrantSettings {
                rights: vec!["cluster".to_string()],
                indexes: vec!["app-*".to_string()],
            }],
        )]);
        RolePolicy::from_settings(&roles).unwrap_err();
    }
}
