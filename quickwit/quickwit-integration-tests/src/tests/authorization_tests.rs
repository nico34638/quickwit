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

use std::collections::BTreeMap;

use quickwit_authorize::{UserTokenSpec, generate_root_key_pair, generate_token};
use quickwit_config::service::QuickwitService;
use quickwit_config::{AuthorizationConfig, ConfigFormat, RoleConfig, RoleGrantConfig};
use quickwit_metastore::SplitState;
use quickwit_rest_client::rest_client::CommitType;
use quickwit_serve::SearchRequestQueryString;
use reqwest::StatusCode;
use serde_json::json;

use crate::ingest_json;
use crate::test_utils::{ClusterSandbox, ClusterSandboxBuilder, ingest};

fn make_user_token(root_private_key: &str, user: &str, roles: &[&str]) -> String {
    let spec = UserTokenSpec {
        user_opt: Some(user.to_string()),
        roles: roles.iter().map(|role| role.to_string()).collect(),
        ..Default::default()
    };
    generate_token(root_private_key, &spec).unwrap()
}

const ALL_RIGHTS: &[&str] = &["index:read", "index:write", "index:admin", "cluster"];

fn rights(rights: &[&str]) -> RoleConfig {
    RoleConfig::Rights(rights.iter().map(|right| right.to_string()).collect())
}

/// Starts a cluster with authorization enabled, whose REST clients use `rest_auth_token`. The
/// searcher runs on its own node so that its metastore calls go through gRPC.
///
/// Authorization is initialized once per process: tests calling this function must run in their
/// own process, which is the case with `cargo nextest`.
async fn start_sandbox(
    root_private_key: &str,
    root_public_key: String,
    roles: BTreeMap<String, RoleConfig>,
    rest_auth_token: &str,
) -> ClusterSandbox {
    let node_token = generate_token(
        root_private_key,
        &UserTokenSpec {
            services: vec!["node".to_string()],
            ..Default::default()
        },
    )
    .unwrap();
    let authorization_config = AuthorizationConfig {
        root_public_key,
        node_token,
        roles,
        ..Default::default()
    };
    let mut sandbox_config = ClusterSandboxBuilder::default()
        .add_node([
            QuickwitService::Metastore,
            QuickwitService::ControlPlane,
            QuickwitService::Indexer,
            QuickwitService::Janitor,
        ])
        .add_node([QuickwitService::Searcher])
        .build_config()
        .await;
    for (node_config, _) in &mut sandbox_config.node_configs {
        node_config.authorization_config = Some(authorization_config.clone());
    }
    sandbox_config.rest_auth_token_opt = Some(rest_auth_token.to_string());
    sandbox_config.start().await
}

#[tokio::test]
async fn test_authorization_multi_nodes() {
    quickwit_common::setup_logging_for_tests();
    let (root_private_key, root_public_key) = generate_root_key_pair();
    let admin_token = make_user_token(&root_private_key, "alice", &["admin"]);
    let reader_token = make_user_token(&root_private_key, "bob", &["reader"]);
    let writer_token = make_user_token(&root_private_key, "carol", &["writer"]);

    let roles = BTreeMap::from([
        ("admin".to_string(), rights(ALL_RIGHTS)),
        ("reader".to_string(), rights(&["index:read"])),
        ("writer".to_string(), rights(&["index:write"])),
    ]);
    let sandbox = start_sandbox(&root_private_key, root_public_key, roles, &admin_token).await;

    // No token or a token signed by another key: 401.
    let anonymous_client = sandbox.rest_client_with_auth_token(QuickwitService::Searcher, None);
    let error = anonymous_client.cluster().snapshot().await.unwrap_err();
    assert_eq!(error.status_code(), Some(StatusCode::UNAUTHORIZED));

    let (other_private_key, _) = generate_root_key_pair();
    let forged_token = make_user_token(&other_private_key, "mallory", &["admin"]);
    let forged_client =
        sandbox.rest_client_with_auth_token(QuickwitService::Searcher, Some(forged_token));
    let error = forged_client.cluster().snapshot().await.unwrap_err();
    assert_eq!(error.status_code(), Some(StatusCode::UNAUTHORIZED));

    let index_id = "test-authorization-index";
    let index_config = format!(
        r#"
            version: 0.8
            index_id: {index_id}
            doc_mapping:
                field_mappings:
                - name: body
                  type: text
            indexing_settings:
                commit_timeout_secs: 1
            "#
    );
    // A reader cannot create an index.
    let reader_client =
        sandbox.rest_client_with_auth_token(QuickwitService::Indexer, Some(reader_token.clone()));
    let error = reader_client
        .indexes()
        .create(index_config.clone(), ConfigFormat::Yaml, false)
        .await
        .unwrap_err();
    assert_eq!(error.status_code(), Some(StatusCode::FORBIDDEN));

    // An admin can.
    sandbox
        .rest_client(QuickwitService::Indexer)
        .indexes()
        .create(index_config, ConfigFormat::Yaml, false)
        .await
        .unwrap();

    // A reader cannot ingest.
    let error = ingest(
        &reader_client,
        index_id,
        ingest_json!({"body": "from the reader"}),
        CommitType::Auto,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<quickwit_rest_client::error::Error>()
            .and_then(|error| error.status_code()),
        Some(StatusCode::FORBIDDEN)
    );

    // A writer can ingest. Indexing then runs in the background with the node token.
    let writer_client =
        sandbox.rest_client_with_auth_token(QuickwitService::Indexer, Some(writer_token.clone()));
    ingest(
        &writer_client,
        index_id,
        ingest_json!({"body": "from the writer"}),
        CommitType::Force,
    )
    .await
    .unwrap();
    sandbox
        .wait_for_splits(index_id, Some(vec![SplitState::Published]), 1)
        .await
        .unwrap();

    // A reader can search, on a searcher node that reaches the metastore over gRPC.
    let search_query = || SearchRequestQueryString {
        query: "body:writer".to_string(),
        max_hits: 10,
        ..Default::default()
    };
    let searcher_reader_client =
        sandbox.rest_client_with_auth_token(QuickwitService::Searcher, Some(reader_token));
    let search_response = searcher_reader_client
        .search(index_id, search_query())
        .await
        .unwrap();
    assert_eq!(search_response.num_hits, 1);

    // A writer cannot search: the metastore rejects its `ListIndexesMetadata` call.
    let searcher_writer_client =
        sandbox.rest_client_with_auth_token(QuickwitService::Searcher, Some(writer_token));
    let error = searcher_writer_client
        .search(index_id, search_query())
        .await
        .unwrap_err();
    assert_eq!(error.status_code(), Some(StatusCode::FORBIDDEN));

    // The health endpoints remain public.
    anonymous_client.node_health().is_live().await.unwrap();
    // So does the UI, which signs in through the API. The UI build may be missing from the
    // workspace: the page is then not found, but never unauthenticated.
    let ui_url = sandbox
        .rest_base_url(QuickwitService::Searcher)
        .join("ui/search")
        .unwrap();
    let ui_status = reqwest::get(ui_url).await.unwrap().status();
    assert_ne!(ui_status, StatusCode::UNAUTHORIZED);

    sandbox.shutdown().await.unwrap();
}

#[test]
fn test_authorization_config_json_roundtrip() {
    // Guards the config field names used by the test above.
    let authorization_config: AuthorizationConfig = serde_json::from_value(json!({
        "root_public_key": "abcd",
        "node_token": "efgh",
        "roles": {"reader": ["index:read"]},
    }))
    .unwrap();
    assert_eq!(
        authorization_config.roles["reader"],
        rights(&["index:read"])
    );
}

fn index_config(index_id: &str) -> String {
    format!(
        r#"
            version: 0.8
            index_id: {index_id}
            doc_mapping:
                field_mappings:
                - name: body
                  type: text
            indexing_settings:
                commit_timeout_secs: 1
            "#
    )
}

#[tokio::test]
async fn test_authorization_index_patterns() {
    quickwit_common::setup_logging_for_tests();
    let (root_private_key, root_public_key) = generate_root_key_pair();
    let admin_token = make_user_token(&root_private_key, "alice", &["admin"]);
    let app_reader_token = make_user_token(&root_private_key, "bob", &["app-reader"]);
    let app_writer_token = make_user_token(&root_private_key, "carol", &["app-writer"]);

    let app_grant = |rights: &[&str]| {
        RoleConfig::Grants(vec![RoleGrantConfig {
            rights: rights.iter().map(|right| right.to_string()).collect(),
            indexes: vec!["app-*".to_string(), "-app-secret*".to_string()],
        }])
    };
    let roles = BTreeMap::from([
        ("admin".to_string(), rights(ALL_RIGHTS)),
        ("app-reader".to_string(), app_grant(&["index:read"])),
        ("app-writer".to_string(), app_grant(&["index:write"])),
    ]);
    let sandbox = start_sandbox(&root_private_key, root_public_key, roles, &admin_token).await;
    let admin_client = sandbox.rest_client(QuickwitService::Indexer);
    for index_id in ["app-logs", "app-secret-logs"] {
        admin_client
            .indexes()
            .create(index_config(index_id), ConfigFormat::Yaml, false)
            .await
            .unwrap();
    }

    // The writer can only ingest into the indexes matching its patterns, including through the
    // bulk API where the index comes from the body.
    let app_writer_client =
        sandbox.rest_client_with_auth_token(QuickwitService::Indexer, Some(app_writer_token));
    ingest(
        &app_writer_client,
        "app-logs",
        ingest_json!({"body": "visible"}),
        CommitType::Force,
    )
    .await
    .unwrap();
    let error = ingest(
        &app_writer_client,
        "app-secret-logs",
        ingest_json!({"body": "hidden"}),
        CommitType::Auto,
    )
    .await
    .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<quickwit_rest_client::error::Error>()
            .and_then(|error| error.status_code()),
        Some(StatusCode::FORBIDDEN)
    );
    ingest(
        &admin_client,
        "app-secret-logs",
        ingest_json!({"body": "hidden"}),
        CommitType::Force,
    )
    .await
    .unwrap();
    for index_id in ["app-logs", "app-secret-logs"] {
        sandbox
            .wait_for_splits(index_id, Some(vec![SplitState::Published]), 1)
            .await
            .unwrap();
    }

    let app_reader_client = sandbox
        .rest_client_with_auth_token(QuickwitService::Searcher, Some(app_reader_token.clone()));
    let search_all = || SearchRequestQueryString {
        query: "*".to_string(),
        max_hits: 10,
        ..Default::default()
    };
    // Explicitly named index.
    let search_response = app_reader_client
        .search("app-logs", search_all())
        .await
        .unwrap();
    assert_eq!(search_response.num_hits, 1);
    // A forbidden index is reported as not found.
    let error = app_reader_client
        .search("app-secret-logs", search_all())
        .await
        .unwrap_err();
    assert_eq!(error.status_code(), Some(StatusCode::NOT_FOUND));
    // Wildcards only resolve to the allowed indexes.
    let search_response = app_reader_client
        .search("app-*", search_all())
        .await
        .unwrap();
    assert_eq!(search_response.num_hits, 1);
    let admin_search_response = sandbox
        .rest_client(QuickwitService::Searcher)
        .search("app-*", search_all())
        .await
        .unwrap();
    assert_eq!(admin_search_response.num_hits, 2);

    // Index listings are filtered.
    let index_ids: Vec<String> = app_reader_client
        .indexes()
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|index_metadata| index_metadata.index_id().to_string())
        .collect();
    assert_eq!(index_ids, vec!["app-logs".to_string()]);

    // Index metadata of a forbidden index.
    let error = app_reader_client
        .indexes()
        .get("app-secret-logs")
        .await
        .unwrap_err();
    assert_eq!(error.status_code(), Some(StatusCode::FORBIDDEN));

    // Scroll IDs are checked against the indexes of their scroll.
    let rest_base_url = sandbox.rest_base_url(QuickwitService::Searcher);
    let http_client = reqwest::Client::new();
    let scroll_response: serde_json::Value = http_client
        .post(
            rest_base_url
                .join("api/v1/_elastic/app-secret-logs/_search?scroll=1m&size=1")
                .unwrap(),
        )
        .bearer_auth(&admin_token)
        .json(&json!({"query": {"match_all": {}}}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let scroll_id = scroll_response["_scroll_id"].as_str().unwrap().to_string();
    let continue_scroll = |token: &str| {
        http_client
            .post(
                rest_base_url
                    .join("api/v1/_elastic/_search/scroll")
                    .unwrap(),
            )
            .bearer_auth(token)
            .json(&json!({"scroll_id": scroll_id, "scroll": "1m"}))
            .send()
    };
    let app_reader_scroll_response = continue_scroll(&app_reader_token).await.unwrap();
    assert_eq!(app_reader_scroll_response.status(), StatusCode::FORBIDDEN);
    let admin_scroll_response = continue_scroll(&admin_token).await.unwrap();
    assert_eq!(admin_scroll_response.status(), StatusCode::OK);

    // Leaf requests are reserved to nodes: a user cannot send them directly, even an admin.
    let mut search_grpc_client = sandbox.search_grpc_client();
    for user_token in [&app_reader_token, &admin_token] {
        let mut leaf_search_request =
            tonic::Request::new(quickwit_proto::search::LeafSearchRequest::default());
        leaf_search_request.metadata_mut().insert(
            "authorization",
            format!("Bearer {user_token}").parse().unwrap(),
        );
        let status = search_grpc_client
            .leaf_search(leaf_search_request)
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    sandbox.shutdown().await.unwrap();
}
