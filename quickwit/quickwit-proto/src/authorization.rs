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

//! Maps every gRPC request type to the [`RequestFamily`] and the [`IndexScope`] checked by the
//! authorization layer.
//!
//! Hidden contracts:
//! - Requests sent on behalf of a user (with the user token in context) must not belong to the
//!   `Internal` family, which only node tokens are granted. For instance, an ingest request makes
//!   the router call `GetOrCreateOpenShards` and `Persist` with the token of the user, so these
//!   requests belong to the `IndexWrite` family. Requests sent from actors and background tasks run
//!   with the node token, which is granted every right.
//! - Conversely, the node sends some `Internal` requests while serving a user request, after having
//!   checked the rights of the user: the root search resolves the indexes through the filtered
//!   listings, then sends the leaf requests with the node token (see
//!   `quickwit_search::SearchServiceClient`).
//! - A request whose index IDs cannot be extracted uses [`IndexScope::AllIndexes`].
//! - Requests with the [`IndexScope::AnyIndex`] scope list indexes, and their responses are
//!   filtered by the metastore server (see `quickwit_authorize::current_index_filter`), or resolve
//!   their indexes through these listings (root searches), or are not specific to an index (index
//!   templates, cluster identity).

use quickwit_authorize::{Authorization, IndexScope, RequestFamily};

use crate::cluster::FetchClusterStateRequest;
use crate::compaction::ReportStatusRequest;
use crate::control_plane::{AdviseResetShardsRequest, GetOrCreateOpenShardsRequest};
use crate::developer::GetDebugInfoRequest;
use crate::indexing::ApplyIndexingPlanRequest;
use crate::ingest::ingester::{
    CloseShardsRequest, DecommissionRequest, InitShardsRequest, OpenFetchStreamRequest,
    PersistRequest, RetainShardsRequest, TruncateShardsRequest,
};
use crate::ingest::router::IngestRequestV2;
use crate::metastore::*;
use crate::search::{
    FetchDocsRequest, GetKvRequest, GetLoadRequest, LeafListFieldsRequest, LeafListTermsRequest,
    LeafSearchRequest, ListFieldsRequest, ListTermsRequest, PutKvRequest, ReportSplitsRequest,
    ScrollRequest, SearchRequest,
};
use crate::types::IndexUid;

/// Implements [`Authorization`] for request types with a fixed index scope.
macro_rules! impl_authorization {
    ($request_family:expr, $index_scope:expr => $($request_type:ty),+ $(,)?) => {
        $(
            impl Authorization for $request_type {
                fn request_family(&self) -> RequestFamily {
                    $request_family
                }

                fn index_scope(&self) -> IndexScope {
                    $index_scope
                }
            }
        )+
    };
}

/// Implements [`Authorization`] for request types with an `index_uid: Option<IndexUid>` field.
macro_rules! impl_authorization_for_index_uid {
    ($request_family:expr => $($request_type:ty),+ $(,)?) => {
        $(
            impl Authorization for $request_type {
                fn request_family(&self) -> RequestFamily {
                    $request_family
                }

                fn index_scope(&self) -> IndexScope {
                    index_uids_scope([self.index_uid.as_ref()])
                }
            }
        )+
    };
}

/// Returns the scope of the indexes of `index_uids`, or [`IndexScope::AllIndexes`] if one of them
/// is missing.
fn index_uids_scope<'a>(index_uids: impl IntoIterator<Item = Option<&'a IndexUid>>) -> IndexScope {
    let mut index_ids = Vec::new();
    for index_uid_opt in index_uids {
        let Some(index_uid) = index_uid_opt else {
            return IndexScope::AllIndexes;
        };
        index_ids.push(index_uid.index_id.clone());
    }
    IndexScope::Indexes(index_ids)
}

fn index_ids_scope<'a>(index_ids: impl IntoIterator<Item = &'a String>) -> IndexScope {
    IndexScope::Indexes(index_ids.into_iter().cloned().collect())
}

/// Extracts the `index_id` field of a JSON serialized index config.
fn index_config_json_scope(index_config_json: &str) -> IndexScope {
    let index_id_opt = serde_json::from_str::<serde_json::Value>(index_config_json)
        .ok()
        .and_then(|index_config| {
            index_config
                .get("index_id")
                .and_then(|index_id| index_id.as_str())
                .map(str::to_string)
        });
    match index_id_opt {
        Some(index_id) => IndexScope::Indexes(vec![index_id]),
        None => IndexScope::AllIndexes,
    }
}

// Metastore and control plane

impl Authorization for CreateIndexRequest {
    fn request_family(&self) -> RequestFamily {
        RequestFamily::IndexAdmin
    }

    fn index_scope(&self) -> IndexScope {
        index_config_json_scope(&self.index_config_json)
    }
}

impl Authorization for IndexMetadataRequest {
    fn request_family(&self) -> RequestFamily {
        RequestFamily::IndexRead
    }

    fn index_scope(&self) -> IndexScope {
        if let Some(index_uid) = &self.index_uid {
            return IndexScope::Indexes(vec![index_uid.index_id.clone()]);
        }
        match &self.index_id {
            Some(index_id) => IndexScope::Indexes(vec![index_id.clone()]),
            None => IndexScope::AllIndexes,
        }
    }
}

impl Authorization for IndexesMetadataRequest {
    fn request_family(&self) -> RequestFamily {
        RequestFamily::IndexRead
    }

    fn index_scope(&self) -> IndexScope {
        let mut index_ids = Vec::with_capacity(self.subrequests.len());
        for subrequest in &self.subrequests {
            if let Some(index_uid) = &subrequest.index_uid {
                index_ids.push(index_uid.index_id.clone());
            } else if let Some(index_id) = &subrequest.index_id {
                index_ids.push(index_id.clone());
            } else {
                return IndexScope::AllIndexes;
            }
        }
        IndexScope::Indexes(index_ids)
    }
}

impl Authorization for ListSplitsRequest {
    fn request_family(&self) -> RequestFamily {
        RequestFamily::IndexRead
    }

    fn index_scope(&self) -> IndexScope {
        // `query_json` is a serialized `ListSplitsQuery`, defined in `quickwit-metastore`.
        let index_uids_opt: Option<Vec<IndexUid>> =
            serde_json::from_str::<serde_json::Value>(&self.query_json)
                .ok()
                .and_then(|query| query.get("index_uids").cloned())
                .and_then(|index_uids| serde_json::from_value(index_uids).ok());
        match index_uids_opt {
            Some(index_uids) => index_uids_scope(index_uids.iter().map(Some)),
            None => IndexScope::AllIndexes,
        }
    }
}

impl Authorization for ListShardsRequest {
    fn request_family(&self) -> RequestFamily {
        RequestFamily::IndexRead
    }

    fn index_scope(&self) -> IndexScope {
        index_uids_scope(
            self.subrequests
                .iter()
                .map(|subrequest| subrequest.index_uid.as_ref()),
        )
    }
}

impl Authorization for FindIndexTemplateMatchesRequest {
    fn request_family(&self) -> RequestFamily {
        RequestFamily::IndexRead
    }

    fn index_scope(&self) -> IndexScope {
        index_ids_scope(&self.index_ids)
    }
}

impl Authorization for GetOrCreateOpenShardsRequest {
    fn request_family(&self) -> RequestFamily {
        RequestFamily::IndexWrite
    }

    fn index_scope(&self) -> IndexScope {
        index_ids_scope(
            self.subrequests
                .iter()
                .map(|subrequest| &subrequest.index_id),
        )
    }
}

impl_authorization_for_index_uid!(RequestFamily::IndexRead =>
    LastDeleteOpstampRequest,
    ListDeleteTasksRequest,
    ListStaleSplitsRequest,
);

impl_authorization_for_index_uid!(RequestFamily::IndexWrite =>
    DeleteQuery,
);

impl_authorization_for_index_uid!(RequestFamily::IndexAdmin =>
    UpdateIndexRequest,
    DeleteIndexRequest,
    AddSourceRequest,
    UpdateSourceRequest,
    ToggleSourceRequest,
    DeleteSourceRequest,
    ResetSourceCheckpointRequest,
    MarkSplitsForDeletionRequest,
    DeleteSplitsRequest,
);

// The responses of the index listings are filtered by the metastore server.
impl_authorization!(RequestFamily::IndexRead, IndexScope::AnyIndex =>
    ListIndexesMetadataRequest,
    ListIndexStatsRequest,
);

// Not filtered: any user who can read some index can read all the index templates.
impl_authorization!(RequestFamily::IndexRead, IndexScope::AnyIndex =>
    GetIndexTemplateRequest,
    ListIndexTemplatesRequest,
    GetClusterIdentityRequest,
);

// Index templates apply to any index created in the future.
impl_authorization!(RequestFamily::IndexAdmin, IndexScope::AllIndexes =>
    CreateIndexTemplateRequest,
    DeleteIndexTemplatesRequest,
);

// Ingest

impl Authorization for IngestRequestV2 {
    fn request_family(&self) -> RequestFamily {
        RequestFamily::IndexWrite
    }

    fn index_scope(&self) -> IndexScope {
        index_ids_scope(
            self.subrequests
                .iter()
                .map(|subrequest| &subrequest.index_id),
        )
    }
}

impl Authorization for PersistRequest {
    fn request_family(&self) -> RequestFamily {
        RequestFamily::IndexWrite
    }

    fn index_scope(&self) -> IndexScope {
        index_uids_scope(
            self.subrequests
                .iter()
                .map(|subrequest| subrequest.index_uid.as_ref()),
        )
    }
}

// Search: the root resolves the index ID patterns through the metastore, whose listing is
// filtered. The scroll checks the indexes of its context once loaded.
impl_authorization!(RequestFamily::IndexRead, IndexScope::AnyIndex =>
    SearchRequest,
    ListTermsRequest,
    ScrollRequest,
    ListFieldsRequest,
);

// Operators
impl_authorization!(RequestFamily::Cluster, IndexScope::NoIndex =>
    // The developer API fans this request out to the nodes with the token of the operator.
    GetDebugInfoRequest,
);

// Requests exchanged between nodes, reserved to node tokens.
impl_authorization!(RequestFamily::Internal, IndexScope::NoIndex =>
    // Metastore
    StageSplitsRequest,
    PublishSplitsRequest,
    UpdateSplitsDeleteOpstampRequest,
    OpenShardsRequest,
    AcquireShardsRequest,
    DeleteShardsRequest,
    PruneShardsRequest,
    // Control plane
    AdviseResetShardsRequest,
    // Ingester
    InitShardsRequest,
    RetainShardsRequest,
    TruncateShardsRequest,
    CloseShardsRequest,
    DecommissionRequest,
    OpenFetchStreamRequest,
    // Indexing, compaction, cluster
    ApplyIndexingPlanRequest,
    ReportStatusRequest,
    FetchClusterStateRequest,
    // Search: the leaf requests carry the splits of indexes resolved and checked by the root.
    LeafSearchRequest,
    FetchDocsRequest,
    LeafListTermsRequest,
    LeafListFieldsRequest,
    // Scroll contexts, stored and loaded by the root.
    PutKvRequest,
    GetKvRequest,
    // Load of the searchers, probed by the search job placer.
    GetLoadRequest,
    ReportSplitsRequest,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::router::IngestSubrequest;

    #[test]
    fn test_index_scopes() {
        let index_uid = IndexUid::for_test("app-logs", 0);
        let delete_index_request = DeleteIndexRequest {
            index_uid: Some(index_uid.clone()),
        };
        assert_eq!(
            delete_index_request.index_scope(),
            IndexScope::Indexes(vec!["app-logs".to_string()])
        );
        assert_eq!(
            DeleteIndexRequest { index_uid: None }.index_scope(),
            IndexScope::AllIndexes
        );

        let create_index_request = CreateIndexRequest {
            index_config_json: r#"{"version": "0.8", "index_id": "app-logs"}"#.to_string(),
            source_configs_json: Vec::new(),
        };
        assert_eq!(
            create_index_request.index_scope(),
            IndexScope::Indexes(vec!["app-logs".to_string()])
        );
        let invalid_create_index_request = CreateIndexRequest {
            index_config_json: "not json".to_string(),
            source_configs_json: Vec::new(),
        };
        assert_eq!(
            invalid_create_index_request.index_scope(),
            IndexScope::AllIndexes
        );

        let ingest_request = IngestRequestV2 {
            subrequests: vec![
                IngestSubrequest {
                    index_id: "app-logs".to_string(),
                    ..Default::default()
                },
                IngestSubrequest {
                    index_id: "secret".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            ingest_request.index_scope(),
            IndexScope::Indexes(vec!["app-logs".to_string(), "secret".to_string()])
        );

        let index_uid_json = serde_json::to_string(&index_uid).unwrap();
        let list_splits_request = ListSplitsRequest {
            query_json: format!(r#"{{"index_uids": [{index_uid_json}]}}"#),
        };
        assert_eq!(
            list_splits_request.index_scope(),
            IndexScope::Indexes(vec!["app-logs".to_string()])
        );
        let list_all_splits_request = ListSplitsRequest {
            query_json: r#"{"index_uids": null}"#.to_string(),
        };
        assert_eq!(
            list_all_splits_request.index_scope(),
            IndexScope::AllIndexes
        );
    }
}
