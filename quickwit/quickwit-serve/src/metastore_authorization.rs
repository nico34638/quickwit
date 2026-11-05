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

//! Filters the index listings of the metastore server by the index rights of the caller.
//!
//! The authorization layer only checks that the caller can read at least one index for these
//! requests (`IndexScope::AnyIndex`). Filtering their responses is what restricts the resolution
//! of index ID patterns (search, `_cat`, `_resolve`, `_field_caps`, ...) to the indexes the caller
//! can read: an index the caller cannot read is reported as not found, which does not disclose its
//! existence.

use std::task::{Context, Poll};

use futures::future::BoxFuture;
use quickwit_authorize::{RequestFamily, current_index_filter};
use quickwit_metastore::ListIndexesMetadataResponseExt;
use quickwit_proto::metastore::{
    ListIndexStatsRequest, ListIndexStatsResponse, ListIndexesMetadataRequest,
    ListIndexesMetadataResponse, MetastoreError,
};
use tower::{Layer, Service};

/// Filters the responses of `ListIndexesMetadata` and `ListIndexStats`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IndexListingFilterLayer;

impl<S> Layer<S> for IndexListingFilterLayer {
    type Service = IndexListingFilter<S>;

    fn layer(&self, service: S) -> Self::Service {
        IndexListingFilter { service }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IndexListingFilter<S> {
    service: S,
}

impl<S> Service<ListIndexesMetadataRequest> for IndexListingFilter<S>
where
    S: Service<
            ListIndexesMetadataRequest,
            Response = ListIndexesMetadataResponse,
            Error = MetastoreError,
        >,
    S::Future: Send + 'static,
{
    type Response = ListIndexesMetadataResponse;
    type Error = MetastoreError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, request: ListIndexesMetadataRequest) -> Self::Future {
        // The filter is computed in the task of the caller, which holds its authorization token.
        let index_filter = current_index_filter(RequestFamily::IndexRead);
        let response_fut = self.service.call(request);
        Box::pin(async move {
            let response = response_fut.await?;
            if index_filter.is_allow_all() {
                return Ok(response);
            }
            let indexes_metadata = response.deserialize_indexes_metadata().await?;
            let allowed_indexes_metadata = indexes_metadata
                .into_iter()
                .filter(|index_metadata| index_filter.is_index_allowed(index_metadata.index_id()))
                .collect();
            ListIndexesMetadataResponse::try_from_indexes_metadata(allowed_indexes_metadata).await
        })
    }
}

impl<S> Service<ListIndexStatsRequest> for IndexListingFilter<S>
where
    S: Service<ListIndexStatsRequest, Response = ListIndexStatsResponse, Error = MetastoreError>,
    S::Future: Send + 'static,
{
    type Response = ListIndexStatsResponse;
    type Error = MetastoreError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, request: ListIndexStatsRequest) -> Self::Future {
        let index_filter = current_index_filter(RequestFamily::IndexRead);
        let response_fut = self.service.call(request);
        Box::pin(async move {
            let mut response = response_fut.await?;
            if index_filter.is_allow_all() {
                return Ok(response);
            }
            response
                .index_stats
                .retain(|index_stats| match &index_stats.index_uid {
                    Some(index_uid) => index_filter.is_index_allowed(&index_uid.index_id),
                    None => false,
                });
            Ok(response)
        })
    }
}
