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

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use futures::future::Either;
use tokio::task::JoinHandle;
use tokio::task::futures::TaskLocalFuture;
use tokio_inherit_task_local::{FutureInheritTaskLocal, TaskLocalInheritableTable};
use tracing::error;

use crate::state::enabled_state;
use crate::{AuthorizationError, AuthorizationToken};

tokio_inherit_task_local::inheritable_task_local! {
    /// Token on behalf of which the current task runs: the token of a user while serving a user
    /// request, the node token in system tasks (actors, background tasks started at node startup).
    ///
    /// Only tasks spawned with [`spawn_inherit_auth_context`] (or futures wrapped with
    /// `inherit_task_local()`) inherit it.
    pub static AUTHORIZATION_TOKEN: AuthorizationToken;
}

/// Minimum interval between two "missing authorization context" logs.
const MISSING_CONTEXT_LOG_INTERVAL_SECS: u64 = 10;

static LAST_MISSING_CONTEXT_LOG_SECS: AtomicU64 = AtomicU64::new(0);

/// Returns the token of the current task.
///
/// There is no fallback on the node token: a task that lost its authorization context (for
/// instance, a `tokio::spawn` that does not inherit task-locals) must not get the rights of the
/// node. `operation` names the denied operation in the logs, to find the spawn that lost the
/// context.
pub(crate) fn current_token(operation: &str) -> Option<AuthorizationToken> {
    if let Ok(token) = AUTHORIZATION_TOKEN.try_with(|token| token.clone()) {
        return Some(token);
    }
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let last_log_secs = LAST_MISSING_CONTEXT_LOG_SECS.load(Ordering::Relaxed);
    if now_secs >= last_log_secs + MISSING_CONTEXT_LOG_INTERVAL_SECS
        && LAST_MISSING_CONTEXT_LOG_SECS
            .compare_exchange(
                last_log_secs,
                now_secs,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    {
        error!(
            operation,
            "no authorization context in the current task, the request will be denied: the task \
             was probably spawned without inheriting it"
        );
    }
    None
}

/// Wraps a request into a `tonic::Request`, adding the token of the current task to its metadata.
/// No-op when authorization is disabled.
pub fn build_tonic_request_with_auth_token<R>(request: R) -> tonic::Request<R> {
    let mut tonic_request = tonic::Request::new(request);
    inject_auth_token(tonic_request.metadata_mut(), std::any::type_name::<R>());
    tonic_request
}

/// Adds the token of the current task to the metadata of an outgoing gRPC request. Without a
/// token in context, no header is added and the server rejects the request as unauthenticated.
/// No-op when authorization is disabled.
pub fn inject_auth_token(metadata: &mut tonic::metadata::MetadataMap, operation: &str) {
    if enabled_state().is_none() {
        return;
    }
    let Some(token) = current_token(operation) else {
        return;
    };
    let header_value_res = token.to_header_value().and_then(|header_value| {
        header_value
            .parse()
            .map_err(|_| AuthorizationError::InvalidToken)
    });
    match header_value_res {
        Ok(header_value) => {
            metadata.insert(http::header::AUTHORIZATION.as_str(), header_value);
        }
        Err(error) => {
            // The server will reject the request as unauthenticated.
            error!(%error, "failed to serialize authorization token");
        }
    }
}

/// Extracts and verifies the token from the metadata of an incoming gRPC request.
///
/// Returns `Ok(None)` when authorization is disabled, and an error if it is enabled and the token
/// is missing or invalid.
pub fn extract_auth_token(
    metadata: &tonic::metadata::MetadataMap,
) -> Result<Option<AuthorizationToken>, tonic::Status> {
    let Some(state) = enabled_state() else {
        return Ok(None);
    };
    let header_value = metadata
        .get(http::header::AUTHORIZATION.as_str())
        .ok_or(AuthorizationError::AuthorizationTokenMissing)?
        .to_str()
        .map_err(|_| AuthorizationError::InvalidToken)?;
    let token = AuthorizationToken::parse_header_value(header_value, state.root_public_key)?;
    Ok(Some(token))
}

/// Runs `future` with `token_opt` as the token of the current task.
pub fn execute_with_authorization<F: Future>(
    token_opt: Option<AuthorizationToken>,
    future: F,
) -> Either<F, TaskLocalFuture<TaskLocalInheritableTable, F>> {
    match token_opt {
        Some(token) => Either::Right(AUTHORIZATION_TOKEN.scope(token, future)),
        None => Either::Left(future),
    }
}

/// Runs `future` with the node token as the token of the current task. Used at the root of system
/// tasks: actors, background tasks, node startup. No-op when authorization is disabled.
pub fn with_node_authorization<F: Future>(
    future: F,
) -> Either<F, TaskLocalFuture<TaskLocalInheritableTable, F>> {
    let node_token_opt = enabled_state().map(|state| state.node_token.clone());
    execute_with_authorization(node_token_opt, future)
}

/// Like `tokio::spawn`, but the spawned task inherits the authorization token of the caller.
pub fn spawn_inherit_auth_context<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    tokio::spawn(future.inherit_task_local())
}
