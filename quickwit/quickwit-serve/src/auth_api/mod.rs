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

//! Exchange of JWTs issued by an identity provider (OIDC) for Quickwit tokens.

mod jwt;
mod rest_handler;
mod token_exchange;

pub(crate) use rest_handler::{AuthApi, auth_token_handler, whoami_handler};
pub(crate) use token_exchange::TokenExchange;
