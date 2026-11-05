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

//! `quickwit tool auth-token`: generates the root key pair and the authorization tokens.

use std::time::Duration;

use clap::{ArgAction, ArgMatches, Command, arg};
use quickwit_authorize::{UserTokenSpec, attenuate_token, generate_root_key_pair, generate_token};

pub fn build_auth_token_command() -> Command {
    Command::new("auth-token")
        .display_order(10)
        .about("Generates an authorization token (and a root key pair if none is provided).")
        .long_about(
            "Generates an authorization token signed by the root private key. Without \
             `--root-private-key`, a new root key pair is generated: configure its public key as \
             `authorization.root_public_key` on every node. Node tokens are created with \
             `--service`, user tokens with `--user` and `--role`. `--attenuate` appends a block \
             to an existing token instead, as any holder of the token can do: its facts are not \
             trusted, and its checks can only restrict the token.",
        )
        .args(&[
            arg!(--"root-private-key" <ROOT_PRIVATE_KEY> "Hex-encoded root private key.")
                .required(false),
            arg!(--user <USER> "Name of the user.").required(false),
            arg!(--role <ROLE> "Role granted to the token. Can be repeated.")
                .required(false)
                .action(ArgAction::Append),
            arg!(--service <SERVICE> "Quickwit service, for node tokens. Can be repeated.")
                .required(false)
                .action(ArgAction::Append),
            arg!(--ttl <TTL> "Validity of the token (e.g. `12h`). Never expires if unset.")
                .required(false),
            arg!(--attenuate <TOKEN> "Token to attenuate with `--block`.").required(false),
            arg!(--block <DATALOG> "Datalog of the block appended by `--attenuate`.")
                .required(false),
        ])
}

#[derive(Debug, Eq, PartialEq)]
pub struct AuthTokenArgs {
    pub root_private_key_opt: Option<String>,
    pub user_opt: Option<String>,
    pub roles: Vec<String>,
    pub services: Vec<String>,
    pub ttl_opt: Option<Duration>,
    pub attenuate_opt: Option<String>,
    pub block_opt: Option<String>,
}

pub fn parse_auth_token_args(mut matches: ArgMatches) -> anyhow::Result<AuthTokenArgs> {
    let ttl_opt = match matches.remove_one::<String>("ttl") {
        Some(ttl_str) => Some(humantime::parse_duration(&ttl_str)?),
        None => None,
    };
    Ok(AuthTokenArgs {
        root_private_key_opt: matches.remove_one::<String>("root-private-key"),
        user_opt: matches.remove_one::<String>("user"),
        roles: matches
            .remove_many::<String>("role")
            .map(Iterator::collect)
            .unwrap_or_default(),
        services: matches
            .remove_many::<String>("service")
            .map(Iterator::collect)
            .unwrap_or_default(),
        ttl_opt,
        attenuate_opt: matches.remove_one::<String>("attenuate"),
        block_opt: matches.remove_one::<String>("block"),
    })
}

pub fn auth_token_cli(args: AuthTokenArgs) -> anyhow::Result<()> {
    if let Some(token) = &args.attenuate_opt {
        let Some(block) = &args.block_opt else {
            anyhow::bail!("`--attenuate` requires `--block`");
        };
        let has_token_spec = args.root_private_key_opt.is_some()
            || args.user_opt.is_some()
            || !args.roles.is_empty()
            || !args.services.is_empty()
            || args.ttl_opt.is_some();
        if has_token_spec {
            anyhow::bail!("`--attenuate` cannot be combined with the options of a new token");
        }
        println!("Token: {}", attenuate_token(token, block)?);
        return Ok(());
    }
    if args.block_opt.is_some() {
        anyhow::bail!("`--block` requires `--attenuate`");
    }
    if args.services.is_empty() && args.roles.is_empty() {
        anyhow::bail!("a token needs at least one `--role` or one `--service`");
    }
    let root_private_key = match args.root_private_key_opt {
        Some(root_private_key) => root_private_key,
        None => {
            let (root_private_key, root_public_key) = generate_root_key_pair();
            println!("Root private key (keep it secret): {root_private_key}");
            println!("Root public key: {root_public_key}");
            root_private_key
        }
    };
    let spec = UserTokenSpec {
        user_opt: args.user_opt,
        roles: args.roles,
        services: args.services,
        ttl_opt: args.ttl_opt,
    };
    let token = generate_token(&root_private_key, &spec)?;
    println!("Token: {token}");
    Ok(())
}
