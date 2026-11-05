# Authorization (proof of concept)

This document describes the biscuit-based authorization implemented in the `quickwit-authorize`
crate. It ports the approach of PR #5533 without the community/enterprise split: the code is always
compiled, and authorization is enabled by adding an `authorization` section to the node config.

## Configuration

```yaml
authorization:
  root_public_key: <hex>   # or QW_AUTH_ROOT_PUBLIC_KEY
  node_token: <base64>     # or QW_AUTH_NODE_TOKEN
  roles:
    # A plain list of rights applies to all the indexes.
    admin: [index:read, index:write, index:admin, cluster]
    # Grants restrict rights to index ID patterns: `*` matches any sequence of characters,
    # patterns starting with `-` exclude indexes.
    app-reader:
      - rights: [index:read]
        indexes: ["app-*", "-app-secret*"]
    app-writer:
      - rights: [index:write]
        indexes: ["app-*"]
```

The `cluster` right covers the operator endpoints (cluster state, node config, indexing status,
developer API). It does not apply to indexes: it must be granted on `*`.

All the nodes of a cluster must share the same section, except `root_private_key` (see the JWT
exchange below). When it is absent, no token is required, emitted, or checked.

Keys and tokens are generated with the CLI:

```bash
# New root key pair + node token.
quickwit tool auth-token --service node
# User token signed by an existing root key.
quickwit tool auth-token --root-private-key <hex> --user alice --role reader --ttl 12h
```

## JWT exchange

Users authenticated by an identity provider (OIDC) exchange their JWT for a Quickwit token:

```yaml
authorization:
  # ...
  root_private_key: <hex>  # or QW_AUTH_ROOT_PRIVATE_KEY, only on the nodes serving the exchange
  jwt:
    issuer: https://idp.example.com/realms/acme
    audience: quickwit
    jwks_url: https://idp.example.com/realms/acme/protocol/openid-connect/certs  # or jwks_path
    user_claim: preferred_username  # default: sub
    roles_claim: realm_access.roles # default: roles; dots reach nested claims
    role_mapping:                   # optional: claim value -> Quickwit roles
      quickwit-admins: [admin]
    token_ttl: 1h                   # default: 1h, capped by the expiration of the JWT
```

```bash
curl -X POST -H "Authorization: Bearer $JWT" http://localhost:7280/api/v1/auth/token
# {"token": "<biscuit>", "user": "alice", "roles": ["admin"], "expires_at": "..."}
```

The node (`quickwit-serve/src/auth_api/`) verifies the signature of the JWT against the key set
(asymmetric algorithms only), its issuer, audience, and validity period, then maps the values of the
roles claim to Quickwit roles: through `role_mapping` if set, as role names otherwise. Values that
are not configured roles are dropped, and a JWT without any role is rejected (403). The key set of
`jwks_url` is fetched lazily, cached for 10 minutes, and fetched again (at most every 30 seconds)
when a JWT is signed by an unknown key.

The issued token is signed by the root private key: only the nodes that hold it serve the exchange
(404 on the others), and any node holding it can issue tokens with any role. Confine it to the
nodes that serve `/api/v1/auth/token`.

`GET /api/v1/auth/whoami` describes the token of the request: user, roles, grants (rights and
index ID patterns), and whether it holds the `cluster` right. Without authorization, it answers
`{"authorization_enabled": false, ...}`.

The embedded UI starts with `whoami`: on 401, it displays a sign-in page instead of the app, where
the user pastes a Quickwit token or a JWT that it exchanges. The token is stored in the local
storage of the browser and sent with every API call, including those of the API playground. The UI
then shows the user and its rights, hides the pages that require the `cluster` right, displays
"access denied" on 403, and comes back to the sign-in page when a call returns 401 (expired token).

An expired token is reported as unauthenticated (401), like a missing or invalid one, so that
clients obtain a new token. A 403 means that a valid token lacks a right.

## Tokens

Tokens are [biscuits](https://www.biscuitsec.org/) signed by the root key pair. Their authority
block holds identity facts:

- user tokens: `user("alice"); role("reader");` and an optional expiration check;
- node tokens: `service("node");`.

## Rights

The biscuit authorizer checks the token itself (signature, expiration) and reads its identity facts
from the authority block, so that blocks appended by the token holder cannot grant roles. The rights
are then evaluated in Rust (`quickwit-authorize/src/policy.rs`): node tokens are granted every right,
and the rights of a user are the union of the grants of its roles.

Every gRPC request type implements `Authorization` (`quickwit-proto/src/authorization.rs`,
`quickwit-ingest/src/authorize.rs`), which returns its request family (`index:read`, `index:write`,
`index:admin`, `cluster`, `internal`) and its index scope.

The `internal` family covers the requests exchanged between nodes: splits staging and publication,
shard management, indexing plans, cluster state, and the leaf requests of the search (leaf search,
fetch docs, leaf list terms and fields, scroll contexts, searcher load). It cannot be granted to a
role: only node tokens pass, so a user cannot send these requests directly, whatever its rights.

The index scopes are:

| Scope        | Meaning                                                    | Examples                                           |
|--------------|------------------------------------------------------------|----------------------------------------------------|
| `Indexes`    | Each index must be granted.                                | index admin, ingest subrequests, `ListSplits`      |
| `AnyIndex`   | The family must be granted on at least one index.          | index listings (filtered), root searches           |
| `AllIndexes` | The family must be granted on all the indexes (`*`).       | index template changes, requests without index IDs |
| `NoIndex`    | `cluster` and `internal` families.                         | debug info, shards, splits publication             |

A request whose index IDs cannot be extracted requires the rights on all the indexes. An empty list
of indexes is checked like `AnyIndex`.

Tokens are evaluated with datalog run limits of 100 ms (instead of the 1 ms of biscuit): a node
under CPU pressure must not deny requests because the evaluation was preempted.

### Index listings

The metastore server filters the responses of `ListIndexesMetadata` and `ListIndexStats` by the
indexes the caller can read (`quickwit-serve/src/metastore_authorization.rs`). Index ID patterns
are resolved through these listings (search, `_msearch`, `_cat`, `_resolve`, `_field_caps`, index
listing), so:

- a wildcard only resolves to the readable indexes;
- a forbidden index named explicitly returns "not found" (404) through search, which
  does not disclose its existence, but 403 through the APIs that take an index ID directly
  (`GET /api/v1/indexes/{index}`, index admin).

The index templates are not filtered: any user who can read some index can read all of them.

### Searches

The root search checks the rights of the user: it resolves the indexes through the filtered
listings. It then sends the leaf requests with the node token (`quickwit_search::SearchServiceClient`):
the leaves trust the root, and a user cannot send leaf requests directly.

Scroll IDs are not bound to the user who started the scroll: resuming a scroll requires the
`index:read` right on all the indexes of its context.

## Propagation

```
REST request ──► AuthorizationTokenExtractionLayer (scopes the token in a task-local)
             └─► require_authorization filter, on /api/v1, /mcp, /api/developer:
                 401 if the token is missing, badly signed, or expired,
                 403 without the `cluster` right on the REST-only routes (see below)
                    │
                    ▼
generated gRPC client ── `authorization: Bearer <token>` ──► generated gRPC server adapter
(token from the task-local)                                 (verifies and scopes the token)
                                                                      │
                                                                      ▼
                                                        AuthorizationLayer (checks the family)
```

Most REST handlers call services through gRPC clients, which are checked by the
`AuthorizationLayer`. The handlers of `/api/v1/cluster`, `/api/v1/config`, `/api/v1/indexing`, and
`/api/developer/*` answer on their own, so the REST edge requires the `cluster` right for them
(`CLUSTER_REST_PATH_PREFIXES` in `quickwit-serve/src/rest.rs`). `Authorization` is an allowed CORS
header.

The search service is not generated by `quickwit-codegen`: its client adds the token with the
`SearchClientInterceptor` and its server adapter checks it with `serve_authorized`.

The `AuthorizationLayer` is stacked on the local service clients that back the gRPC servers, so
in-process calls are checked too.

## Authorization context

The token of the current task lives in the `AUTHORIZATION_TOKEN` inheritable task-local:

- REST requests and gRPC requests run with the token they carry.
- System tasks run with the node token, set explicitly with `with_node_authorization`: node startup
  (`serve_quickwit`), actor loops (`quickwit-actors`), event subscribers (`quickwit-common`
  pubsub), and maintenance tasks triggered by requests (ingester shard reset).
- `quickwit_common::spawn_named_task`, `spawn_named_task_on`, and the `OneTaskPerCallLayer`
  propagate the context of the caller to the spawned task.

There is no implicit fallback on the node token: a task without token in context (for instance,
spawned with a plain `tokio::spawn`) is denied, and an error is logged (at most every 10 seconds)
with the name of the denied operation. Spawn such tasks with `spawn_named_task`.

## Known limitations

- In-process root searches issued from REST are only checked through the metastore calls they
  make.
- The node token is a bearer credential granted every right, sent with every internal request.
  Without gRPC TLS, it travels in clear, and a node that joins the (unauthenticated) chitchat gossip
  receives it.
- The Jaeger and OTLP gRPC endpoints do not extract tokens: with authorization enabled, their
  requests are denied when they reach the search or ingest services. `/metrics` and the chitchat
  gossip are not protected.
- The embedded UI does not implement the OIDC login flow: the user pastes a JWT or a token.
- Tokens are not attenuated per call and cannot be revoked.
- Each request re-verifies the token signature.
