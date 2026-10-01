# Choose an example

Start with the deployment you need. You do not need to construct a bound resource
or write a router to use the built-in resource assembly.

| Task | Example | What you supply |
| --- | --- | --- |
| Protect one resource and publish discovery | [resource_proxy.rs](resource_proxy.rs) | Public origin, issuer, optional audience override, upstream |
| Protect two resources | [multi_resource_proxy.rs](multi_resource_proxy.rs) | The same inputs per resource |
| Integrate with your own server and publication routing | [publication_proxy.rs](publication_proxy.rs) | Bound resources, ingress mappings, public endpoint handlers |
| Add browser login | [login_proxy.rs](login_proxy.rs) | Issuer, client ID, registered redirect URI, cookie key, upstream |
| Use bearer-token policies without discovery | [jwt_proxy.rs](jwt_proxy.rs) | Issuer, audience, public/protected route rules |

## One resource

```sh
ISSUER=https://auth.example.com \
PUBLIC_BASE=https://api.example.com \
UPSTREAM=127.0.0.1:3000 \
cargo run --example resource_proxy
```

The resource is `https://api.example.com/api`. By default that exact URL is its
accepted token audience. Set `AUDIENCE` if your issuer uses another value.
`PUBLIC_BASE` is an origin without a path in this introductory example.

The example supplies three things: a resource definition, a token-validation
guard, and an upstream. `ResourceAssembly::register` binds them and installs the
protected subtree and its public metadata endpoint. Other paths return 404.

| Local request | Expected result |
| --- | --- |
| `GET http://127.0.0.1:6188/.well-known/oauth-protected-resource/api` | Public metadata JSON |
| `GET http://127.0.0.1:6188/api` without a token | 401 with the canonical metadata URL in its challenge |
| `/api` with a valid token for this resource | Forwarded to the configured upstream |

Provider discovery happens at startup. The examples use RFC 9068 tokens and
RFC 8414 authorization-server discovery; for an OIDC discovery endpoint, change
`AuthorizationServerMetadata::fetch()` to `oidc_fetch()` in the helper. A real
issuer must be reachable. Successful forwarding also needs an upstream that
serves the unchanged request path.

[support/resource_server.rs](support/resource_server.rs) contains the context,
provider-discovery and Pingora listener boilerplate. The main example keeps
resource identity, audience selection, authentication policy, and registration
visible. The guard defaults to requiring authentication. Add scope requirements
when your service needs them; advertising a scope is not an access policy.

## Multiple resources

```sh
PUBLIC_BASE=https://api.example.com \
INVENTORY_ISSUER=https://inventory-auth.example.com \
PAYMENTS_ISSUER=https://payments-auth.example.com \
cargo run --example multi_resource_proxy
```

This repeats the same registration for `/mcp/inventory` and `/mcp/payments`.
Optional `INVENTORY_AUDIENCE` and `PAYMENTS_AUDIENCE` override their URL audiences;
`INVENTORY_UPSTREAM` and `PAYMENTS_UPSTREAM` default to ports 3001 and 3002.
`LISTEN` defaults to `127.0.0.1:6188` for both introductory examples.

The definition's audience is passed to the validator so token validation and
resource binding agree. Each example resource accepts one audience. The assembly
checks relationships between resources and publishes their derived metadata URLs;
you do not maintain a second table of discovery paths or dispatch predicates.

## Existing servers and independent publication

Only start with [publication_proxy.rs](publication_proxy.rs) when you need to own
server composition. It shows `BoundResource`, route selection before branch
hooks, independent metadata ingress, and an optional `SECURITY_TXT_FILE` handler.
The file's contents are operator supplied and loaded once at startup.

See [the publication and rewrite walkthrough](../docs/how_to/resource_metadata.md#publish-alongside-securitytxt).
Run its routing tests with `cargo test --example publication_proxy`. These use
Pingora's HTTP runner and a test-only validator, without live issuer services.
The library's contribution API does not manage the rest of `.well-known`.

## Browser login and rewrites

First follow [the localhost login tutorial](../docs/tutorial/browser_login.md).
The default mapping is the redirect URI's origin with incoming prefix `/`.
Cookie-key setup, grant configuration, session storage and application policies
are explicit in `login_proxy.rs`; those are deployment choices, not resource
registration requirements.

For a front proxy that exposes `/gateway` and strips it before forwarding:

```sh
export COOKIE_KEY="$(openssl rand -hex 32)"
ISSUER=https://auth.example.com \
CLIENT_ID=my-client \
PUBLIC_BASE=https://app.example.com/gateway \
INCOMING_PREFIX=/ \
REDIRECT_URI=https://app.example.com/gateway/callback \
cargo run --example login_proxy --features login
```

| Browser path | Path received by Pingora |
| --- | --- |
| `/gateway/dashboard` | `/dashboard` |
| `/gateway/callback` | `/callback` |
| `/gateway/logout` (POST) | `/logout` |
| `/gateway/signed-out` | `/signed-out` |

Configure the front proxy to perform the rewrite and register the full public
redirect URI with the provider. The example derives the incoming callback through
`url::callback_path`, rather than treating the public URL path as an incoming
path. The engine validates the callback against the grant.

If the front proxy instead forwards `/edge/dashboard`, set `INCOMING_PREFIX=/edge`;
callback, logout and application policies then use `/edge/...`. Forwarded paths
remain unchanged, so the upstream must also accept those paths. Merely configuring
a mapping does not perform a rewrite. Keep `COOKIE_KEY` stable across restarts.

## Metadata fields and local development

The first example uses `ResourceDefinition::builder().mapping(mapping.clone())`:
only resource-specific inputs remain to be set. Optional name, documentation, policy,
terms and advertised-scope setters belong to the definition; binding supplies
validator capabilities. Explicit scopes override adapter defaults, including
an empty list to omit them. They do not change authorization requirements.

See the shared [metadata and browser discovery guide](https://github.com/huskarl-rs/huskarl/blob/main/huskarl-resource-server/docs/guide/resource_metadata.md)
for a standalone document example and server-owned CORS configuration.

During API iteration, this repository's Cargo patches use sibling
`../huskarl/huskarl-core` and `../huskarl/huskarl-resource-server` sources.
Keep the sibling checkout alongside this repository. Cargo patches apply only
at the workspace root; an external application needs equivalent root patches.
Remove these overrides after releasing the shared API and update version
requirements before publishing the adapter.
