# Publish protected-resource metadata

Use this guide to publish RFC 9728 discovery information for one resource or
several resources on the same origin. This is the API's own metadata, separate
from the authorization-server metadata used to construct a token validator.

You need a trusted public HTTPS origin, a validator for each resource, and the
audiences your provider puts in access tokens. A logical resource can have many
endpoints; it gets one metadata document, not one per endpoint.

## Choose identifiers and audiences

For an origin of `https://api.example.com`, this guide uses:

| Resource identifier | Public metadata URL |
|---|---|
| `https://api.example.com/mcp/inventory` | `https://api.example.com/.well-known/oauth-protected-resource/mcp/inventory` |
| `https://api.example.com/mcp/payments` | `https://api.example.com/.well-known/oauth-protected-resource/mcp/payments` |

Use `AudienceBinding::ResourceIdentifier` if the token's `aud` is the resource
URL. Use `AudienceBinding::mapped(["inventory-api"])` if your provider issues a
different audience. Configure the validator to accept that audience too.
Resources accepting the same audience are not isolated by their different URLs;
use distinct audiences or additional authorization checks when tokens must not
cross between resources.

## Publish one resource

Bind the proxy to the resource and publish the returned endpoint outside its
authentication handling:

```rust
use huskarl_pingora::resource::{
    AudienceBinding, AuthProxy, CaseSensitivity, DecodeDepth,
    Guard, GuardConfig, ResourceMetadataProxy, Rule,
};
# fn configure<P, V>(inner: P, validator: V) -> Result<(), huskarl_pingora::resource::ConfigError>
# where V: huskarl_pingora::resource_server::validator::AccessTokenValidator
#     + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata {
let guard = Guard::builder()
    .validator(validator)
    .base_uri("https://api.example.com".parse().expect("public origin"))
    .path_guard(GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .subtree("/mcp/inventory", Rule::required().scopes(["inventory.read"]))
    .build()?;
let (inventory, metadata) = AuthProxy::new(inner, guard)
    .with_protected_resource("/mcp/inventory", AudienceBinding::ResourceIdentifier)?;
let proxy = ResourceMetadataProxy::new(inventory).publish(metadata)?;
# let _ = proxy;
# Ok(())
# }
```

`Rule::required().scopes(...)` enforces scopes. Metadata describes supported
capabilities; publishing it is not a substitute for a route policy. The guard
collects rule scopes for advertisement when the validator does not already
supply `scopes_supported`.

A resource-bound proxy only applies its guard inside that resource's path.
Requests outside it are refused with 403; requests whose public URI cannot be
reconstructed are refused with 400. Neither reaches the inner proxy. Route
unrelated paths to an explicit fallback rather than treating this wrapper as
protection for the whole listener. Keep discovery outside token validation.

## Add a second resource

Build a separate `Guard` and resource-bound `AuthProxy` for payments. Publish
both returned endpoints through one `ResourceMetadataProxy`. In a multi-resource
server, route the well-known namespace to that publisher in a separate branch,
and route each protected subtree to its own auth proxy. Selection must happen
in the router's early phase so metadata requests never enter an auth branch's
early-filter lifecycle.

Use [examples/multi_resource_proxy.rs](https://github.com/huskarl-rs/huskarl-pingora/blob/main/examples/multi_resource_proxy.rs) for the complete routing and context setup:

```sh
PUBLIC_BASE=https://api.example.com \
INVENTORY_ISSUER=https://inventory-auth.example.com \
PAYMENTS_ISSUER=https://payments-auth.example.com \
LISTEN=127.0.0.1:6188 \
cargo run --example multi_resource_proxy --features resource
```

Replace the issuer URLs with your providers. The same issuer can serve both
resources if it issues the intended distinct audiences. The example uses
RFC 9068 JWT access tokens. `INVENTORY_AUDIENCE` and `PAYMENTS_AUDIENCE` override
the default resource-URL audiences. `INVENTORY_UPSTREAM` defaults to
`127.0.0.1:3001`; `PAYMENTS_UPSTREAM` defaults to `127.0.0.1:3002`. Start both
upstreams with the routes you intend to serve, such as `/mcp/inventory/items`
and `/mcp/payments/items`; the proxy preserves those paths.

The multi-resource example requires authentication and checks audiences. To
enforce operation permissions, add scoped rules to each guard as in the
single-resource setup above. Metadata and unauthenticated challenge checks do
not require healthy upstreams; successful forwarding does.

Use an origin without a path for this example's `PUBLIC_BASE`. Its listener and
upstream connections are plain HTTP; terminate public HTTPS at a trusted entry
point. If you introduce rewrites, align the guard's public URL mapping and
router selection, and route canonical metadata URLs to the publisher.
Pingora supports resource identifiers containing queries; its publisher matches
the derived endpoint's path and query exactly.

## Verify discovery and isolation

Run these against the public HTTPS entry point. For a local routing check only,
you can point `BASE` at the example's HTTP listener; advertised resource and
metadata URLs will still use `PUBLIC_BASE`.

```sh
BASE=https://api.example.com
curl -i "$BASE/.well-known/oauth-protected-resource/mcp/inventory"
curl -I "$BASE/.well-known/oauth-protected-resource/mcp/payments"
curl -i "$BASE/mcp/inventory/items"
curl -i -X POST "$BASE/.well-known/oauth-protected-resource/mcp/inventory"
```

Expect:

| Request | Result |
|---|---|
| Metadata GET without a token | 200 JSON with the intended `resource` and `authorization_servers` |
| Metadata HEAD without a token | 200 with representation headers and no body |
| Protected endpoint without a token | 401; `WWW-Authenticate` advertises that resource's metadata URL |
| Metadata POST | 405 with `Allow: GET, HEAD` |

Repeat GET and the unauthenticated endpoint check for the other resource.
Obtain access tokens from your provider; these examples do not issue them.
Test a token for each resource on its own endpoint, then on the other resource.
With distinct accepted audiences, a token for the wrong resource must receive
401. A token with the correct audience but missing an enforced scope must
receive 403. For Pingora, ensure scoped rules have been added before this check.
A correctly authorized request should reach its handler or upstream.

If discovery fails, check that no authentication layer or branch wraps the
metadata endpoint. If the challenge points to the wrong document, check the
selected resource and trusted public base URL. If a token crosses resource
boundaries, check for overlapping audiences and missing route protection.
