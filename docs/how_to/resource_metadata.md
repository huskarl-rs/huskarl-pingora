# Publish protected-resource metadata

Use this guide to publish RFC 9728 discovery information for one resource or
several resources on the same origin. This is the API's own metadata, separate
from the authorization-server metadata used to construct a token validator.

You need a trusted public HTTPS origin, a validator for each resource, and the
audiences your provider puts in access tokens. A logical resource can have many
endpoints; it gets one metadata document, not one per endpoint.

To integrate with an existing server or export metadata for a separate publisher,
use [publication contributions](crate::_docs::how_to::publication_contributions).

For a server hosting several resources, prefer the [shared registration assembly](crate::_docs::how_to::resource_registration). It derives mounts and metadata from one validated definition; the lower-level APIs below remain available for custom routing.

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
    AudienceBinding, BoundResource, CaseSensitivity, DecodeDepth,
    GuardConfig, ResourcePolicy, ResourceMetadataProxy, Rule,
};
use huskarl_pingora::resource_server::{
    core::url_mapping::PublicUrlMapping, resource::ResourceDefinition,
};
# fn configure<P, V>(inner: P, validator: V) -> Result<(), Box<dyn std::error::Error>>
# where V: huskarl_pingora::resource_server::validator::AccessTokenValidator
#     + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata {
let definition = ResourceDefinition::new(
    PublicUrlMapping::new("https://api.example.com", "/")?,
    "/mcp/inventory",
    AudienceBinding::ResourceIdentifier,
)?;
let policy = ResourcePolicy::builder()
    .path_guard(GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .subtree("/mcp/inventory", Rule::required().scopes(["inventory.read"]))
    .build()?;
let bound = BoundResource::new(definition, validator, policy, inner)?;
let (_definition, inventory, metadata) = bound.into_parts();
let proxy = ResourceMetadataProxy::new(inventory).publish(metadata)?;
# let _ = proxy;
# Ok(())
# }
```

`Rule::required().scopes(...)` enforces scopes. Metadata describes supported
capabilities; publishing it is not a substitute for a route policy. The guard
collects rule scopes for advertisement. A bound `ResourceDefinition` can override
that list with its builder's `scopes_supported` field.

A resource-bound proxy only applies its guard inside that resource's path.
Requests outside it are refused with 403; requests whose public URI cannot be
reconstructed are refused with 400. Neither reaches the inner proxy. Route
unrelated paths to an explicit fallback rather than treating this wrapper as
protection for the whole listener. Keep discovery outside token validation.

## Add a second resource

Build a separate `ResourcePolicy` and `BoundResource` for payments. Publish
both returned endpoints through one `ResourceMetadataProxy`. In a multi-resource
server, route the registered metadata paths to that publisher in a separate branch,
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

The simple example uses an origin-root `PUBLIC_BASE` and no ingress rewrite.
Its listener and upstream connections are plain HTTP; terminate public HTTPS at
a trusted entry point. For rewrites or publication alongside other well-known
endpoints, use the advanced example below.

## Publish alongside security.txt

The advanced `publication_proxy` example owns its server router and consumes the metadata returned by each
`BoundResource`, independently of `ResourceAssembly`. Set `SECURITY_TXT_FILE` to an
operator-maintained UTF-8 file to add `/.well-known/security.txt`. The server
loads the file at startup; restart to publish changes. Supply a valid security.txt
with your contact details and expiry. The example serves its bytes without
validating the document, and advertises a one-hour cache lifetime.

`PUBLIC_BASE` may include a public prefix in this advanced example.
`INCOMING_PREFIX` describes the application ingress prefix;
`METADATA_INCOMING_PREFIX` describes publication ingress. Both default to `/`.
Both publications share the configured metadata ingress mapping in this example;
that is a deployment choice, not a library requirement. Other well-known paths
are left to the server's fallback. Unknown queries on a reserved OAuth metadata
path return 404. GET/HEAD are supported for security.txt and other methods return
405; its handler ignores queries. No publication request enters a resource's
authentication branch or its early hooks.

For example, retain the issuer settings above and run with:

```sh
PUBLIC_BASE=https://api.example.com/gateway \
INCOMING_PREFIX=/edge \
METADATA_INCOMING_PREFIX=/discovery \
SECURITY_TXT_FILE=/etc/my-service/security.txt \
cargo run --example publication_proxy --features resource
```

The front proxy must implement these mappings:

| Public path | Incoming path at the example listener |
| --- | --- |
| `/gateway/mcp/inventory/items` | `/edge/mcp/inventory/items` |
| `/.well-known/oauth-protected-resource/gateway/mcp/inventory` | `/discovery/.well-known/oauth-protected-resource/gateway/mcp/inventory` |
| `/.well-known/security.txt` | `/discovery/.well-known/security.txt` |

For local checks, request the incoming paths at `http://127.0.0.1:6188`. OAuth
metadata and challenges must still contain the canonical public URLs. Requests
using the original public paths directly at this rewritten listener return 404.
The example does not rewrite forwarded upstream paths.

Run the example's integration tests without issuer or upstream services:

```sh
cargo test --example publication_proxy
```

They drive the server router through Pingora's real HTTP request runner using
in-memory connections and a test-only validator. They verify a protected root,
metadata and security.txt responses, method/query handling, ingress rewrites,
and whether authentication or application hooks were invoked. The executable
continues to use the real RFC 9068 validator configured from each issuer.

## Verify discovery and isolation

These commands use the default origin-root mapping. Run them against the public
HTTPS entry point. For a local routing check only,
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

## Owner fields and browser discovery

Use `ResourceDefinition::builder().mapping(mapping.clone())` to add a resource name,
documentation, privacy-policy and terms URLs, and advertised scopes before
binding. The [registration guide](crate::_docs::how_to::resource_registration)
shows this API. Existing constructors retain their defaults.

The shared [metadata guide](https://github.com/huskarl-rs/huskarl/blob/main/huskarl-resource-server/docs/guide/resource_metadata.md)
describes standalone publication and CORS for browser discovery, including
exposing `WWW-Authenticate` on locally generated authentication failures.
