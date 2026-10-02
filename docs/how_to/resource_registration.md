# Assemble resources from shared definitions

For integration with an independently owned server, see
[publication contributions](crate::_docs::how_to::publication_contributions) and
the [publication design](crate::_docs::explanation::endpoint_publication).

Use `huskarl-resource-server::resource::ResourceDefinition` as the source
of truth for a resource's public identifier, accepted audiences, ingress mount,
and canonical metadata endpoint. Construct it before the validator, so the
validator can use the definition's audiences too.

```rust
use huskarl_pingora::resource_server::{
    core::url_mapping::PublicUrlMapping,
    resource::{AudienceBinding, ResourceDefinition},
};

let mapping = PublicUrlMapping::new("https://api.example.com/gateway", "/edge")?;
let inventory = ResourceDefinition::builder()
    .mapping(mapping.clone())
    .subpath("/mcp/inventory")
    .audience(AudienceBinding::ResourceIdentifier)
    .resource_name("Inventory API")
    .resource_documentation("https://api.example.com/docs/inventory")
    .build()?;
assert_eq!(inventory.resource(), "https://api.example.com/gateway/mcp/inventory");
assert_eq!(inventory.incoming_mount(), "/edge/mcp/inventory");
# Ok::<(), Box<dyn std::error::Error>>(())
```

You can prepare a resource with `BoundResource::builder()` and pass
`bound.into_route()` to `ResourceAssembly::register_bound`. Its definition,
authenticated branch, and metadata remain paired until the assembly consumes it.
For a custom consuming server, see the publication contribution guide.

Alternatively, pass the definition, validator, validated policy, and inner proxy
to `ResourceAssembly::register` using `.register().definition(&definition)`
followed by `.validator(validator).policy(policy).inner(inner).call()`.
`ResourcePolicy` contains access rules and
path-guard assumptions; it cannot carry a validator or URL mapping. The definition
supplies the only resource mapping. Policy routes use incoming request coordinates,
including the ingress prefix and resource mount (for example, `/edge/mcp/inventory`).
The assembly binds authentication, mounts its branch, collects metadata, and
checks consistency. Finish with `.assemble().fallback(fallback).slot(slot)`
followed by `.path_guard(path_guard).call()`, supplying the fallback route,
application route-slot lens, and a server-wide `GuardConfig`.
Path ambiguity is checked before selecting
a branch or invoking its early hooks. The existing router still owns hook
delegation and module initialization. For composition with unrelated public
endpoints, the advanced `publication_proxy` example consumes the contributions directly
in its own server router, alongside an operator-supplied `security.txt`.

Metadata publication has an independent mapping. For the resource above, its
canonical URL is
`https://api.example.com/.well-known/oauth-protected-resource/gateway/mcp/inventory`.
That URL is outside `/gateway`, so the resource mapping cannot locate it. Supply
an origin-root mapping for metadata, or explicitly describe the rewrite your
front proxy applies to that namespace. The advertised public URL stays canonical;
only the incoming dispatch path changes.

## Shared contract with Axum

Axum's `ResourceRouter::register` consumes the same definition, a validator,
a scope list (`Vec<String>`), and a router whose routes are relative to the resource
mount. It installs the authentication layer and publishes metadata separately.
The public URL is reconstructed from `OriginalUri`, preserving nested prefixes.
Build the assembly at the application root; nesting the assembled router later
would change the configured ingress coordinates. For custom nesting, use
`ValidatorLayer::for_resource` and mount its metadata service separately.

Both assemblies reject overlapping authentication mounts, mixed public origins,
and metadata endpoint collisions. Root-mounted resources are supported. The
registered metadata paths are reserved public exceptions, even if an application
handler has the same path. Other application paths, unknown well-known paths,
and descendants or lookalikes of metadata paths remain subject to authentication.
Routing syntax is validated by each adapter, not by the shared resource model.

Axum dispatches metadata by path and rejects query-only collisions. Pingora
selects the document by path and query: an unregistered query on a reserved
metadata path returns 404 and never reaches the application's fallback. Other
methods on a published endpoint return 405 without invoking authentication.
Query parameters in a resource identifier do not restrict the authentication
subtree to requests with those parameters: the entire mounted subtree belongs
to that resource.

The definition builder also accepts `resource_policy_uri`, `resource_tos_uri`,
and `scopes_supported`. Explicit scopes override adapter defaults; an explicit
empty list omits the field. When unset, Axum uses its supplied list and Pingora
collects scopes from guard rules. Lists are sorted and deduplicated. Scope advertisement does not grant access; configure scope
requirements in the guard or the Axum subtree's authorization layers.

## Login URL mapping

`PublicUrlMapping` also backs login URL reconstruction. Pass it through
`LoginConfig::builder().url_mapping(mapping)` and derive the callback using
`huskarl_login::url::callback_path(&mapping, &redirect_uri, None)`. An explicit
callback override can be supplied as the final argument and must map back to the
public callback path. Configure logout paths in ingress coordinates.

Engine construction rejects a callback whose browser-facing path disagrees with
the grant's redirect URI, and a mapping whose origin disagrees with the grant.
This moves configuration failures to startup. Axum's trusted `RequestUrl` is
already a public URL: login inverse-maps it before routing and reconstructs it
once for redirects. Overrides outside the configured origin or public prefix
return 400. Arbitrary non-prefix rewrites require a custom adapter contract.

## Standalone authentication and limits

For authentication without a resource definition, use `Guard::builder()` with
`.validator(validator)` and `.policy(policy)`, then wrap the built guard with
`AuthProxy::new`. Set `.url_mapping(mapping)` for trusted public URL reconstruction,
or omit it to pass the original request URI to the validator. DPoP validation
requires a public target; origin-form requests with no mapping fail closed.

Resource-bound proxies are constructed only through `BoundResource::builder` and
cannot be rebound. Legacy resource `base_uri`, `strip_prefix`, and binding setters
have been removed. Use `PublicUrlMapping` for all resource URL reconstruction.
Bare prefixes and trailing slashes remain distinct: mapping `/edge` to
`https://api.example.com/gateway` does not silently append `/`.

Mapping preserves escaped bytes and queries and does not rewrite forwarded
requests, trust incoming Host headers, or normalize paths. It does not replace
the path guard. An endpoint must round-trip through the mapping; a public base
path without its joining slash cannot silently become a different callback URL.

This change does not alter session finalization, cache isolation, cookie delivery,
or disconnect guarantees. Those remain adapter lifecycle responsibilities; see
the login finalization reference and per-user caching guide.
