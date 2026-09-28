# Contribute metadata to an existing publisher

For server integration, construct a `BoundResource` once. Its private fields keep
its definition, authenticated branch, and prepared metadata together until the
consuming server installs them. Existing low-level binding APIs remain available.

Pingora exposes `resource::BoundResource`. Construct it with the definition,
guard, and inner proxy; use `into_route()` when collecting heterogeneous branches.
`ResourceAssembly::register_bound` consumes that routed bundle. Existing
`ResourceAssembly::register` constructs the same bundle internally.

Axum exposes `resource_router::BoundResource`. Construct it with the definition,
validator, scopes, and relative application router; authentication is applied
before the bundle is returned. `ResourceRouter::register_bound` consumes it, and
`ResourceRouter::register` delegates to that same path.

For a custom server, call `definition()` and `metadata()` to inspect the bundle,
and `into_parts()` at the routing boundary. That returns the matching definition,
authenticated proxy/router, and publication contribution. Mount according to the
definition; publish the metadata independently or export it. The consumer still
owns overlaps, precedence, and framework nesting coordinates. The bundle prevents
accidental mixing before handoff; it cannot prevent an arbitrary router from
mounting the extracted parts incorrectly.

```rust
use huskarl_pingora::resource::{AuthProxy, BoundResource, ConfigError, Guard};
use huskarl_pingora::resource_server::{
    resource::ResourceDefinition,
    validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata},
};
fn bind<P, V>(definition: ResourceDefinition, guard: Guard<V>, inner: P)
    -> Result<BoundResource<AuthProxy<P, V>>, ConfigError>
where V: AccessTokenValidator + ProvideValidatorMetadata
{
    BoundResource::new(definition, guard, inner)
}
```

Neither constructing nor inspecting the bundle installs a local metadata route.
The native metadata handlers and snapshot export below use the same prepared
content, without a second metadata preparation during assembly.

## Export a snapshot

`PreparedResource`, Pingora's `ResourceMetadataEndpoint`, and Axum's
`ResourceMetadataService` expose the same borrowed `ResourcePublication` view.
It contains the canonical absolute URL, the exact JSON bytes, and the media type.
Copy these when handing them to a separate process or static publisher:

```rust
use huskarl_pingora::resource::ResourceMetadataEndpoint;

fn export(metadata: &ResourceMetadataEndpoint) -> (String, &'static str, Vec<u8>) {
    let publication = metadata.publication();
    (
        publication.uri.to_string(),
        publication.content_type(),
        publication.body.to_vec(),
    )
}
```

Use the contribution returned by binding, so publication and authentication
challenges use the same prepared information. A framework-independent consumer
can call `ResourceDefinition::prepare` and then `PreparedResource::publication`.
This is a snapshot: changes to the resource configuration require preparing and
republishing it. There is no background refresh or remote publication check.

The external publisher owns deployment, GET/HEAD serving, unsupported-method
handling, cache policy, and routing. Preserve the full canonical URL, including
any query component. Do not turn a URI directly into a filesystem path; choose
an artifact location and keep the public URL in the deployment configuration.
Native handlers currently return JSON, allow GET/HEAD, reject other methods with
405, and advertise a one-hour cache lifetime. An external publisher must account
for its own update schedule and protocol requirements.

## Mount the Pingora handler independently

The canonical URL stays public even when a gateway rewrites incoming paths:

```rust
use huskarl_pingora::{
    resource::{ResourceMetadataEndpoint, ResourceMetadataProxy},
    resource_server::core::url_mapping::PublicUrlMapping,
};

fn publisher<P>(metadata: ResourceMetadataEndpoint, not_found: P)
    -> Result<(http::Uri, ResourceMetadataProxy<P>), Box<dyn std::error::Error>>
{
    let mapping = PublicUrlMapping::new(
        "https://api.example.com/.well-known", "/discovery",
    )?;
    let metadata = metadata.with_mapping(&mapping)?;
    let incoming = metadata.incoming_uri().clone();
    let handler = ResourceMetadataProxy::new(not_found).publish(metadata)?;
    Ok((incoming, handler))
}
```

The consuming router selects this handler at `incoming.path()` for every method,
before authentication hooks run. Pingora's publisher matches the path and query;
its fallback should return 404 for unregistered queries on that reserved path.
The `not_found` argument above must implement that behavior when used as a proxy.
Configure `/.well-known/security.txt`, ACME routes, and other protocols separately
in the consuming router. Check conflicts there; this API does not claim the
whole well-known namespace or inspect other handlers.

`with_mapping` rejects incompatible public origins or prefixes. It preserves the
canonical URL and bytes and only changes dispatch coordinates. A reverse proxy
must actually perform the configured rewrite; the mapping does not rewrite
forwarded requests.

## Complete Pingora consumer

The [advanced publication example](https://github.com/huskarl-rs/huskarl-pingora/blob/main/examples/publication_proxy.rs)
consumes metadata contributions in its own server router and optionally serves
an operator-supplied `security.txt` alongside them. Its router checks resource
relationships, reserves exact publication paths for all methods, and rejects
ambiguous paths before selecting a branch. The
[metadata guide](crate::_docs::how_to::resource_metadata) includes configuration,
rewrite examples, and the integration-test command.

## Axum integration

Axum's metadata service can already be mounted at an independently chosen path.
Use `mapping.incoming_uri(metadata.uri())?` and mount it with
`Router::route_service(incoming.path(), metadata)`. Put that route and unrelated
public endpoints in the outer router, with the protected application as its
fallback. `ResourceMetadataService` documents a complete composition example.

Axum dispatches by path and its metadata service ignores query parameters.
Consumers must reject query-only document collisions or provide their own
query-aware dispatcher using exported snapshots. Mounting the service does not
apply resource authentication; outer middleware, including login middleware,
still applies. Unknown well-known paths have the consumer's configured fallback.
