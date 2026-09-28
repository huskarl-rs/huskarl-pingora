# Contribute metadata to an existing publisher

Bind authentication once using `AuthProxy::with_resource_definition` (Pingora)
or `ValidatorLayer::for_resource` (Axum). Each returns authentication and metadata
separately. Keeping the metadata value does not mount it. Existing resource
assemblies are optional conveniences for mounting these same contributions.

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
