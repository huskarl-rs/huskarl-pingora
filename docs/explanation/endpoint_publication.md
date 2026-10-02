# Why resource binding and metadata publication are separate

A protected resource has two related entry points: application requests need
authentication, while clients need public metadata to discover how to authenticate.
Both must describe the same resource and accepted audiences. `BoundResource`
prepares the authenticated proxy and its metadata from one definition so they
agree when handed to the server.

Publication is separate because a resource does not necessarily own the listener,
the public URL namespace, or even the process that serves its discovery document.
For code, use [resource assembly](crate::_docs::how_to::resource_registration) or
[publication contributions](crate::_docs::how_to::publication_contributions).

## One resource definition, two routes

For `https://api.example.com/api`, the application mount is `/api`, while metadata
is served at `/.well-known/oauth-protected-resource/api`. In a direct deployment:

| Incoming request | Handler | Authentication |
|---|---|---|
| `/api` and descendants | Resource proxy | Resource policy |
| `/.well-known/oauth-protected-resource/api` | Metadata publisher | Public |
| `/.well-known/security.txt` | Operator's separate handler | Operator's policy |

The metadata URL follows [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html#section-3).
The broader `/.well-known/` namespace contains unrelated protocols with their own
methods and response formats. Publishing resource metadata does not give the
library ownership of that namespace or create a blanket authentication exception.

## Two ways to compose a server

`ResourceAssembly` registers resource branches and metadata on one listener. It
checks disjoint resource mounts, a shared public origin, and publication conflicts.
Metadata paths are reserved public exceptions even under a protected root mount.
Unknown queries at those paths return 404 instead of falling into authentication.

A custom server can consume `BoundResource::into_parts()` and install the parts
itself. It owns route conflicts, precedence, fallback behavior, and selection
before branch hooks. Keeping the bundle intact until handoff prevents accidental
mixing of definitions and proxies; it cannot prevent a router from mounting the
extracted proxy at the wrong path. The proxy retains its resource-boundary checks.

Outer middleware still applies. For example, a login wrapper around the entire
server can protect a metadata route that the resource layer considers public.
The final composition must make the intended discovery endpoint reachable.

## Public identity and incoming routing can differ

A gateway may expose `/gateway/api` but forward it as `/edge/api`. The canonical
metadata URL still begins at the public origin's `/.well-known/` path, outside
`/gateway`. It therefore needs its own mapping:

| Purpose | Public path | Incoming path |
|---|---|---|
| Application | `/gateway/api` | `/edge/api` |
| Metadata | `/.well-known/oauth-protected-resource/gateway/api` | `/discovery/oauth-protected-resource/gateway/api` |

Mapping changes where the server dispatches a request, not the public resource
identity or advertised metadata URL. It does not perform gateway rewrites or
normalize forwarded paths. The [URL mapping recipe](crate::_docs::how_to::url_mapping)
and [metadata guide](crate::_docs::how_to::resource_metadata) cover configuration.

## Publication in another process

`ResourceMetadataEndpoint::publication()` exposes the canonical URL, prepared JSON
bytes, and media type. A gateway or static publisher can serve that snapshot
without constructing another validator or recomputing metadata.

The external publisher owns serving, method handling, caching, and updates. A
configuration change requires preparing and republishing the snapshot. Binding
cannot prove that a remote endpoint is live or current. The resource's challenge
and the published document must remain consistent through deployment.

## Relationship to Axum

The shared `huskarl-resource-server` definition and publication view also serve
Axum integrations. Their framework routing contracts differ: Pingora dispatches
metadata by path and query; Axum's native service dispatches by path. Framework
nesting and middleware ordering remain adapter-specific. Consult the
[Axum documentation](https://docs.rs/huskarl-axum/latest/huskarl_axum/) when moving
an integration; do not transfer Pingora routing code directly.
