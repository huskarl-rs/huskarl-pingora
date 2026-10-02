# Publication contributions for an external server

Status: implemented contribution handoff for Pingora and Axum. See
[publication contributions](crate::_docs::how_to::publication_contributions) for
export and mounting examples. General namespace management remains external.

Resource registration provides information that an independently owned server,
gateway, or well-known manager can publish. The consumer owns the broader
namespace and may support protocols we do not know about. Keep the existing
resource definitions, URL mapping, and metadata preparation. Make their output
consumable without requiring our assembly or an in-process callback.

## Why widen the boundary?

`/.well-known/` is a shared namespace. Its protocols define their own formats,
methods, query handling, and additional path components. The prefix does not imply
a directory index or a uniform access policy. See
[RFC 8615 section 3](https://www.rfc-editor.org/rfc/rfc8615.html#section-3).

Current `ResourceAssembly` and Axum `ResourceRouter` collect only OAuth
protected-resource metadata. They correctly reserve individual metadata paths,
including inside a protected root, but cannot validate their ownership against
other server endpoints. Manually composing an outer router works, with consistency
checks left to the caller.

The first change should expose our canonical publication URL and prepared
metadata, with optional native handlers for convenient local mounting. A general
well-known registry, ownership framework, or new shared crate is outside scope.

## Three deployments

### OAuth metadata alongside security.txt

On `https://api.example`, publish these independently:

| Incoming path | Owner | Access in this deployment |
| --- | --- | --- |
| `/.well-known/oauth-protected-resource/api` | Resource metadata handler | Public |
| `/.well-known/security.txt` | Operator-supplied handler | Public |
| `/api` and descendants | Resource authentication branch | Authenticated |

Resource registration derives its canonical metadata URL according to
[RFC 9728 section 3](https://www.rfc-editor.org/rfc/rfc9728.html#section-3).
The operator supplies the security.txt handler and its response policy. The
consuming server owns conflict detection and route precedence for these
contributions. Our contribution identifies only its own metadata endpoint.

### Protected root with ACME HTTP-01

The HTTPS application owns `/`; resource metadata and security.txt are explicit
public exceptions. Certificate validation has a separate HTTP listener with an
owned `/.well-known/acme-challenge/` subtree. Its handler resolves active tokens
and returns 404 for unknown or expired tokens. Other HTTP requests follow the
operator's configured fallback, such as an HTTPS redirect.

HTTP-01 starts with an HTTP GET on port 80 and serves a token-specific key
authorization, so publication cannot universally require HTTPS or static JSON.
See [RFC 8555 section 8.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-8.3).
The external server supplies the ACME mounting point, client, and token store.
Our API neither models nor registers that protocol.

The subtree owns all methods and query variants; its handler decides their
meaning. A missing token or unsupported method must not fall through to login,
resource authentication, or an unrelated application handler. Its sibling
`/.well-known/acme-challenge-other` is outside that ownership. The bare path
without the trailing slash needs an explicit endpoint or fallback decision.

### Gateway publication with rewritten incoming paths

For resource `https://api.example/gateway/inventory`:

| Purpose | Public path | Incoming path |
| --- | --- | --- |
| Application | `/gateway/inventory` | `/edge/inventory` |
| Metadata | `/.well-known/oauth-protected-resource/gateway/inventory` | `/discovery/oauth-protected-resource/gateway/inventory` |

The application mapping and publication mapping are separate. The latter maps
public base `https://api.example/.well-known` to incoming prefix `/discovery`.
Advertisements and challenges retain the canonical public URL. Mapping affects
dispatch coordinates, not the metadata identity or forwarded request bytes.

Alternatively, the gateway serves the prepared document itself. Binding resource
authentication must not force a local metadata route. Deployment configuration
then owns the association between the exported document and the gateway route;
local startup validation cannot prove remote publication is live or current.

Different protocols may be handled by different listeners or gateways. Do not
turn the current metadata mapping into one mandatory mapping for all well-known
endpoints. Existing prefix mapping remains sufficient for the example; arbitrary
rewrites require an explicit adapter integration.

## Contribution contract

The contribution API follows these responsibilities:

1. Bind a resource once, yielding its authentication configuration and publication
   contribution from the same prepared metadata.
2. Expose the canonical absolute public URL, including any query, and the prepared
   metadata document or serialized bytes with their media type. A static publisher
   or separate process must be able to consume these without an adapter callback.
3. Offer framework-native handlers for consumers that want our HTTP behavior:
   an Axum service or a Pingora proxy branch. A portable callback abstraction is
   unnecessary.
4. Document our endpoint's serving contract, including GET/HEAD, unsupported
   methods, and the adapter's query behavior. Make the supported ingress mapping
   available for local handlers without changing the canonical public URL.

The receiving system chooses incoming paths, listeners, virtual hosts, routing
conflicts, and precedence. It can mount the handler, serve the exported document,
or forward requests elsewhere. Exporting data does not also install a local
route. No generic subtree-ownership declarations are required by our API.

Our responsibility is consistency between resource identity, authentication
challenges, canonical metadata URL, and exported content. The consumer must make
that content reachable at the advertised public URL. A custom publisher owns
protocol-compliant HTTP serving, updates, cache policy, and deployment; exporting
a prepared snapshot does not establish automatic refresh or remote health checks.

For local handlers, preserve existing behavior: Pingora selects metadata by path
and query, while Axum mounts its service by path. State these capabilities so a
consumer can reject unsupported combinations instead of silently losing query
information. Method/query misses and handler failures must remain with the
selected metadata handler, rather than reaching an application that assumes
prior authentication.

Unknown well-known paths and other protocols remain the consumer's responsibility.
There is no blanket authentication exception. Outer deployment middleware still
applies: mounting metadata does not implicitly bypass a login wrapper, inject
cookies, or repair unsafe caching. Public URL mappings come from trusted
configuration, not arbitrary Host or forwarding headers.

## Fit with both adapters and shared crates

| Component | Keep | Proposed adjustment |
| --- | --- | --- |
| `huskarl-resource-server` | `ResourceDefinition`, audiences, prepared metadata and challenge consistency | Keep resource relationship validation; separate local publication checks from binding so external publication is possible |
| `huskarl-core` | `PublicUrlMapping` | Reuse per publication where appropriate; no universal well-known URL derivation |
| `huskarl-login` | Login configuration and session engine | No general publication registry |
| Pingora | `BoundResource::new`, `ResourceMetadataProxy`, existing lifecycle router | Expose metadata information and a native handler; provide supported mapped publication beyond private `mount_at` |
| Axum | `ValidatorLayer::for_resource`, `ResourceMetadataService`, native `Router` | Expose metadata information alongside the native service; preserve state and `OriginalUri` when mounted |

The low-level binding APIs already return authentication and metadata separately.
Shared `PreparedResource` already exposes serialized content. Reuse these pieces
and close the adapter handoff gaps, particularly access to the same prepared
content used for binding. Do not require consumers to rebuild metadata from a
second, potentially different validator configuration.

Keep the data contract in `huskarl-resource-server` and handler types native to each
adapter. Preserve existing resource assemblies as optional conveniences built on
the same contributions, with their existing bounded consistency checks. They do
not become general well-known managers, and consumers need not adopt them.

## Integration acceptance checks

Run equivalent observable scenarios in Pingora and Axum; response status alone
is insufficient. Record which handler and authentication hooks ran.

| Scenario | Required observation |
| --- | --- |
| Metadata and security.txt beside protected root | Public handlers run without resource authentication; ordinary application requests still authenticate |
| Consumer already owns our metadata path | Integration example detects the conflict using the consumer's routing facilities; no last-registration-wins behavior |
| Unknown well-known path, descendant of exact endpoint, prefix lookalike | No accidental public exemption |
| Method/query rejection or handler failure within owned publication | Owner responds; application and authentication fallback never run |
| Independently mounted ACME handler | Our contribution leaves that routing untouched; ACME token lifecycle tests belong to its owner |
| Rewritten metadata path | Advertised URL remains canonical; only configured incoming route serves it |
| Data-only publication | Exported URL, media type and content agree with authentication challenges; usable without framework callbacks or a forced local endpoint |
| Axum state and URI extraction | State and original ingress URI preserved; assembly installed at configured root |
| Pingora local and forwarded publication responses | Selected branch receives lifecycle hooks and modules; existing finalization guarantees preserved |
| Per-endpoint cache policy | One endpoint's headers do not become namespace-wide defaults; private application responses retain isolation |

Adapter-specific `BoundResource` values keep the validated definition,
authenticated branch, and metadata together until routing handoff. Convenience
assemblies use the same binding path as custom consumers.

The implementation exposes `ResourcePublication` from prepared metadata and both
adapters, and adds validated Pingora ingress mapping. Tests compare exported and
served bytes with bound authentication metadata. Existing assemblies retain their
routing behavior. Generic namespace ownership and collision algorithms remain
outside this work; consumer-specific checks in the matrix belong to deployment
integration tests.
