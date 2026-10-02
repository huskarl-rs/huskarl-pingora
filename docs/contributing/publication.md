# Testing publication integration

Use these scenarios when changing the routing/publication boundary. For the
current design, see the [publication explanation](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/explanation/endpoint_publication/).

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
