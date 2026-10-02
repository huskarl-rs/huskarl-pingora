# Assemble protected resources on one listener

Use `ResourceAssembly` when this server owns resource routing and discovery.
It installs authentication and public metadata routes together. You supply a
validator and inner proxy per resource, a shared context, and a fallback.
For a guided first run, follow the [resource tutorial](crate::_docs::tutorial::resource_proxy).
For an independently owned router, use [publication contributions](crate::_docs::how_to::publication_contributions).

## 1. Name the resource and configure its validator

Create the definition before the validator. Pass its accepted audiences to your
validator so token validation and resource binding agree. In this example the
public resource is `https://api.example.com/api`, also its accepted audience:

```rust
use huskarl_pingora::resource_server::{
    core::url_mapping::PublicUrlMapping,
    resource::{AudienceBinding, ResourceDefinition},
};

let mapping = PublicUrlMapping::new("https://api.example.com", "/")?;
let definition = ResourceDefinition::builder()
    .mapping(mapping.clone())
    .subpath("/api")
    .audience(AudienceBinding::ResourceIdentifier)
    .resource_name("Example API")
    .build()?;
assert_eq!(definition.audiences(), &["https://api.example.com/api"]);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Use `AudienceBinding::mapped(["my-api"])` when the issuer uses another audience.
See the [standalone authentication recipe](crate::_docs::how_to::resource_proxy)
for RFC 9068 validator construction. The runnable
[resource example](https://github.com/huskarl-rs/huskarl-pingora/blob/main/examples/resource_proxy.rs)
passes `definition.audiences()` to its validator helper.

## 2. Give every branch the same context

The context holds validated credentials and a `RouteSlot` that remembers which
branch receives later Pingora hooks. `AuthCtx` supplies credential storage; this
example delegates the trait methods to it. The validator uses RFC 9068 claims.

```rust
use std::sync::Arc;
use huskarl_pingora::{
    resource::{AuthCtx, HasAuthState},
    resource_server::validator::{ValidatedRequest, rfc9068::Rfc9068AccessTokenClaims},
};
use pingora_proxy_router::RouteSlot;

type Claims = Rfc9068AccessTokenClaims;
#[derive(Default)]
struct AppContext {
    auth: AuthCtx<(), Claims>,
    route: RouteSlot<Self>,
}
impl HasAuthState<Claims> for AppContext {
    fn validated_token(&self) -> Option<&Arc<ValidatedRequest<Claims>>> {
        self.auth.validated_token()
    }
    fn validated_token_mut(&mut self) -> &mut Option<Arc<ValidatedRequest<Claims>>> {
        self.auth.validated_token_mut()
    }
    fn dpop_nonce_mut(&mut self) -> &mut Option<String> { self.auth.dpop_nonce_mut() }
    fn strip_credentials(&self) -> bool { self.auth.strip_credentials() }
    fn set_strip_credentials(&mut self, strip: bool) { self.auth.set_strip_credentials(strip); }
}
```

Use this context as `ProxyHttp::CTX` for the upstream and fallback branches.
The complete example's [transport support](https://github.com/huskarl-rs/huskarl-pingora/blob/main/examples/support/resource_server.rs)
shows both implementations and listener startup.

## 3. Register the resource and assemble the router

This function accepts your configured validator, upstream proxy, and fallback.
The fallback should return 404 when requests outside the registered resources
have no application handler. Resource policy paths include the incoming mount.

```rust
use huskarl_pingora::{
    resource::{CaseSensitivity, DecodeDepth, GuardConfig, ResourcePolicy, Rule,
        assembly::{AssembledResources, ResourceAssembly}},
    resource_server::{core::url_mapping::PublicUrlMapping, resource::ResourceDefinition,
        validator::{AccessTokenValidator, metadata::ProvideValidatorMetadata}},
};
use pingora_proxy::ProxyHttp;
use pingora_proxy_router::{context_lens, route};
# use std::sync::Arc;
# use huskarl_pingora::{resource::{AuthCtx, HasAuthState},
#     resource_server::validator::{ValidatedRequest, rfc9068::Rfc9068AccessTokenClaims}};
# use pingora_proxy_router::RouteSlot;
# type Claims = Rfc9068AccessTokenClaims;
# #[derive(Default)]
# struct AppContext { auth: AuthCtx<(), Claims>, route: RouteSlot<Self> }
# impl HasAuthState<Claims> for AppContext {
# fn validated_token(&self) -> Option<&Arc<ValidatedRequest<Claims>>> { self.auth.validated_token() }
# fn validated_token_mut(&mut self) -> &mut Option<Arc<ValidatedRequest<Claims>>> { self.auth.validated_token_mut() }
# fn dpop_nonce_mut(&mut self) -> &mut Option<String> { self.auth.dpop_nonce_mut() }
# fn strip_credentials(&self) -> bool { self.auth.strip_credentials() }
# fn set_strip_credentials(&mut self, strip: bool) { self.auth.set_strip_credentials(strip); }
# }

fn assemble<P, F, V>(
    definition: &ResourceDefinition,
    metadata_mapping: PublicUrlMapping,
    validator: V,
    upstream: P,
    not_found: F,
) -> Result<AssembledResources<AppContext>, Box<dyn std::error::Error>>
where
    P: ProxyHttp<CTX = AppContext> + Send + Sync + 'static,
    F: ProxyHttp<CTX = AppContext> + Send + Sync + 'static,
    V: AccessTokenValidator<Claims = Claims> + ProvideValidatorMetadata + Send + Sync + 'static,
{
    let paths = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
    let policy = ResourcePolicy::builder()
        .path_guard(paths.clone())
        .subtree(definition.incoming_mount(), Rule::required().scopes(["api.read"]))
        .build()?;
    let router = ResourceAssembly::new(metadata_mapping)
        .register()
        .definition(definition)
        .validator(validator)
        .policy(policy)
        .inner(upstream)
        .call()?
        .assemble()
        .fallback(route(not_found))
        .slot(context_lens!(AppContext, ctx => ctx.route))
        .path_guard(paths)
        .call()?;
    Ok(router)
}
```

For the direct deployment above, pass `mapping` as `metadata_mapping`. Supply
this router to Pingora's `http_proxy_service`. To add resources, repeat
`.register()...call()?` before `.assemble()`. Each resource can use a different
validator and inner proxy, but their context type must agree. Mounts must be
disjoint and public origins must agree.

To customize rejection bodies, build a `BoundResource` with `.error_body(renderer)`,
then use `.register_bound(bound.into_route())?`; see
[error responses](crate::_docs::how_to::error_responses).

## 4. Check routing and authorization

- Fetch `/.well-known/oauth-protected-resource/api` without a token: expect JSON.
- Fetch `/api` without credentials: expect 401 and a metadata URL in the challenge.
- Send a valid token with `api.read`: expect the upstream response.
- Send a token without that scope: expect 403.
- Fetch an unrelated path: expect your fallback's response.
- Add an unregistered query to the metadata path: expect 404, without authentication.

The assembly reserves exact metadata paths for all methods, including under a
root resource. Unsupported methods on a published endpoint return 405. Query
components in resource identifiers do not restrict authentication to that query:
the entire incoming subtree belongs to the resource.

For ingress rewrites, separate application and metadata mappings as described in
[Publish protected-resource metadata](crate::_docs::how_to::resource_metadata).
