# Map public URLs to incoming paths

Use `PublicUrlMapping` when a gateway changes a public path prefix before
forwarding to Pingora. Establish the actual rewrite first: configuring a mapping
does not change the gateway or the request forwarded to the upstream.

## 1. Write down both path spaces

For a gateway exposing `https://app.example.com/gateway` and forwarding to `/edge`:

| Public path | Path received by Pingora |
|---|---|
| `/gateway/dashboard` | `/edge/dashboard` |
| `/gateway/callback` | `/edge/callback` |
| `/gateway/logout` | `/edge/logout` |

```rust
# #[cfg(feature = "resource")]
use huskarl_pingora::resource_server::core::url_mapping::PublicUrlMapping;
# #[cfg(all(feature = "login", not(feature = "resource")))]
# use huskarl_login::core::url_mapping::PublicUrlMapping;
let mapping = PublicUrlMapping::new("https://app.example.com/gateway", "/edge")?;
# let _ = mapping;
# Ok::<(), Box<dyn std::error::Error>>(())
```

For a direct origin-root deployment use public base `https://app.example.com`
and incoming prefix `/`. Bare prefixes and trailing slashes are distinct;
`/edge` and `/edge/` are not silently made equivalent. Mapping preserves escaped
bytes and queries. Only trust deployment configuration for the public origin.

## 2. Apply the mapping to your integration

For a defined resource, pass the mapping to `ResourceDefinition` and supply a
resource subpath. For example, `/api` gives public resource
`https://app.example.com/gateway/api` and incoming mount `/edge/api`. Policy routes
use `/edge/api`, including that mount prefix. Follow
[resource assembly](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/resource_registration/)
for the complete integration.

For standalone `Guard`, set `.url_mapping(mapping)`. Without it the original
request URI goes to the validator; origin-form requests cannot establish the
public target required for DPoP validation.

For browser login, set `LoginConfig::builder().url_mapping(mapping.clone())` and
derive the incoming callback with
`huskarl_login::url::callback_path(&mapping, &redirect_uri, None)`. Register the
full public redirect URI with the provider. Logout and application route policies
use incoming coordinates. Engine construction checks the mapping and callback
against the grant's redirect URI. See the shared
[URL API](https://docs.rs/huskarl-login/0.5.0/huskarl_login/url/) for override rules.

The runnable login example accepts `PUBLIC_BASE`, `INCOMING_PREFIX`, and
`REDIRECT_URI`; see its [rewrite walkthrough](https://github.com/huskarl-rs/huskarl-pingora/blob/main/examples/README.md#browser-login-and-rewrites).

## 3. Map metadata separately

Resource metadata is rooted at `/.well-known/oauth-protected-resource`, outside
an application's public prefix. Supply an origin-root metadata mapping or one
that describes the gateway's separate discovery rewrite. See
[metadata publication](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/resource_metadata/).

## 4. Verify the whole path

Check callback, logout, application, and metadata requests through the real
gateway. Confirm that advertised URLs retain their public form and that the
upstream accepts the unchanged incoming paths. Test encoded separators and dot
segments with `curl --path-as-is` at each rewrite boundary. URL mapping does not
replace the [path guard](crate::_docs::how_to::path_guard) or model arbitrary
non-prefix rewrites.
