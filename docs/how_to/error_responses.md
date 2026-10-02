# Customize authentication error responses

Use separate renderers for browser-login pages and resource-server rejections.
They receive different information: login pages get a status and message;
resource rejections also expose token error codes, required scopes, and
challenge values. Metadata endpoints keep their own JSON and method responses.

## Resource-server error bodies

Both adapters accept an `ErrorBody` renderer through `.error_body(...)`.
The default is an empty body. Use the structured fields instead of parsing
`WWW-Authenticate`; missing credentials have no error code, and server-side
failures deliberately omit internal descriptions. This JSON example has the
same payload in both adapters:

```rust
# #[cfg(feature = "resource")]
# mod resource_example {
use huskarl_pingora::resource::{ErrorBody, ErrorBodyResponse, ErrorDetails};
use http::HeaderValue;

#[derive(Clone)]
struct ApiErrors;

impl ErrorBody for ApiErrors {
    fn error_body(&self, details: &ErrorDetails<'_>) -> ErrorBodyResponse {
        let body = serde_json::json!({
            "status": details.status.as_u16(),
            "error": details.error_code.map(|code| code.as_str()),
            "error_description": details.error_description,
            "scope": details.required_scopes.map(|scopes| scopes.join(" ")),
        });
        ErrorBodyResponse::new(body.to_string(), HeaderValue::from_static("application/json"))
    }
}
# fn configure<P, V>(proxy: huskarl_pingora::resource::AuthProxy<P, V>)
# where V: huskarl_pingora::resource_server::validator::AccessTokenValidator
#     + huskarl_pingora::resource_server::validator::metadata::ProvideValidatorMetadata {
let proxy = proxy.error_body(ApiErrors);
# }
# }
```

Configure the renderer on `AuthProxy`, or on `BoundResource` for a defined
resource. The resource binding is retained. It applies to validation, audience, scope, custom-check,
and path-policy denials. It does not run for forwarded requests or metadata.
`ErrorBodyResponse` accepts only body bytes and a content type. The library
sets status, `WWW-Authenticate`, `DPoP-Nonce`, `Retry-After`, `Cache-Control`, and
content length. HEAD returns the representation headers without body bytes.

For resource assembly, configure the bound resource before converting it to a
route: `bound.error_body(ApiErrors).into_route()`. Pass that bundle to
`ResourceAssembly::register_bound`; its resource definition and prepared metadata
are retained. Calling `error_body` again replaces the renderer.

## Browser-login error pages

Both adapters use `huskarl_login::ErrorPage`. The renderer controls the media
type and body; the login engine controls the response status and protocol
headers. This example uses plain text so provider-supplied messages cannot be
interpreted as HTML:

```rust
# #[cfg(feature = "login")]
# mod login_example {
use huskarl_login::{ErrorPage, ErrorPageResponse};
use http::StatusCode;

struct LoginErrors;

impl ErrorPage for LoginErrors {
    fn render(&self, status: StatusCode, message: &str) -> ErrorPageResponse {
        ErrorPageResponse {
            content_type: "text/plain; charset=utf-8",
            body: format!("Sign-in failed ({status}): {message}").into(),
        }
    }
}
# }
```

If you render HTML instead, escape the message for that context. Provider and
request-derived messages are untrusted. Use JSON serialization for JSON bodies.

Add `.error_page(Box::new(LoginErrors))` to `LoginEngine::builder()`, then pass
that engine to `LoginProxy::builder().engine(Arc::new(engine))`. The proxy uses
the engine's renderer for login errors and login policy denials; no second
page renderer is needed on the proxy.

This customization cannot replace an upstream body after Pingora has committed
to that response. In particular, the persistence-failure policy can fail the
request with a status at that stage, but cannot supply a replacement page.
