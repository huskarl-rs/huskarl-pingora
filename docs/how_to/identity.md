# Forward session identity to an upstream

Use this when an upstream service needs to know who the proxy authenticated.
A loaded session is available to your inner `ProxyHttp` implementation through
[`LoginCtx`](crate::login::LoginCtx); it does not automatically appear in a
separate upstream process.

If you need profile fields or application roles beyond the default session,
first follow [Build an application session](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/how_to/enrichment/).
The resulting session is available through the same Pingora context interface.

## 1. Establish the trust boundary

Choose a dedicated header, such as `X-Authenticated-Subject`, and configure
the upstream to accept that assertion only on connections from this proxy.
Restrict direct upstream access using your network or authenticated transport.
A header alone is not proof of authentication for a publicly reachable service.
For multiple issuers, include a trusted issuer identifier alongside the subject;
a subject is scoped to its issuer.

## 2. Replace the header on every forwarded request

In the inner proxy's `upstream_request_filter`, remove any client-supplied value
before setting the identity from the session. Do this for anonymous and public
routes too, so those requests cannot preserve a forged header.

```rust
use huskarl_login::{CookieSession, Session as _};
use huskarl_pingora::login::{HasLoginSession, LoginCtx};
use pingora_http::RequestHeader;

fn set_identity_header(
    request: &mut RequestHeader,
    ctx: &LoginCtx<(), CookieSession>,
) -> pingora_error::Result<()> {
    request.remove_header("X-Authenticated-Subject");
    if let Some(subject) = ctx.login_state().session.as_ref().and_then(|s| s.sub()) {
        request.insert_header("X-Authenticated-Subject", subject)?;
    }
    Ok(())
}
```

Call this helper before returning from the forwarding hook, as demonstrated in
`examples/login_proxy.rs`. `LoginProxy` has already removed its own session
cookies before invoking that hook; unrelated application cookies remain.
Do not reintroduce the proxy's session cookie as an identity mechanism.

## 3. Handle anonymous requests explicitly

A public rule skips session loading; an optional rule can provide a session
when one is present. If no subject is supplied, the upstream should treat the
request as anonymous, or reject it if the endpoint requires identity. Attach a
required rule to the corresponding protected proxy path as well.

## 4. Verify the integration

Check that a forged identity header is removed on an anonymous request and
replaced on an authenticated request. Check that direct upstream access is
restricted in your deployment and that personalized responses cannot enter a
cache shared across users. Cookie-free responses can still contain private user
data. To enable caching within an authenticated user's partition, follow
[Cache responses per authenticated user](crate::_docs::how_to::user_caching).
