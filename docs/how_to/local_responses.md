# Return a local response with session updates

Use this inside a `LoginProxy` when an application handler can answer without an
upstream. Queue a buffered response so the enclosing proxy can attach refreshed
or clearing cookies before sending it.

## 1. Queue the response in the inner request filter

```rust
use huskarl_pingora::login::{HasLoginSession, LoginResponse};
# use huskarl_pingora::login::{LoginCtx, CookieSession};
# fn handler(ctx: &mut LoginCtx<(), CookieSession>) -> pingora_error::Result<bool> {
ctx.login_state_mut().respond(LoginResponse::Rendered {
    status: http::StatusCode::OK,
    headers: vec![],
    body: "Hello".into(),
})?;
Ok(false)
# }
```

## 2. Return without writing to the session

Return `Ok(false)` from the inner `request_filter` after queuing the response.
The enclosing `LoginProxy` runs the inner downstream response filter, finalizes
session work, and writes the response without contacting an upstream. Do not
also call `Session::write_response_header` or `respond_error`.

To terminate the loaded session with this response, set
`ctx.login_state_mut().terminate_requested = true` before queuing it. This is
useful for an application-managed account-deletion handler. The configured
engine logout endpoint remains the usual choice for sign-out.

## 3. Check response and cookie behavior

Verify that the client receives your status and body and any owed `Set-Cookie`
headers. Verify that no upstream request occurs. A HEAD request receives the
representation headers without body bytes; 204 and 304 also send no body.
Informational responses are rejected by `respond` because this API sends a
complete final response. The entire body is buffered; use normal proxying for
streaming upstream responses.

Session persistence can fail before delivery. The configured persistence policy
can block the response, and a transport failure can prevent cookie receipt.
See the [finalization reference](crate::_docs::reference::login_finalization)
for failure behavior and the [lifecycle explanation](crate::_docs::explanation::login_lifecycle)
for why direct writes bypass cookie delivery.
