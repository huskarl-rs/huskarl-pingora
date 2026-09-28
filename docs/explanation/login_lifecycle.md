# Login state through the Pingora lifecycle

[`LoginProxy`](crate::login::LoginProxy) adapts the shared login engine to
Pingora's request and response phases. The distinction between persisting
server state and delivering browser cookies matters when a proxy returns early.
For the supported contract, exceptions, coding mitigations, and service-user
impact, see [Login response finalization](crate::_docs::reference::login_finalization).

| Phase | Responsibility |
|---|---|
| `request_filter` | Handle callback/logout, resolve route policy, load a session when needed, and gate protected requests |
| Inner proxy | Read the session from context and select or contact the upstream |
| `upstream_request_filter` | Strip session credentials, then let the inner proxy add trusted identity or other forwarding headers |
| `response_filter` | Finalize once on the final downstream response, after caching; deliver cookies and complete pending persistence or termination |
| `logging` | Attempt outstanding work when downstream finalization was bypassed; report cookies that can no longer be delivered |

Refresh persistence starts eagerly inside `LoginEngine::load_session`. For an
external store this can commit durable state before the upstream responds.
For cookie sessions, it only prepares `Set-Cookie` headers: the write finishes
when the browser receives them. Even a successful eager refresh can therefore
lose its browser update if the response bypasses the cookie-delivery phase.

The built-in store-backed driver does not replace the pointer cookie during
refresh: after a durable commit, an existing valid pointer can load the updated
record even if the response is lost. Cookie sessions need replacement-cookie
delivery for that update. Neither mode can guarantee delivery across a disconnect,
and both require a cookie to reach the browser when establishing a new session.
See [the storage comparison](crate::_docs::reference::login_finalization#how-session-storage-changes-the-impact)
for logout, delayed responses, cancellation, and backend-failure tradeoffs.

A failed eager save produces `ActivePending`; its later commit is a retry.
If the response is already sent, the logging fallback can retry a server-side
write, but cannot deliver replacement cookies or change the response status.
Finalization covers upstream responses, fresh cache hits, and revalidated cache
responses. It skips informational responses such as `100` and `103`; a `101`
upgrade is terminal and does finalize. The authenticated session remains
available to later hooks, including logging. Session cookies are added after
Pingora's cache processing and never become part of its cached representation.
Personalized application content still requires a suitable cache policy.

## Local responses

An inner proxy can queue a buffered response instead of writing directly:

```rust
# use huskarl_pingora::login::{HasLoginSession, LoginResponse, LoginCtx, CookieSession};
# fn handler(ctx: &mut LoginCtx<(), CookieSession>) -> pingora_error::Result<bool> {
ctx.login_state_mut().respond(LoginResponse::Rendered {
    status: http::StatusCode::OK,
    headers: vec![],
    body: "Hello".into(),
})?;
Ok(false)
# }
```

Return `Ok(false)` from `request_filter` after queuing the response. The enclosing
`LoginProxy` invokes the inner downstream response filter, finalizes session
work, and writes the buffered response without contacting an upstream. Set
`terminate_requested` before queuing it to terminate a session with the response.
Informational responses are rejected by this API. `HEAD`, `204`, and `304`
responses send no body.

Direct calls to `Session::write_response_header` or `respond_error` bypass the
proxy response hooks. Queuing a response and also writing directly is unsupported.
Proxy-generated error responses can bypass the hooks too. Logging performs
best-effort cleanup on these paths and reports undelivered cookies; it cannot
repair a response already sent or guarantee delivery after a connection fails.

## Persistence failures

A pending-save failure follows the configured `PersistFailurePolicy`. A rejecting
policy produces a filter error: its replacement body and headers are not used.
Pingora 0.9 returns 500 for response-filter errors on fresh cache hits, while its
usual error handler honors the supplied status (503 for the default policy).
Both paths block the successful response. Custom inner error handlers can change
that behavior and should be included in integration tests.

## Testing the contract

`src/login/proxy/tests/lifecycle.rs` drives Pingora's actual `HttpProxy` request
runner over in-memory HTTP/1 and HTTP/2 downstream connections, with loopback
HTTP/1 and HTTP/2 upstreams and Pingora's in-memory cache. The scenario table
covers upstream responses, early hints, cache hits, revalidation, queued local
responses, and direct writes. Assertions check client-observed headers and bodies,
cached headers, persistence counts, and identity visibility during logging.
HTTP/2 responses are decoded by the `h2` client. Pingora currently consumes
HTTP/2 upstream informational headers without invoking the adapter's response
hook; HTTP/1 upstream informational headers do reach it.

Failure tests use notifications to pause at known boundaries, without sleeps:

- Disconnect before response headers while persistence is pending: the save
  completes once, the write fails, and logging does not repeat persistence.
- Disconnect during a large buffered body: the client has received the cookie
  header, and the body-write failure does not repeat persistence.
- Reset an HTTP/2 stream during persistence: the request task completes its save
  and error cleanup even though the client cannot receive the response.
- Abort the request task before finalization or during a save: no response is
  delivered and async logging cleanup does not run. The mock save does not
  complete; a real backend may already have committed, so cancellation does not
  establish rollback or safe retry.

These tests distinguish request-task cancellation from a client disconnect.
Cookie receipt here means transport delivery, not browser acceptance. Extend
the inner proxy implementations and scenarios when adding middleware or
upgrading Pingora.

Run `cargo test --lib login::proxy::tests::lifecycle` (loopback access is required).
Unit tests additionally cover termination, interim headers, upgrades, and
repeated finalization.

`public` rules skip session loading; `optional` rules load a session without
requiring one; `required` rules gate unauthenticated requests. Browser navigation
can start login, while API/XHR requests receive a challenge. Temporary refresh
failure after access-token expiry produces a retryable response rather than
silently treating the user as anonymous.

For the full engine model, read
[Token refresh](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/explanation/refresh/).
For the upstream process boundary, follow
[Forward session identity](crate::_docs::how_to::identity).

Before rollout, follow [Deploy a proxy](crate::_docs::how_to::deployment) for
refresh concurrency, cookie delivery, and logout limits.
