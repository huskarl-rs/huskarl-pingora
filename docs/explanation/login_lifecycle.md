# Login state through the Pingora lifecycle

[`LoginProxy`](crate::login::LoginProxy) adapts the shared login engine to
Pingora's request and response phases. The distinction between persisting
server state and delivering browser cookies matters when a proxy returns early.

| Phase | Responsibility |
|---|---|
| `request_filter` | Handle callback/logout, resolve route policy, load a session when needed, and gate protected requests |
| Inner proxy | Read the session from context and select or contact the upstream |
| `upstream_request_filter` | Strip session credentials, then let the inner proxy add trusted identity or other forwarding headers |
| `upstream_response_filter` | Deliver queued cookies and commit pending persistence or termination before headers go to the browser |
| `logging` | Attempt outstanding work when there was no upstream response; report cookies that can no longer be delivered |

Refresh persistence starts eagerly inside `LoginEngine::load_session`. For an
external store this can commit durable state before the upstream responds.
For cookie sessions, it only prepares `Set-Cookie` headers: the write finishes
when the browser receives them. Even a successful eager refresh can therefore
lose its browser update if the response bypasses the cookie-delivery phase.

A failed eager save produces `ActivePending`; its later commit is a retry.
If the response is already sent, the logging fallback can retry a server-side
write, but cannot deliver replacement cookies or change the response status.
An inner proxy that answers directly in `request_filter` must account for this
boundary. The tutorial forwards application requests to a real upstream so
they take the normal response-filter path.

`public` rules skip session loading; `optional` rules load a session without
requiring one; `required` rules gate unauthenticated requests. Browser navigation
can start login, while API/XHR requests receive a challenge. Temporary refresh
failure after access-token expiry produces a retryable response rather than
silently treating the user as anonymous.

For the full engine model, read
[Token refresh](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/explanation/refresh/).
For the upstream process boundary, follow
[Forward session identity](crate::_docs::how_to::identity).
