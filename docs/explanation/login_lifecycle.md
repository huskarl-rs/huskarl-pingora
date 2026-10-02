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

A local application response still needs to deliver session updates. Queuing it
through `LoginState::respond` lets the enclosing proxy run downstream response
filtering and finalization before writing. Writing directly to the session skips
that coordination. Follow [Return a local response](crate::_docs::how_to::local_responses)
for the supported integration.

## Persistence failures

A pending-save failure follows the configured `PersistFailurePolicy`. A rejecting
policy produces a filter error: its replacement body and headers are not used.
Pingora 0.9 returns 500 for response-filter errors on fresh cache hits, while its
usual error handler honors the status selected by the policy. The default
policy distinguishes missing sessions, conflicts, internal failures, and temporary
unavailability; see the [status reference](crate::_docs::reference::login_finalization#persistence-failure-status).
Both paths block the successful response. Custom inner error handlers can change
that behavior and should be included in integration tests.

## Contract and evidence

The [finalization reference](crate::_docs::reference::login_finalization) states
supported behavior and exceptions. The [named invariants](crate::_docs::reference::login_invariants)
collect the obligations for custom integrations. Maintainers can use the
[lifecycle test guide](https://github.com/huskarl-rs/huskarl-pingora/blob/main/docs/contributing/login_lifecycle.md)
when changing hooks or upgrading Pingora.

`public` rules skip session loading; `optional` rules load a session without
requiring one; `required` rules gate unauthenticated requests. Browser navigation
can start login, while API/XHR requests receive a challenge. Temporary refresh
failure after access-token expiry produces a retryable response rather than
silently treating the user as anonymous.

For the full engine model, read
[Token refresh](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/explanation/refresh/).
For the upstream process boundary, follow
[Forward session identity](crate::_docs::how_to::identity).

Before rollout, follow [Deploy a proxy](crate::_docs::how_to::deployment) for
refresh concurrency, cookie delivery, and logout limits.
