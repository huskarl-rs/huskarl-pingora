# Login response finalization

This is the response contract for [`LoginProxy`](crate::login::LoginProxy),
including exceptions observed by the Pingora 0.9 lifecycle tests. See
[Login state through the Pingora lifecycle](crate::_docs::explanation::login_lifecycle)
for the sequence of operations and a local-response example. The
[named finalization invariants](crate::_docs::reference::login_invariants) state
the review obligations and map them to regression tests and coverage gaps.

## Supported behavior

For application requests that reach the final downstream `response_filter`,
`LoginProxy` completes pending session persistence or termination once and
appends queued cookies after Pingora cache processing. This includes upstream
responses, fresh cache hits, and revalidated responses. Interim `100` and `103`
headers do not consume pending work; a `101` upgrade does finalize it.

Buffered responses queued with [`LoginState::respond`](crate::login::LoginState::respond)
and followed by `Ok(false)` from the inner `request_filter` use the same
finalization path. Callback and configured logout endpoints are handled directly
by the login engine and have their own response delivery.

“Finalized” means the adapter processed the pending work and response headers.
It does not mean the client received the headers or that a browser accepted the
cookies. A successful store write, a successful header write, browser receipt,
and browser cookie acceptance are distinct events.

## How session storage changes the impact

**Store-backed sessions reduce the impact of missed refresh cookies and lost
logout responses. They do not guarantee response delivery.** The built-in store
keeps refreshed credentials in a server-side record and leaves the browser's
session pointer unchanged during refresh. Cookie sessions keep the refreshed
credentials in the browser, so preparing a cookie is not enough: the browser
must receive and accept the replacement.

Disconnection is an unavoidable delivery boundary for either mode. Skipping
finalization through a direct response write is an avoidable integration issue.
Changing storage can reduce its consequences, but does not fix the bypass.

| Situation | Cookie-backed sessions | Store-backed sessions | What can be avoided or mitigated? |
|---|---|---|---|
| Refresh succeeds but its response never reaches the browser | The browser retains the old session. With refresh-token rotation, the next refresh may fail and require login. | Once the refresh is durably committed, the existing valid pointer can load the updated record; refresh needs no replacement pointer cookie. | Store-backed sessions avoid dependence on browser delivery for an already-committed refresh. They do not help if persistence has not succeeded or the pointer has expired or become unreadable. |
| Logout clearing cookies are not delivered | The browser retains a usable session until expiry or another invalidation condition; local logout cannot revoke a copied cookie. | Successful deletion makes the old pointer unusable for subsequent session loads, even if the browser retains it. | Store-backed sessions provide server-side revocation when deletion succeeds. This does not cancel requests that already loaded the session or end provider SSO. |
| An older response arrives after a newer refresh or logout | Old cookies can overwrite a newer session or restore browser state after logout. | Refresh does not replace the pointer; guarded store updates reject stale refresh writes, and a deleted record is not recreated by them. | Store-backed sessions mitigate these stored-state and response-ordering failures, assuming the backend honors the store contract. They do not coordinate exchanges at the provider. |
| A direct response write or proxy error bypasses finalization | Logging cannot deliver a replacement or clearing cookie after the response. Users can unexpectedly need login or retain browser session state. | Eager persistence may already have succeeded; logging can attempt an owed save or deletion if it runs. Cookie clears still cannot be delivered afterward. | Use the supported local-response API and test custom error paths in both modes. Store-backed sessions make successful server-side cleanup useful even without cookie delivery. |
| The request task is aborted during pending work | Pending persistence or cookie delivery can be lost. | An already-committed record remains useful, but an interrupted write or deletion has an uncertain outcome and async cleanup does not run. | Graceful draining and scoped operation timeouts help both modes. Neither mode guarantees completion after task cancellation; cancellation does not prove rollback. |
| A new login response is lost | The browser never receives its new session cookie. | The browser never receives its new pointer cookie, even if the record was created. | Both modes require browser delivery to establish a new session. Users may need to start login again. |
| Persistence infrastructure fails | No external session database is required, though sealing or serialization can fail. | Loads, saves, and revocation depend on the backend; failures can interrupt requests or prevent revocation. | Store-backed resilience to delivery loss comes with a backend availability requirement. Choose and operate the backend accordingly. |

Body-transfer failures, Pingora's 500-versus-503 error mapping, personalized
content caching, and informational-header forwarding affect both modes. Storage
choice does not make an interrupted application operation safe to repeat. The
exception table below gives the proxy-code mitigations and remaining user impact.

## Exceptions, mitigations, and service-user impact

| Exception | How to write or configure the proxy | Effect on service users |
|---|---|---|
| An inner handler writes directly with `Session::write_response_header` or `respond_error` | For buffered local responses, queue `LoginState::respond` and return `Ok(false)` without writing. Forward streaming responses through the normal proxy path; the queue API buffers the whole body. | The application response may succeed without delivering refresh or clearing cookies. Cookie-session users may retain stale credentials and need to sign in again; a requested local termination may leave browser state uncleared. |
| An upstream failure or another proxy-generated error bypasses response filtering | Where an inner handler can decide the response before writing, queue a controlled error response. Test custom `fail_to_proxy` implementations: they can write directly and do not automatically finalize login state. Keep the logging fallback for best-effort store cleanup. | Users receive an error, potentially without a needed session-cookie update. A later request can require login even if a refresh exchange succeeded. Logging cannot repair the already-sent response. |
| A client disconnects before receiving final headers, or resets an HTTP/2 stream | Allow the request task to complete cleanup where possible. Distinguish transport errors from task cancellation in monitoring. Store-backed sessions reduce dependence on replacement cookies for refresh once the durable write succeeds. | A save may complete without the client receiving cookies. Cookie-session users can lose the refreshed session; store-backed users may continue with their existing pointer cookie. Neither delivery nor recovery is guaranteed. |
| A client disconnects during the response body | Do not repeat session persistence merely because body delivery failed. Treat the application operation and session update as separate outcomes. | The client may already have received the new session cookie while seeing a truncated or failed application response. The application operation may have completed; retrying it can duplicate effects unless it is safe to retry. |
| The request future is dropped by task abortion, an enclosing timeout, or forced shutdown | Prefer graceful draining. Scope timeouts around fallible inner operations and handle them before writing, rather than dropping the entire request future when finalization is required. A hard shutdown deadline still leaves this exception possible. | Async logging cleanup does not run. Pending work and cookies can be lost; a backend write may have committed before cancellation. Users can see an interrupted response or need to sign in again. Cancellation does not establish rollback or make a retry safe. |
| A rejecting persistence policy fails a fresh cache-hit response | Account for Pingora 0.9's 500 mapping in monitoring and clients. Other tested paths use the configured status, normally 503. Do not rely on `fail_to_proxy` alone to normalize the fresh-hit path; test any custom error integration through the real request runner. | Users receive 500 instead of the usual 503, but the successful application response is blocked in the tested default integration. Replacement policy headers and bodies are not delivered, so clients must not depend on a policy-provided error page or retry header. |
| Server-side revocation fails during response finalization | Preserve the clearing cookies and monitor the revocation error. Use store-backed sessions when server-side revocation is needed, while accounting for backend availability. Do not treat browser clearing as proof of deletion. | The current browser can appear signed out if it accepts the clears, while a copied store-pointer cookie may remain usable until the record is revoked or expires. |
| Personalized content is admitted to a shared cache | Disable shared caching for personalized content or implement an appropriate isolation policy before cache admission. Preserve downstream `no-store` when session cookies are attached. | Session cookies stay outside Pingora's cached representation, but that alone does not prevent one user's application content being served to another. Cache admission precedes downstream persistence finalization. |
| An HTTP/2 upstream sends informational headers | Do not rely on those headers reaching the inner response hook in Pingora 0.9. Exercise informational-response behavior when upgrading Pingora. HTTP/1 upstream informational headers do reach the hook. | Early resource-loading hints may be absent. Final response and session-cookie processing still occur; the tested case does not cause session loss. |

The loaded `session` remains readable by later hooks, including logging, even
after finalization or termination. It records the identity authenticated for
this request; its presence is not a fresh check that the session remains valid.
Set `terminate_requested` before finalization, not in logging after a response
has already been finalized.

For an application that deliberately caches personalized content, follow
[Cache responses per authenticated user](crate::_docs::how_to::user_caching).
Cookie isolation and user-specific response-body isolation are separate contracts.

## Session-storage limits still apply

Correct response finalization does not order different requests' responses.
Cookie-session responses can arrive out of order, restore an older token, or
restore browser state after logout. Store-backed sessions support server-side
revocation when deletion succeeds, but neither storage choice by itself
serializes refresh exchanges or ends provider SSO. Follow the shared
[deployment guide](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/deployment/)
for these limits and storage choices.

## Evidence and scope

The [lifecycle tests](https://github.com/huskarl-rs/huskarl-pingora/blob/main/src/login/proxy/tests/lifecycle.rs)
run Pingora's actual request runner with HTTP/1 and HTTP/2 clients and upstreams,
cache hits and revalidation, local responses, injected persistence failures,
disconnects, stream resets, and task cancellation. They check client-observed
headers and bodies, cached headers, persistence counts, and logging. The
adjacent adapter tests cover termination and revocation failure.

These are bounded test scenarios with a mock session driver, not guarantees for
every middleware combination, external store, browser, or load balancer. Add
custom error handlers, response filters, caches, and cancellation policies to
the integration tests used for your deployment. In particular, preserve every
`Set-Cookie` header through outer filters and load balancers. A successful write
in a test does not establish browser acceptance or transactional rollback at a
real backend.
