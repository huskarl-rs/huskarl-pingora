# Login finalization invariants

These are review and test obligations for `LoginProxy` application-response
finalization. They describe the adapter's intended contract, not a formal proof
of the Rust implementation. The
[finalization reference](crate::_docs::reference::login_finalization) describes
exceptions, mitigations, and the difference between cookie and store-backed
sessions.

## Scope and terms

The unit of these invariants is **one request's prepared login state**, not a
session shared across requests. They assume normal Pingora hook ordering, the
supported local-response API, and middleware that does not overwrite managed
state, strip outgoing session cookies, or turn a rejected response into success.
Callback and configured logout endpoints use separate engine response paths.

- **Pending commit** means the adapter's deferred `PendingPersist::commit`,
  after an earlier eager save failed. It excludes eager persistence and retries
  internal to a session driver.
- **Final header** means a non-informational response or a terminal `101`
  upgrade. Other `1xx` responses are interim.
- **Attached** means the adapter appended cookie headers to the outgoing final
  response. **Received** means the transport client observed them. **Accepted**
  means the browser applied them. These are different events.
- **Finalization started** means the adapter claimed its pending work; it does
  not establish that the work completed. The implementation's `finalized` flag
  is set before awaiting persistence or revocation.

## Finalization

**F1 — At most one deferred attempt.** For one prepared request state, final
response handling and logging together invoke a pending commit at most once.
Repeated final-header callbacks, a subsequent body-write failure, and logging
must not repeat that commit. This is not exactly-once durable storage execution:
a driver can retry internally or commit before returning an error.

**F2 — Interim headers preserve obligations.** Processing a `100` or `103`
header must not invoke finalization's commit or termination, drain queued
cookies, or claim finalization. A later final response, including `101`, remains
eligible to finalize. This applies when Pingora exposes the header to the
adapter; HTTP/2 upstream informational headers currently do not reach this hook.

**F3 — Termination supersedes pending refresh persistence.** When a loaded
session has `terminate_requested` set before finalization, the pending refresh
commit is abandoned and termination is attempted instead. Logging after that
finalization must not save or terminate it again. This does not undo a refresh
that was already persisted eagerly or revoke an already-running request.

**F4 — Finalization preserves request identity.** The adapter does not remove
the authenticated session snapshot when finalizing or cleaning up. Later hooks
can still attribute the request to that identity. The snapshot is not evidence
that the session remains valid after termination or concurrent revocation.

## Cookie handling

**C1 — Successful finalization attaches the owed cookie bundle once.** On a
supported final response, if finalization completes successfully, the adapter
appends its queued cookie headers and any headers returned by persistence or
termination. Repeated finalization of that response does not append them again.
This applies to forwarded, cached, revalidated, and queued local responses.
It does not promise attachment to a replacement error response after finalization
fails, nor attachment after task cancellation.

**C2 — Adapter cookies stay out of Pingora cache admission.** Login cookie
updates are appended after cache processing, to the individual downstream
response. They must not become part of the cached representation through this
adapter. This does not cover cookies supplied by an upstream or middleware, and
it does not establish isolation of personalized response bodies between users.

**C3 — Cookie attachment disables downstream storage.** Whenever the adapter
appends session cookies, it sets `Cache-Control: no-store` on that response.
When it appends none, it leaves the existing cache-control policy unchanged.
Outer middleware must preserve this restriction. It does not retroactively
change Pingora cache admission, which already occurred.

**C4 — Cleanup never pretends to deliver cookies.** If logging runs with
unhandled cookie obligations, it reports and discards cookies that can no longer
be sent. It may attempt pending server-side work, but must not write another
response. A prior successful save or header write must not be interpreted as
proof of browser acceptance.

## Failure handling

**E1 — A rejecting pending-save failure blocks the application response.** If
pending persistence fails and `PersistFailurePolicy` returns a rejection, the
final response filter returns an error before the application response is
committed downstream. In the tested default Pingora integration, the client gets
an error rather than the successful application response or its body. The policy
can explicitly permit continuation; a custom error handler can change the
outcome and must be tested. A fresh cache hit maps the error to 500 in Pingora
0.9; other paths normally use the policy-selected status. See the
[status table](crate::_docs::reference::login_finalization#persistence-failure-status). Exact status,
policy response body, and policy headers are not universal invariants.

**E2 — Revocation failure does not suppress browser clears.** When termination
returns clearing cookies and a revocation error, the adapter appends the clears,
reports the error to the configured diagnostic handler, and does not reject the
response solely because revocation
failed. This permits the current browser to clear its session; it does not
assert successful server-side deletion or revoke copied credentials.

**E3 — Transport failure does not replay finalization.** Once finalization has
claimed a request's work, a later header or body write error does not cause the
logging fallback to repeat it. A client disconnect or stream reset may coexist
with a completed durable save and no cookie delivery. A failed body transfer may
coexist with headers already received by the client.

## Limits on progress guarantees

These safety obligations do not assert that every request eventually finalizes,
that every pending save succeeds, or that every cookie reaches a browser.

- Direct writes and some proxy error paths bypass response finalization.
  Logging cleanup is best effort if the request task reaches it.
- Dropping the request future, aborting its task, or terminating the process can
  prevent async cleanup entirely. An interrupted backend call may have committed;
  cancellation proves neither rollback nor safety of retry.
- Cookie sessions cannot prevent another request's delayed response from
  restoring older browser state. Store-backed refresh and deletion have
  different consequences, detailed in the storage comparison.
- No response-delivery guarantee makes application side effects atomic with a
  session update. Retrying an interrupted operation can duplicate its effects.

Any stronger progress claim needs explicit assumptions about task lifetime,
backend availability, transport delivery, and browser cookie acceptance.

## Regression evidence

The [maintainer evidence table](https://github.com/huskarl-rs/huskarl-pingora/blob/main/docs/contributing/login_lifecycle.md#regression-evidence-and-coverage-gaps)
maps these obligations to tests and known coverage gaps. Applications must test
their own middleware, backend, and cancellation behavior; the adapter fixtures
do not prove browser cookie acceptance or real-backend rollback.
