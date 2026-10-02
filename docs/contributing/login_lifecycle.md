# Testing the login lifecycle

Use the [named invariants](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/reference/login_invariants/) as the
review and test checklist for finalization, cookie handling, and failure behavior.
They distinguish safety obligations from progress assumptions and list current
coverage gaps.

`src/login/proxy/tests/lifecycle.rs` drives Pingora's actual `HttpProxy` request
runner over in-memory HTTP/1 and HTTP/2 downstream connections, with loopback
HTTP/1 and HTTP/2 upstreams and Pingora's in-memory cache. The scenario table
covers upstream responses, early hints, cache hits, revalidation, queued local
responses, and direct writes. Assertions check client-observed headers and bodies,
cached headers, persistence counts, and identity visibility during logging.
HTTP/2 responses are decoded by the `h2` client. Pingora currently consumes
HTTP/2 upstream informational headers without invoking the adapter's response
hook; HTTP/1 upstream informational headers do reach it.

The fixture uses the real `StoreBackedSessionStore` with a controllable
`ExternalSessionStore` backend. Requests carry genuine encrypted pointer cookies.
The harness queues engine-generated cookie clears separately from refresh
persistence: a store-backed refresh does not replace the pointer cookie.

Failure tests use notifications to pause at known boundaries, without sleeps:

- Disconnect before response headers while persistence is pending: the save
  completes once, the write fails, and logging does not repeat persistence.
- Disconnect during a large buffered body: the client has received the cookie
  header, and the body-write failure does not repeat persistence.
- Reset an HTTP/2 stream during persistence: the request task completes its save
  and error cleanup even though the client cannot receive the response.
- Abort the request task before finalization or during a save: no response is
  delivered and async logging cleanup does not run. The test backend save does not
  complete; a real backend may already have committed, so cancellation does not
  establish rollback or safe retry.

These tests distinguish request-task cancellation from a client disconnect.
Cookie receipt here means transport delivery, not browser acceptance. Extend
the inner proxy implementations and scenarios when adding middleware or
upgrading Pingora.

Run `cargo test --lib login::proxy::tests::lifecycle` (loopback access is required).
Unit tests additionally cover termination, interim headers, upgrades, and
repeated finalization.


## Regression evidence and coverage gaps

Test names below are in `src/login/proxy/tests.rs` or its `lifecycle.rs` child.
The lifecycle harness drives Pingora's real request runner; adapter unit tests
exercise individual hooks. A passing scenario supports the stated obligation
under its fixture assumptions, not every possible execution.

| Invariant | Existing evidence | Remaining boundary or gap |
|---|---|---|
| F1 | `logging_after_response_filter_does_not_double_persist`; `interim_headers_preserve_work_until_final_or_upgrade_response`; lifecycle save counts | Driver-internal retries and real backend commit ambiguity are outside the test backend's count. |
| F2 | `interim_headers_preserve_work_until_final_or_upgrade_response`; HTTP/1 early-hints and HTTP/2 upstream scenarios | `101` is tested at hook level, not a full upgraded connection. |
| F3 | `response_filter_termination_path`; `logging_fallback_revokes_when_termination_requested` | These termination tests do not also inject a pending refresh. Simultaneous pending-plus-termination and repeated termination need dedicated regression coverage. |
| F4 | Lifecycle `logging` assertions; interim/final header unit test | Identity retained after termination is not separately asserted end to end. |
| C1 | `real_pingora_response_paths_deliver_cookies_once`; `http2_response_paths_finalize_and_keep_cookies_out_of_cache`; `http2_upstreams_finalize_for_both_downstream_protocols` | Uses engine-generated clearing headers; browser chunk parsing and acceptance are not exercised. |
| C2 | Lifecycle cache-admission and stored-header assertions | Application-supplied cookies and user isolation require application tests. |
| C3 | `response_filter_forces_no_store_when_session_cookie_appended`; `response_filter_preserves_cache_control_without_session_cookie` | Outer filters and downstream caches are deployment responsibilities. |
| C4 | `direct_writes_demonstrate_the_documented_boundary`; `upstream_failure_uses_cleanup_without_claiming_cookie_delivery` | These verify no cookie delivery and store attempts, not the optional diagnostic notification. |
| E1 | `real_pingora_persist_failures_never_serve_success`; `http2_persist_failures_never_deliver_success_or_cookies`; HTTP/2 upstream failure matrix | Custom permissive policies and custom error handlers need their own scenarios. |
| E2 | `response_filter_termination_delivers_clears_when_revocation_fails` | Hook-level test; no real external-store outage or browser involved. |
| E3 | `disconnect_before_headers_does_not_repeat_completed_persistence`; `disconnect_during_body_preserves_the_already_delivered_cookie`; `http2_stream_reset_during_save_completes_once_and_runs_cleanup` | These do not establish that a browser accepted a cookie. |
| Cancellation limit | `aborting_the_request_task_does_not_run_async_cleanup` | The blocked test backend save does not commit; real backend durability after cancellation remains uncertain. |

When changing finalization, name the affected invariant in review and add a
counterexample sequence to the appropriate test. Keep stronger desired properties
labelled as unverified until their assumptions and regression coverage are clear.
