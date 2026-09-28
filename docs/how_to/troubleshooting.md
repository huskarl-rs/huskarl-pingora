# Troubleshoot a proxy

Follow status codes and redirects in the browser or HTTP client, and correlate
them with proxy and upstream logs. Record cookie attributes and header names
without sharing cookie values, authorization codes, or tokens.

| Symptom | First checks |
|---|---|
| Opening `/` does not start login | The tutorial makes `/` optional; open `/dashboard`, which requires a session |
| The provider rejects the callback | Register the exact public redirect URI, including scheme, host, port, and path |
| Callback completes but proxying fails | Check that the upstream is running and that `UPSTREAM`, TLS, and hostname settings match it |
| Logout returns 405 | Submit a POST form; an address-bar visit sends GET |
| Logout returns 403 | Preserve the same-origin `Origin` header and match the configured public origin |
| Session disappears after restart | Reuse the same cookie key; retain old keys during a rotation |
| An authenticated upstream lacks identity | Session context is local to the proxy; explicitly forward a trusted identity assertion |
| A path returns 400 before authentication | Inspect path-guard parsing assumptions, structural forms, and analysis budget |
| A method returns 403 despite a public default | A method-specific route denies unlisted methods without an explicit all-method fallback |
| API client gets 401 instead of a login page | Browser login distinguishes navigations from API requests; bearer-token protection challenges unauthenticated requests |

For refresh-related sign-outs, uncleared browser state, truncated responses,
or 500 responses on cache hits, use the
[login finalization reference](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/reference/login_finalization/).
It maps each exception to coding mitigations and service-user impact, including
why retrying an interrupted application request may duplicate an operation.

## Trace routing and rewrites

Compare the original request path with the path your inner proxy forwards.
Use `curl --path-as-is` when testing dot segments; otherwise the client may
normalize the path before the proxy sees it. Check exact routes versus subtrees,
case sensitivity, and every downstream decode pass. Do not disable the guard
to compensate for an unexplained mismatch. See
[Configure the path guard](crate::_docs::how_to::path_guard) and
[Path confusion](crate::_docs::explanation::path_confusion).

## Trace session-cookie delivery

For login integrations, inspect callback and downstream response headers. The
browser must receive all session-cookie updates and clears. An inner proxy that
writes directly can bypass `response_filter`; use `LoginState::respond` and return
`Ok(false)` for buffered local responses. Logging cannot send cookies after the
response is gone. Cookie-session refreshes depend on delivery even
when the engine already prepared a successful save.

For cookie sessions, missing a refreshed cookie can leave the browser with an
old refresh token and lead to re-login. For store-backed sessions, first check
whether the refresh committed to the backend and whether the existing pointer
is still valid; a successful refresh does not require a replacement pointer
cookie. After logout, successful record deletion invalidates that pointer even
if cookie clears were lost. Neither mode can recover an initial login cookie
that never reached the browser. Use the
[storage comparison](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/reference/login_finalization/#how-session-storage-changes-the-impact)
to distinguish delivery failures from persistence failures.

For provider refresh failures, cookie rejection, and lifetime checks, use the
shared [browser login troubleshooting guide](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/troubleshooting/).
