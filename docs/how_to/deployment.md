# Deploy a Pingora proxy

Use this after the browser-login tutorial, before exposing the proxy beyond
localhost. The upstream trust and routing steps also apply to bearer-token proxies.

## Configure the shared login engine first

For browser sessions, use the `huskarl-login` guides for decisions shared across
adapters:

| Task | Shared guide |
|---|---|
| Choose cookie or server-side sessions, persist keys, configure replicas | [Deployment](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/how_to/deployment/) |
| Implement a session database | [External session stores](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/how_to/external_store/) |
| Rotate encryption keys and understand cookie paths/chunks | [Cookie security](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/explanation/cookie_security/) |
| Test provider refresh-token reuse and concurrent exchanges | [Refresh-token rotation](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/how_to/rotation/) |
| Set absolute and idle session limits | [Session lifetime](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/explanation/session_lifetime/) |

Store-backed sessions can survive lost refresh-cookie delivery after a durable
commit and support revocation when deletion succeeds. Cookie sessions depend on
browser updates. Neither storage mode coordinates simultaneous provider refresh
exchanges. The [Pingora finalization reference](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/reference/login_finalization/)
explains how storage choice changes the impact of adapter response failures.

For bearer-token proxies, configure trusted resource audiences and public URL
mappings, then apply the routing, upstream trust, and response checks below.
Session-key and logout configuration applies only to browser login.

## Configure Pingora

1. **Set the public origin.** Register the public HTTPS callback with the provider
   and set `REDIRECT_URI` to it. This controls secure cookies; it does not enable
   TLS on the example's plain HTTP listener. Terminate TLS at Pingora or a trusted
   load balancer, protect the internal connection, and prevent bypassing the TLS
   entry point. `UPSTREAM_TLS` controls the separate connection to the upstream.
2. **Keep sessions readable.** Load a stable `COOKIE_KEY` from managed secret
   storage and share compatible keys and session configuration across replicas.
   The example accepts one key; rolling rotation requires an integration with
   a key ring. Follow the shared guide for the rotation sequence.
3. **Configure routes and logout.** Preserve the browser's `Origin` for POST
   logout and redirect to a public signed-out page. Match
   [route policies](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/routes/) and
   [path-guard assumptions](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/path_guard/)
   to the full rewrite and parsing pipeline.
4. **Restrict upstream access.** Accept identity assertions only on trusted proxy
   connections. Use network controls or authenticated transport. Remove incoming
   identity headers on every forwarded request, including public routes, before
   setting identity from authenticated context. `LoginProxy` strips its session
   cookies; your inner proxy owns identity-header forwarding. Follow
   [Forward session identity](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/identity/).
5. **Preserve response headers.** Keep every `Set-Cookie` header through response
   filters and load balancers. Exclude personalized responses from shared caches
   even when cookies do not change. The example upstream uses
   `Cache-Control: no-store`. If you need personalized caching inside Pingora,
   follow [Cache responses per authenticated user](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/user_caching/)
   for identity keys, authorization before lookup, and downstream cache policy.
   See also the shared
   [caching guide](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/how_to/caching/).

## Account for Pingora's response lifecycle

`LoginProxy` queues session-cookie changes during request handling and delivers
them through the final downstream response phase, after Pingora caching.

| Request outcome | Cookie-delivery consequence |
|---|---|
| Upstream or cached response reaches `response_filter` | Cookies are attached after cache processing, before headers go to the browser |
| Inner proxy queues a response with `LoginState::respond` and returns `Ok(false)` | The proxy finalizes and writes the local response |
| Inner proxy writes directly, or a proxy error bypasses response filters | Cookie delivery can be bypassed |
| Only the logging fallback runs | Server-side persistence can be retried, but cookies cannot be sent after the response is gone |

Callback and logout responses are handled directly by the login engine; the
boundary above concerns application requests continuing through the inner proxy.
A successful refresh exchange alone does not prove delivery to the browser.
See the [login lifecycle](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/explanation/login_lifecycle/)
and the shared guide's [delivery and response-ordering limits](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/how_to/deployment/#limits-configuration-cannot-remove).

For each exception, its coding mitigation, and its effect on service users,
consult the [login finalization reference](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/reference/login_finalization/).
Plan graceful request draining; aborting a request task does not run async
logging cleanup. Test the error and cancellation policies used in your deployment,
not just successful upstream responses.

## Verify the integration

Run the shared guide's [rollout checks](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/how_to/deployment/#verify-before-rollout)
for restart persistence, replicas, concurrent refresh, and logout. Then check
these Pingora-specific paths:

- Early inner-proxy responses and upstream failures during refresh; confirm
  updated cookies return on the next browser request when delivery succeeds.
- Forged identity headers, direct upstream access, and alternative spellings
  of protected paths through the full rewrite pipeline.
- Authenticated upstream requests contain the intended identity and no proxy
  session cookies.

For failures, use [Troubleshoot a proxy](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/_docs/how_to/troubleshooting/).
