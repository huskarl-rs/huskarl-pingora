# Telemetry contracts

Enable `huskarl-pingora/metrics` to emit the counters below through the `metrics`
facade. It is off by default and independent of `resource` and `login`. Install
an application-selected recorder/exporter; this crate installs none. Without
this feature, local recorder calls and label allocations compile out. Naming
and diagnostic APIs remain available in either build.

```toml
[dependencies]
huskarl-pingora = { version = "0.6", features = ["metrics"] }
```

For bearer-only applications, use `default-features = false` with `resource`,
`metrics`, and the verifier feature appropriate to your application.

## Names and ownership

Set `ResourcePolicy::builder().metrics_name("inventory")`,
`LoginProxy::builder().metrics_name("browser")`, or
`ResourceAssembly::new(mapping).metrics_name("edge")`. Every local series has a
`name` label; unnamed instances emit `name=""`. Names must be stable deployment
configuration, never request paths, hosts, claims, session identifiers, or
values from discovery. Budget distinct names over the monitoring retention
period as well as within one process.

`AuthProxy` uses its guard's name for authorization metrics. An assembly's name
applies only to route selection; it does not rename its branches. A pre-built
shared `LoginEngine` retains its own name. None of these APIs automatically
wraps a supplied validator, HTTP client, or cryptographic implementation in a
metrics decorator. Applications own instrumentation of supplied dependencies.

The adapter's `metrics` feature forwards to `huskarl?/metrics`,
`huskarl-core?/metrics`, and `huskarl-login?/metrics`, without enabling unused
authentication modes. Enabling `login` and `metrics` also enables the shared
engine counters.

The engine has its own diagnostic handler: `LoginProxy::diagnostics` configures
only adapter diagnostics. See the shared
[telemetry reference](https://docs.rs/huskarl-login/0.5.0/huskarl_login/metrics/)
for engine setup, counters, and observation boundaries.

The resource-server dependency has no metrics feature forwarded here. Supplied
validators and their HTTP or cryptographic dependencies keep their own
instrumentation contracts. Adapter counters do not instrument that whole graph.

## Counter catalog

All metrics are counters. No duration histograms, gauges, automatic tracing,
or end-to-end response-success metrics are emitted by this adapter. Labels
other than `name` are fixed values compiled into the library.

| Metric | Additional labels | Observation and population |
| --- | --- | --- |
| `huskarl.resource.check` | `outcome` | One completed guard evaluation, including standalone checks and checks inside `AuthProxy` |
| `huskarl.pingora.resource.authorization` | `outcome` | One `AuthProxy` decision, including resource-binding/URI rejection before guard invocation |
| `huskarl.pingora.resource.route` | `outcome` | One assembly selector invocation, including metadata and fallback selection and pre-branch rejection |
| `huskarl.pingora.login.check` | `outcome` | One login adapter routing/authentication decision, before forwarding or writing its response |
| `huskarl.pingora.login.session_operation` | `operation`, `phase`, `outcome` | One returned result from a session operation invoked by the adapter |
| `huskarl.pingora.login.finalization` | `outcome` | First entry into final response preparation or logging fallback per login context, not completion of persistence or delivery |
| `huskarl.pingora.login.stranded_cookies` | none | Number of prepared `Set-Cookie` headers discarded in logging fallback; counts headers, not requests or sessions |

### Resource outcomes

`huskarl.resource.check` retains its existing name and denominator. Its outcomes
are `forward`, `path_confusion`, `policy_denied`, `unauthenticated`,
`invalid_token`, `expired`, `unrecognized_issuer`, `binding_error`,
`nonce_required`, `insufficient_scope`, `invalid_request`, and `server_error`.
These reflect the guard's domain classification, not a classification inferred
from an HTTP status. Unknown validator error classifications retain the legacy
`invalid_token` fallback.

`huskarl.pingora.resource.authorization` uses the same outcomes and adds
`outside_resource`. A bound proxy that cannot reconstruct the public URI emits
`invalid_request`; a request outside the bound path emits `outside_resource`.
Neither invokes the guard or increments `huskarl.resource.check`.

`huskarl.pingora.resource.route` uses `selected`, `path_confusion`,
`policy_denied`, and `server_error`. `selected` includes metadata and fallback
branches. Metadata publication itself does not emit authorization or guard
metrics. A rejected selection never reaches the branch's auth proxy.

The assembly owns routing, the auth proxy owns its final authorization gate,
and the guard owns policy evaluation. These populations intentionally differ:
do not add their counts to obtain a total request count. A request selected for
an auth branch normally increments all three metrics once. Separately composed
or nested auth proxies each own their evaluation; their counts are evaluations,
not globally deduplicated requests. Give independently meaningful instances
distinct names.

One owner applies to each logical observation, not to the whole request: a
proxy and its wrapper must not both report the same proxy decision, while two
distinct policy gates may each report their own decision. These counters alone
do not provide an overall rejection rate for all requests entering an assembly.
That would require a separate assembly-owned counter and a decision-reporting
contract with its branches, including explicit treatment of metadata, fallback,
and branches without authentication. No such aggregate counter is emitted.

`forward` permits the inner proxy to continue. It does not prove upstream
contact, application authorization, a cache hit, or successful response delivery.
Checks in an inner application are outside this metric's authorization boundary.

Axum's `huskarl.axum.resource.middleware_completion` has a different population:
it counts only middleware calls that return a response and shares one observation
across nested validators. A later service error or cancellation can exclude an
Axum sample after authorization passed; it does not erase a Pingora decision.
Do not combine these counters into a cross-framework authorization rate.

### Login outcomes

`huskarl.pingora.login.check` uses:

- `preflight`: session-free CORS pass-through after the path guard;
- `public`: a route that bypasses session loading;
- `anonymous`: optional authentication with no usable session;
- `authenticated`: a session passed the login rule and its custom check;
- `unauthenticated`: a required session was absent, before login redirect/challenge;
- `forbidden`: the route's session check denied access;
- `login_route`: the engine handled its callback/logout route, regardless of the
  response status; engine-owned flow outcomes remain engine metrics;
- `refresh_unavailable`: the engine reported temporarily unavailable refresh;
- `path_confusion`, `policy_denied`, or `server_error`: path guard or session-load
  failure as applicable.

`session_operation` has `operation=load|persist|revoke`,
`phase=request|denied|response|logging`, and `outcome=success|error`.
Only actual adapter calls are counted: load occurs in `request`; an owed persist
can run in `denied`, `response`, or `logging`; explicit local revocation runs in
`response` or `logging`. Engine-internal refresh, save, and revocation work is
not recounted. A successful load can return missing, cleared, or refresh-unavailable
state: `success` means the engine returned a classified result, not that a user
was authenticated. Persist success means the engine returned prepared cookie
headers or committed store state under its contract, not that the browser changed.

`finalization` uses `outcome=response|logging`. It counts the first finalization
entry even if no session work is owed. Interim responses do not enter; a 101
upgrade does. Repeated response/logging hooks do not count again. The engine's
direct callback/logout responses bypass response finalization and can therefore
enter the logging fallback with no outstanding work.

Cancellation before a decision or operation result emits no terminal count.
Cancellation after finalization entry can leave that entry without an operation
result. Decision counters remain recorded if a later write fails. Stranded-cookie
counts cover only headers observed and discarded by logging fallback; they do
not count every cookie lost to cancellation or a transport failure. Successful
header writes do not prove browser receipt or acceptance. No metric asserts
that a browser session was established or ended.

## Diagnostics without library logging

This adapter emits no library log statements. Returned proxy errors remain
available through Pingora's error hooks. `LoginProxy::diagnostics` provides an
optional application handler for session load/persist/revocation errors consumed
inside the adapter and for stranded cookie batches. It works without `metrics`.

```rust
# #[cfg(feature = "login")]
# fn configure<P, SD>(proxy: huskarl_pingora::login::LoginProxy<P, SD>)
# where P: pingora_proxy::ProxyHttp + Send + Sync,
# P::CTX: huskarl_pingora::login::HasLoginSession<SD::SessionType> + Send + Sync,
# SD: huskarl_pingora::login::SessionDriver + Send + Sync {
use huskarl_pingora::login::LoginDiagnostic;
let proxy = proxy.diagnostics(|event| match event {
    LoginDiagnostic::SessionFailure { operation, phase, error } => {
        // Apply application redaction/sampling before logging or exporting.
        // error.kind() and its source chain remain available here.
        let _ = (operation, phase, error.kind());
    }
    LoginDiagnostic::StrandedCookies { count } => {
        let _ = count; // Number of headers; never the cookie values.
    }
    _ => {}
});
# }
```

This synchronous `Fn` may run concurrently. It must not block or panic; panics
propagate and reentrant calls are not serialized. Reconfiguration replaces the
handler. No callback is installed by default and no error string is formatted
for telemetry without a consumer. Error sources can contain sensitive or
untrusted text; never copy them into metric labels. For asynchronous export,
copy only the required fields into a bounded queue and define overflow behavior.
The callback does not supply durable delivery or an atomic audit record.

Raw path logging has deliberately been removed. Counters preserve denial
categories, but do not retain individual paths or structural-probe details.
An application needing those details can inspect `ResolveError` when using the
route guard directly; generic proxy errors/responses do not promise the full
structured reason. This is an explicit reduction in default diagnostics, not
an assertion that counters replace detailed logs.

## Migration

Existing users must enable `metrics` to retain the guard counter. Unnamed
`huskarl.resource.check` series now carry `name=""`; update dashboards and
recording rules for this label-schema change. Named series keep their existing
name and outcome values. New adapter counters use `huskarl.pingora.*` because
their observation points are specific to this integration. Metric names, label
keys, and counting semantics are documented interfaces: changes require an
explicit migration note rather than silently changing a denominator.

Install a diagnostic handler if you relied on this crate's former login failure
logs. Configure the shared engine's diagnostic handler separately if engine failure
details are needed. Pingora and other dependencies retain their own logging behavior. The Pingora `logging` lifecycle hook still runs; removing library
log statements does not remove session cleanup or inner-proxy logging hooks.
