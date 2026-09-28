# Cache responses per authenticated user

Use this when personalized responses are reusable for one authenticated identity.
Caching is disabled by default in Pingora. `LoginProxy` and `AuthProxy` do not
automatically enable it or construct a user-specific cache key. If you cannot
identify all inputs that affect a response or enforce access before a cache hit,
leave personalized caching disabled.

## Authenticate and authorize before lookup

In the normal Pingora request lifecycle, the auth decorator's `request_filter`
runs before cache lookup. Its authenticated context is therefore available to
the inner proxy's `request_cache_filter` and `cache_key_callback`.

- For browser login, read the session through `HasLoginSession::login_state`
  and its subject through the session's `sub()` method. This works with cookie
  and store-backed sessions. Obtain the issuer namespace from trusted login
  configuration or authenticated session enrichment; do not assume `sub` is
  globally unique.
- For bearer tokens, use `HasAuthState::validated_token` and its validated
  issuer and subject. A valid access token is not guaranteed to have a user
  subject. Define an appropriate authenticated principal for machine clients,
  or disable this caching path.
- In `request_cache_filter`, enable personalized caching only when the required
  identity is present. Check again when constructing the key; never map a missing
  identity to a shared empty-user key.

A `public` rule skips authentication loading or validation. Use `optional` when
a route accepts anonymous requests but needs available identity, and keep its
anonymous response policy separate from personalized caching.

Cache hits skip the upstream and its authorization checks. Enforce the required
access checks before lookup, using route checks or the inner `request_filter`.
Checks in `upstream_request_filter` or `proxy_upstream_filter` are too late to
protect a cache hit. A user-specific key alone cannot prevent a user retrieving
content after losing access. Use current authorization checks, invalidation, or
a trusted authorization version in the key. Token claims and session snapshots
are not automatically refreshed from an application's permission database on
each request.

## Put identity in the primary key

**`CacheKey::new(primary, user_tag)` hashes only `primary`. Putting a user ID
solely in `user_tag` does not separate users' cache entries.** Include identity
in the primary key itself.

Build a key from the trusted service/resource namespace, issuer, subject,
tenant where applicable, method, path and query, and every response variant
needed by the application. Use explicit framing to avoid collisions between
component boundaries:

```rust
use pingora_cache::CacheKey;

fn framed_key(fields: &[&str]) -> CacheKey {
    let mut primary = Vec::new();
    for field in fields {
        primary.extend_from_slice(field.len().to_string().as_bytes());
        primary.push(b':');
        primary.extend_from_slice(field.as_bytes());
    }
    CacheKey::new(primary, "")
}

// In cache_key_callback, obtain identity from authenticated context and the
// resource namespace from trusted routing configuration. These are examples.
let alice = framed_key(&[
    "user-cache-v1", "inventory", "https://issuer.example", "alice",
    "tenant-a", "GET", "/account?view=summary", "en",
]);
let bob = framed_key(&[
    "user-cache-v1", "inventory", "https://issuer.example", "bob",
    "tenant-a", "GET", "/account?view=summary", "en",
]);
assert_ne!(alice.primary_key(), bob.primary_key());
assert_ne!(framed_key(&["ab", "c"]).primary_key(),
           framed_key(&["a", "bc"]).primary_key());
```

The fields above are illustrative, not a universal response-variation policy.
Account for selected account, language, relevant application cookies, and
session-specific content where applicable. Use Pingora's variance callbacks
when implementing response `Vary` behavior; do not assume user partitioning
handles it. Start with explicitly cacheable GET/HEAD responses and define their
key and representation semantics consistently.

Do not use raw tokens or session cookies as the user identifier. They are
credentials and can rotate independently of identity. Do not trust incoming
identity headers or raw `Host` as proof of an authenticated user or configured
resource. Headers inserted in `upstream_request_filter` are unavailable during
lookup and are not a substitute for reading the authenticated context.

## Control admission and downstream caching separately

Your inner proxy owns `response_cache_filter`, freshness, invalidation, and
variance handling. A user key does not make every response cacheable: respect
upstream cache restrictions and exclude session-specific responses that cannot
safely be reused. In particular, application-generated `Set-Cookie` headers can
still arrive from the upstream; the login adapter's handling of its own cookies
does not make those safe to cache, even across two sessions of the same user.

Login session cookies are added in downstream `response_filter`, after Pingora
cache processing. The adapter adds `Cache-Control: no-store` when it appends
those cookies. Steady-state personalized responses without cookie changes still
need an explicit downstream policy.

Browsers and CDNs do not know your internal user-specific cache key. Apply
appropriate downstream `Cache-Control: private` or `no-store` for personalized
responses, including cache hits. `private` permits browser caching; `no-store`
is appropriate when that is unwanted too. Set downstream policy in the response
phase while keeping internal admission an explicit, separate decision; a late
`no-store` does not undo Pingora's earlier cache admission. Do not simply ignore
an upstream `no-store` to enable internal caching.

## Verify user isolation

Test through Pingora's real request runner with the caching configuration used
in production:

1. Alice requests a URL twice: the second response is a cache hit with Alice's
   content, without another upstream request.
2. Bob requests the same URL: he never receives Alice's content.
3. Subjects with the same text under different issuers or tenants stay separate.
4. Anonymous requests and forged identity headers cannot retrieve either entry.
5. After access is removed, the configured authorization or invalidation mechanism
   prevents the old response being served. Include different scopes or permissions
   for tokens belonging to the same subject when those affect access.
6. Relevant representation variants stay separate, and downstream cache-control
   headers are present on both hits and misses.
7. Neither login cookies nor application cookies are inadvertently replayed from
   cached responses.

The adapter's lifecycle tests already check that login cookie headers stay out
of Pingora's cache. They do not establish user isolation for an application cache
key or its response bodies. Add those assertions for your chosen key and policy.
