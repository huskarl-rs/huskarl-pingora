# Put browser login in front of an upstream

Run a Pingora proxy and a small upstream, sign in through an OIDC provider,
see your subject identifier on the upstream page, and sign out. The proxy
manages encrypted cookie sessions; the upstream receives a subject header.

## 1. Prepare the provider and checkout

You need Rust 1.92 or later, native build tools for Pingora (including CMake),
Python 3, OpenSSL, and an OIDC provider. Run the commands from a checkout of
`huskarl-pingora`. Dependencies come from Cargo's registry; no sibling checkout
is required.

Register a public client using Authorization Code with PKCE and no client
secret. Register this exact sign-in redirect URI:

```text
http://localhost:6188/callback
```

The example uses `NoAuth`; a confidential client registration requires a
different grant configuration. Keep the browser host as `localhost`; changing
to `127.0.0.1` changes the origin and cookie host.

## 2. Start the upstream

In the first terminal, from the repository root:

```sh
python3 examples/login_upstream.py
```

Expect `Demo upstream listening on 127.0.0.1:3001`. Check its health:

```sh
curl http://127.0.0.1:3001/health
```

Expect `ok`. Keep this terminal running. This small upstream trusts the proxy's
identity header and binds only to loopback. In a deployment, restrict upstream
access to the proxy; the header is not a signed credential. Other processes on
this machine are within this demo's trust boundary.

## 3. Start the proxy

In a second terminal, also from the repository root:

```sh
export ISSUER='https://your-provider.example.com'
export CLIENT_ID='your-public-client-id'
export REDIRECT_URI='http://localhost:6188/callback'
export COOKIE_KEY="$(openssl rand -hex 32)"
cargo run --example login_proxy --features login
```

Replace the issuer and client ID with your registration. The proxy fetches
provider metadata and signing keys, then listens on `127.0.0.1:6188`, forwarding
to `127.0.0.1:3001`. Keep the same 32-byte key across restarts. The example
requires it and never prints it.

`LISTEN`, `UPSTREAM`, and `UPSTREAM_TLS` override networking; leave them unset
for this exercise. The explicit native verifier also supports running this
example with `--no-default-features --features login`.

## 4. Sign in and inspect identity

Open `http://localhost:6188/dashboard` in your browser.

1. The protected route redirects you to the provider.
2. Sign in and approve consent if requested.
3. The provider returns to `/callback`; the proxy exchanges the code, validates
   the response, and sets its session cookie.
4. The browser returns to `/dashboard`. The upstream displays **You are signed
   in** and your provider subject identifier.

The root `/` is an optional-authentication landing page with a sign-in link;
opening it does not itself require login. API requests may receive `401`
instead of a browser redirect.

The proxy removes its session cookies before forwarding. The example removes
any incoming `X-Authenticated-Subject` header and sets it from the loaded
session. The upstream does not decrypt cookies or receive refresh tokens.
The example upstream marks its responses `Cache-Control: no-store`.

## 5. Sign out

Use **Sign out** on the dashboard. Its same-origin form sends `POST /logout`.
The proxy clears its cookies and returns `303 See Other` to `/signed-out`, a
public route displaying **You are signed out**.

Typing `/logout` into the address bar sends GET and returns `405`. A POST
without the matching `Origin` returns `403`. This example performs local
application logout. Your provider may retain its SSO session, so **Sign in
again** may work without another password prompt.

## 6. Check restart persistence

Sign in again, stop only the proxy, and run its command again in the same
terminal without regenerating `COOKIE_KEY`. Reload `/dashboard`; the same
session should remain usable while its token and eight-hour lifetime are valid.

The example requests only `openid`. To exercise refresh, enable refresh tokens
for your client and add `offline_access` to the scopes if the provider uses it.
Start a new login, then verify behavior after the token enters the refresh
window. Rotation and concurrent refresh require their own deployment checks.

## Next steps

- [Review deployment limits](crate::_docs::how_to::deployment) before exposing the proxy beyond localhost.

- [Forward identity to an upstream](crate::_docs::how_to::identity).
- [Choose route policies](crate::_docs::how_to::routes) and
  [configure the path guard](crate::_docs::how_to::path_guard).
- Understand the [login proxy lifecycle](crate::_docs::explanation::login_lifecycle).
- [Troubleshoot a proxy](crate::_docs::how_to::troubleshooting).
- For refresh deployment, use the shared
  [rotation guide](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/how_to/rotation/).

- For ingress rewrites, follow [Map public URLs to incoming paths](crate::_docs::how_to::url_mapping).
- To construct the engine in your own application, follow the shared
  [login-engine tutorial](https://docs.rs/huskarl-login/0.5.0/huskarl_login/_docs/tutorial/getting_started/).
  Its environment variables and port differ from this Pingora exercise.
