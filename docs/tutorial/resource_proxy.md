# Protect an upstream with access tokens

Run an upstream and a Pingora proxy, inspect public discovery metadata, then
compare requests with and without a valid access token. The example protects
`/api` and its descendants and returns 404 for unrelated paths.

## 1. Prepare the checkout and issuer

You need Rust 1.92 or later, native Pingora build tools (including CMake), Python 3,
curl, and an authorization server that issues RFC 9068 JWT access tokens. Run the
commands from this repository's root. Dependencies come from Cargo's registry;
sibling repositories are not required.

In your provider, register an API/resource with audience `pingora-demo` and
RFC 9068 access tokens. For this exercise, register a confidential client allowed
to use the client-credentials grant for that API, with `client_secret_basic`
authentication. Record its client ID, secret, and token endpoint. The provider's
resource/audience settings must cause that grant to issue tokens for `pingora-demo`.
If your provider requires an extra audience or resource parameter, include it in
the token request in step 5 as instructed by the provider.

An existing client can also supply a suitable access token if client credentials
are unavailable. An OIDC ID token is not a substitute. The proxy validates access
tokens; it does not issue them or register OAuth clients.

The example fetches RFC 8414 authorization-server metadata. If your provider only
exposes OIDC discovery, change `AuthorizationServerMetadata::fetch()` to
`oidc_fetch()` in `examples/support/resource_server.rs` before continuing.

## 2. Start a small upstream

In the first terminal, create a temporary directory and serve a file:

```sh
export DEMO_ROOT="$(mktemp -d)"
printf 'You reached the protected upstream.\n' > "$DEMO_ROOT/api"
python3 -m http.server 3000 --bind 127.0.0.1 --directory "$DEMO_ROOT"
```

In another terminal, check `curl http://127.0.0.1:3000/api`. Expect
`You reached the protected upstream.` Keep the first terminal running.
This upstream has no authentication; loopback access is part of the demo's
trust boundary. A deployment must restrict upstream access to the proxy.

## 3. Start the proxy

From the repository root in the second terminal:

```sh
ISSUER=https://your-issuer.example.com \
PUBLIC_BASE=https://api.example.com \
AUDIENCE=pingora-demo \
UPSTREAM=127.0.0.1:3000 \
cargo run --example resource_proxy
```

Replace `ISSUER` with your provider's issuer URL. After discovery and startup,
expect `Listening on 127.0.0.1:6188`.

`PUBLIC_BASE` is the trusted advertised origin. For this local bearer-token
exercise it need not resolve: requests go directly to the loopback listener.
The resource identifier is `https://api.example.com/api`; its accepted token
audience is the explicit `pingora-demo` override. In a deployment, publish the
configured URLs through your real HTTPS entry point.

## 4. Inspect discovery and rejection

In a third terminal:

```sh
curl -i http://127.0.0.1:6188/.well-known/oauth-protected-resource/api
curl -i http://127.0.0.1:6188/api
curl -i http://127.0.0.1:6188/unrelated
```

Expect, respectively:

1. 200 and JSON identifying `https://api.example.com/api`.
2. 401 and a `WWW-Authenticate` challenge advertising the canonical metadata URL.
3. 404 from the assembly's fallback.

Discovery is public; it does not require a token. The metadata advertises the
public HTTPS URL even though this exercise uses a local HTTP connection.

## 5. Make an authenticated request

In the third terminal, set `TOKEN_ENDPOINT`, `CLIENT_ID`, and `CLIENT_SECRET` to
your registration's values. Obtain a token and extract the `access_token` field:

```sh
export TOKEN_ENDPOINT='https://your-issuer.example.com/token'
export CLIENT_ID='your-client-id'
export CLIENT_SECRET='your-client-secret'
TOKEN_RESPONSE="$(curl --fail --silent --show-error \
  --user "$CLIENT_ID:$CLIENT_SECRET" \
  --data grant_type=client_credentials \
  "$TOKEN_ENDPOINT")"
export ACCESS_TOKEN="$(printf '%s' "$TOKEN_RESPONSE" | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')"
unset TOKEN_RESPONSE
```

The endpoint path is provider-specific: use the discovered or registered endpoint,
not the placeholder above. If token acquisition fails, check client authentication
and the provider's grant/audience configuration before testing the proxy. If using
an existing OAuth client instead, load its access token into `ACCESS_TOKEN`.

Send the authenticated request:

```sh
curl -i -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:6188/api
```

Expect 200 and `You reached the protected upstream.` The proxy validates the
token and forwards the unchanged `/api` path. It removes `Authorization` and
`DPoP` before forwarding by default.

If you receive 401, check the token's issuer, audience, expiry, and RFC 9068
format against the provider configuration. An opaque token or ID token will
not work with this example's validator. Check startup discovery separately from
request-time token validation. A 5xx after authentication can indicate that the
upstream is unavailable; repeat the direct upstream check from step 2.

This example requires authentication but no particular scope. Next, follow
[Choose route policies](crate::_docs::how_to::routes) to require `api.read` and
compare tokens with and without that scope.

## Next steps

- [Assemble multiple resources](crate::_docs::how_to::resource_registration).
- [Publish metadata behind a rewriting gateway](crate::_docs::how_to::resource_metadata).
- [Customize rejection bodies](crate::_docs::how_to::error_responses).
- [Deploy the proxy](crate::_docs::how_to::deployment) before exposing it publicly.

Stop both servers with Ctrl-C when finished and unset `ACCESS_TOKEN` and `CLIENT_SECRET` in the client
terminal. The temporary upstream directory contains only the demo file.
