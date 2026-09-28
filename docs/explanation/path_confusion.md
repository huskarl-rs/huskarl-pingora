# Path confusion

Rules are matched on the request path, which huskarl leaves unchanged.
If the proxy and the upstream disagree about what a path *means* —
a parser differential — a request can be authorized as one path while the
upstream acts on another (`/x/../admin/secret`, `/admin%2fsecret`,
`/admin/..;/secret`, …). Both proxies guard against this automatically, and
it is **on by default**. The guard only ever *detects*: it denies the request
or allows it without rewriting the path. An inner proxy can still rewrite it;
see the forwarding and rewrite contract below.

The default [`GuardMode::RejectAmbiguous`](crate::path_confusion::GuardMode::RejectAmbiguous)
checks whether the configured downstream parsing behaviors could select a
different authorization rule. Its guarantees depend on your case sensitivity,
decode depth, and structural-class declarations. See the
[`crate::path_confusion`] configuration module for the supported parsing model.

Structural forms can pass when analysis proves they stay within the same rule.
For example, `subtree("/files", Rule::public())` permits `/files/a%2Fb.txt`
when no nested rule changes the policy. `/files/../admin/x` is denied when it
could escape into a different rule. NUL truncation is always denied in active modes.

`blob_subtree` registers an exclusive subtree: nested overrides are a build
error. It uses the same ambiguity checks as an ordinary subtree; exclusivity
does not disable checks or by itself establish uniform method coverage.

Method-specific rules deny unlisted methods with `403 Forbidden`, even if
the default rule is public. Register an all-method rule at the same path to
supply an explicit fallback policy.

Integrations that resolve routes directly can use
[`crate::path_confusion::resolve_error_status`] to match both proxies: invalid or
ambiguous input returns `400`, a missing method policy returns `403`, and an
internal routing failure returns `500`.

## Authorization across layers

The path guard checks ambiguity against this proxy's configured rules only.
A `LoginProxy` with only a default rule still enforces that login policy and
performs input checks, but its ambiguity analysis cannot distinguish finer
permission boundaries enforced by inner handlers. For example, if an inner
handler restricts `/downloads/private` more than `/downloads/public`, a
single outer login rule does not protect that distinction from path confusion.

Represent those boundaries in the guarding layer's rule table, or guard them
in the layer that makes the authorization decision, using its own rules and
downstream parsing assumptions. Passing the outer guard does not establish
that a path is unambiguous for every inner authorization decision.

## Forwarding and rewrite contract

The baseline contract is to forward the checked path unchanged. The guard
analyzes downstream parsing of that path; it does not model arbitrary rewrites
performed by an inner proxy such as `RouterProxy`.

A prefix replacement can preserve the guarantee only when every downstream
interpretation of the rewritten path remains within the authorization policy
checked before the rewrite. The rule table must cover the corresponding
boundaries in the original path namespace, and the declared case sensitivity,
decode depth, and structural classes must cover the full downstream pipeline,
including any parsing performed by the rewrite itself.

Applying the same prefix replacement consistently is not sufficient by itself:
removing a prefix can change where `..` resolves, and decoding before selecting
a prefix can change which rewrite applies. Verify the actual guard, rewrite,
and downstream routing together, including encoded separators and traversal
at the prefix boundary. If that correspondence cannot be established, resolve
and authorize the rewritten path with a guard configured for the destination
rules before dispatching it.
