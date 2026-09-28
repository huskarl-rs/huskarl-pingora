# Choose route policies

Both proxies map request paths to per-path rules. There are two ways to
register a rule, and **which you pick is a security decision**:

- **`subtree(path, rule)`** applies the rule to `path` *and everything
  beneath it* (`/admin`, `/admin/`, `/admin/users/42`). This is what you
  almost always want when protecting an area of your API, and it is the
  recommended default.
- **`route(pattern, rule)`** matches a single path *exactly*. `route("/admin",
  …)` does **not** cover `/admin/` or `/admin/users` — those fall through to
  the default rule. Reach for `route` only when you genuinely mean one path
  (e.g. a health check), or to carve a more-specific exception out of a
  `subtree`.

Using `route` where you meant `subtree` is a classic authorization gap: the
scope/audience checks you attached to `/admin` silently don't apply to
`/admin/users`. When in doubt, use `subtree`.

Unmatched paths fall back to the builder's default rule — `Rule::required()`
/ `LoginRule::required()` — so everything is protected unless you open it up.


## Select authentication behavior

| Policy | Session/token handling | Use for |
|---|---|---|
| `required` | Require usable authentication before forwarding | Protected areas |
| `optional` | Load/validate authentication when supplied; allow anonymous access | Public pages that can personalize responses |
| `public` | Skip authentication handling | Health checks and anonymous content |

For login, opening an optional page does not start a new login. Link to a
required route to start the browser flow. A required route returns a challenge
rather than a browser redirect for API requests.

For bearer-token protection, attach audience, scopes, and custom checks to the
resource rule. The `resource` module documents those rule options.

## Check the boundaries

Exercise the exact path, trailing slash, descendants, and intended methods.
Method-specific rules deny unlisted methods with 403, even with a public
default; register an all-method fallback deliberately when required.
Configure the [path guard](crate::_docs::how_to::path_guard) for the complete
downstream parsing pipeline.
