# huskarl-pingora

This crate implements resource server functionality on top of pingora; that is, it can validate requests that
have accompanying access tokens. Standard checks include token validity, signature verification; also
rules against the audience, issuer, and so on.

Some rules can be defined for sub-routes - allowing, for example, per-route scopes to be checked.

It is capable of handling both JWT tokens and opaque tokens (where the token can be validated using token
introspection). mTLS and DPoP bindings are also checked.
