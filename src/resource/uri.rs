//! URI reconstruction for `DPoP` proof validation.
//!
//! When a `base_uri` is configured on the
//! [`Guard`](super::Guard), the request path is rewritten to the client-facing
//! URI so that `DPoP` `htu` (HTTP URI) binding works correctly behind a reverse
//! proxy.
//!
//! `base_uri` must be an origin the client cannot spoof — typically a value you
//! configure, not one taken from the inbound `Host` header. When it is
//! **absent** and no `url_mapping` is configured, the guard passes the raw request
//! URI to the validator. Behind a reverse proxy this is normally origin-form
//! (path and optional query, without scheme or authority), so `DPoP` validation
//! fails closed with a server-side integration error. Configure the guard's
//! `base_uri` or `url_mapping` whenever DPoP-bound tokens are accepted.

/// Reconstructs the client-facing URI for `DPoP` `htu` matching.
///
/// Combines the scheme and authority from `base_uri` with its path
/// prepended to the request path (after stripping `strip_prefix`).
/// If no `base_uri` is set, returns `Some(req_uri)`.
/// Returns `None` if a `strip_prefix` is configured but does not match
/// the request path, or if URI reconstruction fails.
pub(crate) fn request_uri(
    base_uri: Option<&http::Uri>,
    strip_prefix: Option<&str>,
    req_uri: &http::Uri,
) -> Option<http::Uri> {
    let Some(base) = base_uri else {
        return Some(req_uri.clone());
    };
    let mapping = crate::resource_server::core::url_mapping::PublicUrlMapping::new(
        &base.to_string(),
        strip_prefix.unwrap_or("/"),
    )
    .ok()?;
    legacy_request_uri(&mapping, req_uri)
}

/// Keeps the joining slash when a legacy ingress prefix consumes the whole path.
pub(crate) fn legacy_request_uri(
    mapping: &crate::resource_server::core::url_mapping::PublicUrlMapping,
    req_uri: &http::Uri,
) -> Option<http::Uri> {
    if req_uri.path() == mapping.incoming_prefix() {
        let subpath = req_uri
            .query()
            .map_or_else(|| "/".to_owned(), |q| format!("/?{q}"));
        mapping.resource_url(&subpath).ok()
    } else {
        mapping.public_url(req_uri).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> http::Uri {
        s.parse().unwrap()
    }

    #[test]
    fn reconstructs_expected_uri() {
        // (base_uri, strip_prefix, request_uri, expected reconstruction)
        let cases: &[(Option<&str>, Option<&str>, &str, &str)] = &[
            // No base → the raw request URI is returned unchanged.
            (None, None, "/api/data?q=1", "/api/data?q=1"),
            // Base contributes scheme + authority + path.
            (
                Some("https://api.example.com/v1"),
                None,
                "/users",
                "https://api.example.com/v1/users",
            ),
            // A trailing slash on the base path is trimmed before joining.
            (
                Some("https://api.example.com/v1/"),
                None,
                "/users",
                "https://api.example.com/v1/users",
            ),
            // A root base path adds no prefix.
            (
                Some("https://api.example.com"),
                None,
                "/users",
                "https://api.example.com/users",
            ),
            // The query string is preserved.
            (
                Some("https://api.example.com"),
                None,
                "/users?page=2&limit=10",
                "https://api.example.com/users?page=2&limit=10",
            ),
            // strip_prefix removes the matched leading segment.
            (
                Some("https://api.example.com"),
                Some("/proxy"),
                "/proxy/users",
                "https://api.example.com/users",
            ),
            // strip_prefix composes with a base path.
            (
                Some("https://api.example.com/v1"),
                Some("/proxy"),
                "/proxy/users",
                "https://api.example.com/v1/users",
            ),
            // strip_prefix keeps the query string.
            (
                Some("https://api.example.com"),
                Some("/proxy"),
                "/proxy/users?q=test",
                "https://api.example.com/users?q=test",
            ),
            // `/proxy/X` strips at the segment boundary — contrast the `/proxyX`
            // none-case below: the two must not reconstruct to the same URI.
            (
                Some("https://api.example.com"),
                Some("/proxy"),
                "/proxy/X",
                "https://api.example.com/X",
            ),
        ];
        for &(base, strip, req, expected) in cases {
            let base = base.map(uri);
            assert_eq!(
                request_uri(base.as_ref(), strip, &uri(req))
                    .map(|u| u.to_string())
                    .as_deref(),
                Some(expected),
                "base {base:?} strip {strip:?} req {req}",
            );
        }
    }

    #[test]
    fn returns_none_when_strip_prefix_does_not_match_at_a_boundary() {
        // A raw byte-prefix match would collapse `/proxyX` onto the same htu as
        // `/proxy/X`; stripping only at a segment boundary keeps them distinct, so
        // a non-boundary or absent prefix must fail reconstruction (fail closed).
        let base = uri("https://api.example.com");
        // (strip_prefix, request_uri) pairs that must NOT reconstruct.
        let cases: &[(&str, &str)] = &[
            ("/proxy", "/other/users"), // prefix absent
            ("/proxy", "/proxyusers"),  // shares bytes but not a segment boundary
            ("/proxy", "/proxyX"),      // ditto — must not collide with `/proxy/X`
        ];
        for &(strip, req) in cases {
            assert!(
                request_uri(Some(&base), Some(strip), &uri(req)).is_none(),
                "strip {strip:?} req {req} must not reconstruct",
            );
        }
    }

    #[test]
    fn strip_prefix_exact_match_leaves_empty_path() {
        let base = uri("https://api.example.com");
        let result = request_uri(Some(&base), Some("/proxy"), &uri("/proxy")).unwrap();
        // After stripping "/proxy" from "/proxy" we get "", base path is ""
        // so result path is "/" (from "/" being added).
        assert!(result.to_string().starts_with("https://api.example.com/"));
    }
}
