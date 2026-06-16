//! URI reconstruction for `DPoP` proof validation.
//!
//! When a `base_uri` (resource identifier) is configured on the
//! [`Guard`](super::Guard), the request path is rewritten to the client-facing
//! URI so that `DPoP` `htu` (HTTP URI) binding works correctly behind a reverse
//! proxy.

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

    let req_path = req_uri.path();
    let stripped = match strip_prefix {
        Some(prefix) => {
            // Only strip when the prefix ends at a segment boundary, so that
            // `/proxy` matches `/proxy` and `/proxy/...` but not `/proxyX`.
            // A raw byte-prefix match would collapse `/proxyX` and `/proxy/X`
            // onto the same reconstructed URI, weakening DPoP `htu` binding.
            match req_path.strip_prefix(prefix) {
                Some(rest) if rest.is_empty() || rest.starts_with('/') => rest,
                _ => {
                    log::warn!("strip_prefix {prefix:?} did not match request path {req_path:?}");
                    return None;
                }
            }
        }
        None => req_path,
    };

    let base_path = base.path().trim_end_matches('/');
    let new_path = if stripped.starts_with('/') {
        format!("{base_path}{stripped}")
    } else {
        format!("{base_path}/{stripped}")
    };

    let path_and_query = match req_uri.query() {
        Some(q) => format!("{new_path}?{q}"),
        None => new_path,
    };

    let mut parts = http::uri::Parts::default();
    parts.scheme = base.scheme().cloned();
    parts.authority = base.authority().cloned();
    parts.path_and_query = match path_and_query.parse() {
        Ok(pq) => Some(pq),
        Err(e) => {
            log::warn!("failed to parse reconstructed path_and_query {path_and_query:?}: {e}");
            return None;
        }
    };
    http::Uri::from_parts(parts)
        .map_err(|e| {
            log::warn!(
                "failed to reconstruct DPoP URI from base {base:?} and path {path_and_query:?}: {e}"
            );
            e
        })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> http::Uri {
        s.parse().unwrap()
    }

    #[test]
    fn no_base_returns_original() {
        let req = uri("/api/data?q=1");
        let result = request_uri(None, None, &req).unwrap();
        assert_eq!(result.to_string(), "/api/data?q=1");
    }

    #[test]
    fn base_prepends_scheme_authority_and_path() {
        let base = uri("https://api.example.com/v1");
        let req = uri("/users");
        let result = request_uri(Some(&base), None, &req).unwrap();
        assert_eq!(result.to_string(), "https://api.example.com/v1/users");
    }

    #[test]
    fn base_with_trailing_slash() {
        let base = uri("https://api.example.com/v1/");
        let req = uri("/users");
        let result = request_uri(Some(&base), None, &req).unwrap();
        assert_eq!(result.to_string(), "https://api.example.com/v1/users");
    }

    #[test]
    fn base_root_path() {
        let base = uri("https://api.example.com");
        let req = uri("/users");
        let result = request_uri(Some(&base), None, &req).unwrap();
        assert_eq!(result.to_string(), "https://api.example.com/users");
    }

    #[test]
    fn preserves_query_string() {
        let base = uri("https://api.example.com");
        let req = uri("/users?page=2&limit=10");
        let result = request_uri(Some(&base), None, &req).unwrap();
        assert_eq!(
            result.to_string(),
            "https://api.example.com/users?page=2&limit=10"
        );
    }

    #[test]
    fn strip_prefix_removes_prefix() {
        let base = uri("https://api.example.com");
        let req = uri("/proxy/users");
        let result = request_uri(Some(&base), Some("/proxy"), &req).unwrap();
        assert_eq!(result.to_string(), "https://api.example.com/users");
    }

    #[test]
    fn strip_prefix_mismatch_returns_none() {
        let base = uri("https://api.example.com");
        let req = uri("/other/users");
        assert!(request_uri(Some(&base), Some("/proxy"), &req).is_none());
    }

    #[test]
    fn strip_prefix_requires_segment_boundary() {
        // `/proxyX` shares a byte prefix with `/proxy` but is a different path
        // segment — it must NOT be stripped (a raw byte-prefix match would
        // collapse it onto the same htu as `/proxy/X`).
        let base = uri("https://api.example.com");
        let req = uri("/proxyusers");
        assert!(request_uri(Some(&base), Some("/proxy"), &req).is_none());
    }

    #[test]
    fn strip_prefix_boundary_does_not_collide() {
        // `/proxyX` is rejected, while `/proxy/X` reconstructs to `.../X`, so the
        // two no longer map to the same reconstructed URI.
        let base = uri("https://api.example.com");
        assert!(request_uri(Some(&base), Some("/proxy"), &uri("/proxyX")).is_none());
        let collide = request_uri(Some(&base), Some("/proxy"), &uri("/proxy/X")).unwrap();
        assert_eq!(collide.to_string(), "https://api.example.com/X");
    }

    #[test]
    fn strip_prefix_with_base_path() {
        let base = uri("https://api.example.com/v1");
        let req = uri("/proxy/users");
        let result = request_uri(Some(&base), Some("/proxy"), &req).unwrap();
        assert_eq!(result.to_string(), "https://api.example.com/v1/users");
    }

    #[test]
    fn strip_prefix_with_query() {
        let base = uri("https://api.example.com");
        let req = uri("/proxy/users?q=test");
        let result = request_uri(Some(&base), Some("/proxy"), &req).unwrap();
        assert_eq!(result.to_string(), "https://api.example.com/users?q=test");
    }

    #[test]
    fn strip_prefix_exact_match_leaves_empty_path() {
        let base = uri("https://api.example.com");
        let req = uri("/proxy");
        let result = request_uri(Some(&base), Some("/proxy"), &req).unwrap();
        // After stripping "/proxy" from "/proxy" we get "", base path is ""
        // so result path is "/" (from "/"  being added).
        assert!(result.to_string().starts_with("https://api.example.com/"));
    }
}
