/// Reconstructs the client-facing URI for DPoP `htu` matching.
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
            let Some(stripped) = req_path.strip_prefix(prefix) else {
                log::warn!(
                    "strip_prefix {:?} did not match request path {:?}",
                    prefix,
                    req_path,
                );
                return None;
            };
            stripped
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
            log::warn!(
                "failed to parse reconstructed path_and_query {:?}: {e}",
                path_and_query,
            );
            return None;
        }
    };
    http::Uri::from_parts(parts)
        .map_err(|e| {
            log::warn!(
                "failed to reconstruct DPoP URI from base {:?} and path {:?}: {e}",
                base,
                path_and_query,
            );
            e
        })
        .ok()
}
