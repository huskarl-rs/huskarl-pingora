//! Cookie utilities for the login layer.
//!
//! Provides helpers for reading cookies from request headers and constructing
//! login-state cookie names with appropriate security prefixes (`__Host-`,
//! `__Secure-`, or none).

use http::header;

pub(super) const LOGIN_COOKIE_PREFIX: &str = "huskarl_login_";

/// Returns the login-state cookie name for the given OAuth `state` value,
/// applying the appropriate cookie name prefix based on security settings:
///
/// - `__Host-` when `secure` is `true` and `path` is `"/"` (strongest guarantee)
/// - `__Secure-` when `secure` is `true` and `path` is a sub-path
/// - no prefix when `secure` is `false` (e.g. local HTTP development)
pub(super) fn login_state_cookie_name(state: &str, secure: bool, path: &str) -> String {
    let prefix = if secure {
        if path == "/" { "__Host-" } else { "__Secure-" }
    } else {
        ""
    };
    format!("{prefix}{LOGIN_COOKIE_PREFIX}{state}")
}

/// Builds the standard cookie attribute string for session cookies.
///
/// Returns `"HttpOnly; SameSite=Lax; Path={path}; Secure"` (or without
/// `Secure` when `secure` is `false`).
pub(super) fn cookie_attrs(secure: bool, path: &str) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("HttpOnly; SameSite=Lax; Path={path}{secure}")
}

/// Extracts a cookie value by name from request headers.
///
/// This is a utility function for [`SessionDriver`](super::SessionDriver)
/// implementations that need to read cookies from request headers.
pub fn get_cookie<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    for value in headers.get_all(header::COOKIE) {
        let Ok(s) = value.to_str() else { continue };
        for pair in s.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=')
                && k.trim() == name
            {
                return Some(v.trim());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_cookie_present() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::COOKIE, "foo=bar".parse().unwrap());
        assert_eq!(get_cookie(&headers, "foo"), Some("bar"));
    }

    #[test]
    fn get_cookie_missing() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::COOKIE, "foo=bar".parse().unwrap());
        assert_eq!(get_cookie(&headers, "baz"), None);
    }

    #[test]
    fn get_cookie_multiple_pairs() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::COOKIE, "a=1; b=2; c=3".parse().unwrap());
        assert_eq!(get_cookie(&headers, "a"), Some("1"));
        assert_eq!(get_cookie(&headers, "b"), Some("2"));
        assert_eq!(get_cookie(&headers, "c"), Some("3"));
    }

    #[test]
    fn get_cookie_whitespace_trimmed() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::COOKIE, " foo = bar ".parse().unwrap());
        assert_eq!(get_cookie(&headers, "foo"), Some("bar"));
    }

    #[test]
    fn get_cookie_empty_headers() {
        let headers = http::HeaderMap::new();
        assert_eq!(get_cookie(&headers, "foo"), None);
    }

    #[test]
    fn get_cookie_multiple_cookie_headers() {
        let mut headers = http::HeaderMap::new();
        headers.append(header::COOKIE, "a=1".parse().unwrap());
        headers.append(header::COOKIE, "b=2".parse().unwrap());
        assert_eq!(get_cookie(&headers, "a"), Some("1"));
        assert_eq!(get_cookie(&headers, "b"), Some("2"));
    }

    #[test]
    fn get_cookie_value_with_equals() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::COOKIE, "token=abc=def".parse().unwrap());
        // split_once on '=' means value is "abc=def"
        assert_eq!(get_cookie(&headers, "token"), Some("abc=def"));
    }

    // ── login_state_cookie_name tests ──────────────────────────────────────

    #[test]
    fn cookie_name_secure_root_uses_host_prefix() {
        let name = login_state_cookie_name("abc123", true, "/");
        assert!(name.starts_with("__Host-"));
    }

    #[test]
    fn cookie_name_secure_subpath_uses_secure_prefix() {
        let name = login_state_cookie_name("abc123", true, "/app");
        assert!(name.starts_with("__Secure-"));
    }

    #[test]
    fn cookie_name_insecure_no_prefix() {
        let name = login_state_cookie_name("abc123", false, "/");
        assert!(!name.starts_with("__"));
    }

    #[test]
    fn cookie_name_contains_state() {
        let name = login_state_cookie_name("mystate", true, "/");
        assert!(name.contains("mystate"));
    }
}
