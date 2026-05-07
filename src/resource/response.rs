//! HTTP response helpers for the resource server.
//!
//! Writes [RFC 6750] challenge responses, [RFC 9728] resource metadata
//! responses, and 405 Method Not Allowed responses to the downstream Pingora
//! session.
//!
//! [RFC 6750]: https://datatracker.ietf.org/doc/html/rfc6750
//! [RFC 9728]: https://datatracker.ietf.org/doc/html/rfc9728

use pingora_error::{Error, ErrorType::InternalError};
use pingora_http::{IntoCaseHeaderName, ResponseHeader};
use pingora_proxy::Session;

// ── Header helpers ───────────────────────────────────────────────────────────

fn build_response(status: u16, capacity: usize) -> Result<ResponseHeader, Box<Error>> {
    ResponseHeader::build(status, Some(capacity))
        .map_err(|e| Error::because(InternalError, "failed to build response header", e))
}

fn insert_header(
    resp: &mut ResponseHeader,
    name: impl IntoCaseHeaderName,
    value: impl TryInto<http::header::HeaderValue>,
    context: &'static str,
) -> Result<(), Box<Error>> {
    resp.insert_header(name, value)
        .map_err(|e| Error::because(InternalError, context, e))?;
    Ok(())
}

fn append_header(
    resp: &mut ResponseHeader,
    name: impl IntoCaseHeaderName,
    value: impl TryInto<http::header::HeaderValue>,
    context: &'static str,
) -> Result<(), Box<Error>> {
    resp.append_header(name, value)
        .map_err(|e| Error::because(InternalError, context, e))?;
    Ok(())
}

// ── Public response writers ──────────────────────────────────────────────────

/// Writes the RFC 9728 protected resource metadata JSON response.
///
/// Returns 200 OK with `content-type: application/json` and
/// `cache-control: max-age=3600`.
pub(crate) async fn write_resource_metadata_response(
    session: &mut Session,
    body: &bytes::Bytes,
) -> Result<(), Box<Error>> {
    let mut resp = build_response(200, 3)?;
    insert_header(
        &mut resp,
        http::header::CONTENT_TYPE,
        "application/json",
        "failed to set content-type header",
    )?;
    insert_header(
        &mut resp,
        http::header::CONTENT_LENGTH,
        body.len(),
        "failed to set content-length header",
    )?;
    insert_header(
        &mut resp,
        http::header::CACHE_CONTROL,
        "max-age=3600",
        "failed to set cache-control header",
    )?;

    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(body.clone()), true)
        .await?;

    Ok(())
}

/// Writes an RFC 6750 challenge response to the downstream session.
///
/// Sets the HTTP status code, appends each challenge as a `WWW-Authenticate`
/// header, and optionally sets the `DPoP-Nonce` header.
pub(crate) async fn write_challenge_response(
    session: &mut Session,
    status: http::StatusCode,
    challenges: &[String],
    dpop_nonce: Option<&str>,
) -> Result<(), Box<Error>> {
    let capacity = challenges.len() + 2 + dpop_nonce.is_some() as usize;
    let mut resp = build_response(status.as_u16(), capacity)?;

    for challenge in challenges {
        append_header(
            &mut resp,
            http::header::WWW_AUTHENTICATE,
            challenge,
            "failed to append WWW-Authenticate header",
        )?;
    }

    if let Some(nonce) = dpop_nonce {
        insert_header(
            &mut resp,
            "DPoP-Nonce",
            nonce,
            "failed to set DPoP-Nonce header",
        )?;
    }

    insert_header(
        &mut resp,
        http::header::CONTENT_LENGTH,
        0,
        "failed to set content-length header",
    )?;
    insert_header(
        &mut resp,
        http::header::CACHE_CONTROL,
        "no-store",
        "failed to set cache-control header",
    )?;

    session.write_response_header(Box::new(resp), true).await?;

    Ok(())
}

/// Writes a 405 Method Not Allowed response with an `Allow` header.
pub(crate) async fn write_method_not_allowed(
    session: &mut Session,
    allow: &str,
) -> Result<(), Box<Error>> {
    let mut resp = build_response(405, 3)?;
    insert_header(
        &mut resp,
        http::header::ALLOW,
        allow,
        "failed to set Allow header",
    )?;
    insert_header(
        &mut resp,
        http::header::CONTENT_LENGTH,
        0,
        "failed to set content-length header",
    )?;
    insert_header(
        &mut resp,
        http::header::CACHE_CONTROL,
        "no-store",
        "failed to set cache-control header",
    )?;

    session.write_response_header(Box::new(resp), true).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use pingora_proxy::Session as ProxySession;
    use tokio::io::{AsyncWriteExt, DuplexStream};

    use super::*;

    /// Creates a test session. Returns both the session and the client half of
    /// the duplex stream — the client half must be kept alive until after
    /// response writing completes.
    async fn make_session(method: &str, path: &str) -> (ProxySession, DuplexStream) {
        let raw = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(raw.as_bytes()).await.unwrap();
        let mut session = ProxySession::new_h1(Box::new(server));
        session.downstream_session.read_request().await.unwrap();
        (session, client)
    }

    #[tokio::test]
    async fn metadata_response_sets_json_and_cache() {
        let (mut session, _client) =
            make_session("GET", "/.well-known/oauth-protected-resource").await;
        let body = Bytes::from_static(b"{\"resource\":\"https://api.example.com\"}");

        write_resource_metadata_response(&mut session, &body)
            .await
            .unwrap();

        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 200);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(resp.headers.get("cache-control").unwrap(), "max-age=3600");
        assert_eq!(
            resp.headers.get("content-length").unwrap(),
            &body.len().to_string()
        );
    }

    #[tokio::test]
    async fn challenge_response_401_with_challenges() {
        let (mut session, _client) = make_session("GET", "/api").await;
        let challenges = vec![
            "Bearer realm=\"api\"".to_owned(),
            "DPoP algs=\"ES256\"".to_owned(),
        ];

        write_challenge_response(
            &mut session,
            http::StatusCode::UNAUTHORIZED,
            &challenges,
            None,
        )
        .await
        .unwrap();

        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 401);
        let www_auth: Vec<_> = resp
            .headers
            .get_all("www-authenticate")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(www_auth, challenges);
        assert_eq!(resp.headers.get("content-length").unwrap(), "0");
        assert_eq!(resp.headers.get("cache-control").unwrap(), "no-store");
        assert!(resp.headers.get("dpop-nonce").is_none());
    }

    #[tokio::test]
    async fn challenge_response_with_dpop_nonce() {
        let (mut session, _client) = make_session("GET", "/api").await;

        write_challenge_response(
            &mut session,
            http::StatusCode::UNAUTHORIZED,
            &["Bearer".to_owned()],
            Some("server-nonce-abc"),
        )
        .await
        .unwrap();

        let resp = session.response_written().unwrap();
        assert_eq!(resp.headers.get("dpop-nonce").unwrap(), "server-nonce-abc");
    }

    #[tokio::test]
    async fn challenge_response_403() {
        let (mut session, _client) = make_session("GET", "/admin").await;

        write_challenge_response(
            &mut session,
            http::StatusCode::FORBIDDEN,
            &["Bearer error=\"insufficient_scope\"".to_owned()],
            None,
        )
        .await
        .unwrap();

        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 403);
    }

    #[tokio::test]
    async fn method_not_allowed_response() {
        let (mut session, _client) =
            make_session("POST", "/.well-known/oauth-protected-resource").await;

        write_method_not_allowed(&mut session, "GET, HEAD")
            .await
            .unwrap();

        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 405);
        assert_eq!(resp.headers.get("allow").unwrap(), "GET, HEAD");
        assert_eq!(resp.headers.get("content-length").unwrap(), "0");
        assert_eq!(resp.headers.get("cache-control").unwrap(), "no-store");
    }
}
