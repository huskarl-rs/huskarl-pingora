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

use super::ErrorBodyResponse;
use crate::resource_server::core::platform::Duration;

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
/// `cache-control: max-age=3600`. `Content-Length` always reflects the body
/// size, but the body itself is only written when `include_body` is `true` —
/// pass `false` for `HEAD` requests, which must carry the headers without a
/// body.
pub(crate) async fn write_resource_metadata_response(
    session: &mut Session,
    body: &bytes::Bytes,
    include_body: bool,
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

    session
        .write_response_header(Box::new(resp), !include_body)
        .await?;
    if include_body {
        session
            .write_response_body(Some(body.clone()), true)
            .await?;
    }

    Ok(())
}

/// Writes an RFC 6750 challenge response to the downstream session.
///
/// Sets the HTTP status code, appends each challenge as a `WWW-Authenticate`
/// header, and optionally sets the `DPoP-Nonce` header.
#[bon::builder]
pub(crate) async fn write_challenge_response(
    session: &mut Session,
    status: http::StatusCode,
    challenges: &[String],
    dpop_nonce: Option<&str>,
    retry_after: Option<Duration>,
    body: &ErrorBodyResponse,
) -> Result<(), Box<Error>> {
    let capacity = challenges.len()
        + 2
        + usize::from(dpop_nonce.is_some())
        + usize::from(retry_after.is_some());
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

    if let Some(after) = retry_after {
        // Delta-seconds rather than an HTTP-date, so the client needs no clock
        // agreement with us. Round a fractional second up: a remaining cooldown
        // must never render as `Retry-After: 0` and invite an immediate retry.
        let seconds = after
            .as_secs()
            .saturating_add(u64::from(after.subsec_nanos() > 0));
        insert_header(
            &mut resp,
            http::header::RETRY_AFTER,
            seconds,
            "failed to set Retry-After header",
        )?;
    }

    insert_header(
        &mut resp,
        http::header::CONTENT_LENGTH,
        body.body.len(),
        "failed to set content-length header",
    )?;
    insert_header(
        &mut resp,
        http::header::CACHE_CONTROL,
        "no-store",
        "failed to set cache-control header",
    )?;

    if let Some(content_type) = &body.content_type {
        insert_header(
            &mut resp,
            http::header::CONTENT_TYPE,
            content_type.clone(),
            "failed to set content-type header",
        )?;
    }
    let send_body = session.req_header().method != http::Method::HEAD && !body.body.is_empty();
    session
        .write_response_header(Box::new(resp), !send_body)
        .await?;
    if send_body {
        session
            .write_response_body(Some(body.body.clone()), true)
            .await?;
    }

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
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::resource::test_support::make_session;

    #[tokio::test]
    async fn metadata_response_sets_json_and_cache() {
        let (mut session, _client) =
            make_session("GET", "/.well-known/oauth-protected-resource").await;
        let body = Bytes::from_static(b"{\"resource\":\"https://api.example.com\"}");

        write_resource_metadata_response(&mut session, &body, true)
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
    async fn metadata_response_head_omits_body_but_keeps_content_length() {
        let (mut session, mut client) =
            make_session("HEAD", "/.well-known/oauth-protected-resource").await;
        let body = Bytes::from_static(b"{\"resource\":\"https://api.example.com\"}");

        write_resource_metadata_response(&mut session, &body, false)
            .await
            .unwrap();

        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 200);
        // Content-Length still advertises the full body size, per HTTP HEAD semantics.
        assert_eq!(
            resp.headers.get("content-length").unwrap(),
            &body.len().to_string()
        );

        // No body bytes are written for HEAD. Read whatever was sent to the
        // client and assert the JSON document is absent.
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let sent = String::from_utf8_lossy(&buf[..n]);
        assert!(
            !sent.contains("\"resource\""),
            "HEAD response must not include the body, got: {sent:?}"
        );
    }

    #[tokio::test]
    async fn challenge_response_401_with_challenges() {
        let (mut session, _client) = make_session("GET", "/api").await;
        let challenges = vec![
            "Bearer realm=\"api\"".to_owned(),
            "DPoP algs=\"ES256\"".to_owned(),
        ];

        write_challenge_response()
            .session(&mut session)
            .status(http::StatusCode::UNAUTHORIZED)
            .challenges(&challenges)
            .body(&ErrorBodyResponse::default())
            .call()
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

        write_challenge_response()
            .session(&mut session)
            .status(http::StatusCode::UNAUTHORIZED)
            .challenges(&["Bearer".to_owned()])
            .dpop_nonce("server-nonce-abc")
            .body(&ErrorBodyResponse::default())
            .call()
            .await
            .unwrap();

        let resp = session.response_written().unwrap();
        assert_eq!(resp.headers.get("dpop-nonce").unwrap(), "server-nonce-abc");
    }

    #[tokio::test]
    async fn challenge_response_omits_retry_after_when_absent() {
        let (mut session, _client) = make_session("GET", "/api").await;

        write_challenge_response()
            .session(&mut session)
            .status(http::StatusCode::UNAUTHORIZED)
            .challenges(&["Bearer".to_owned()])
            .body(&ErrorBodyResponse::default())
            .call()
            .await
            .unwrap();

        let resp = session.response_written().unwrap();
        assert!(resp.headers.get("retry-after").is_none());
    }

    #[tokio::test]
    async fn challenge_response_emits_retry_after_as_delta_seconds() {
        let (mut session, _client) = make_session("GET", "/api").await;

        write_challenge_response()
            .session(&mut session)
            .status(http::StatusCode::SERVICE_UNAVAILABLE)
            .challenges(&[])
            .retry_after(Duration::from_secs(30))
            .body(&ErrorBodyResponse::default())
            .call()
            .await
            .unwrap();

        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 503);
        assert_eq!(resp.headers.get("retry-after").unwrap(), "30");
    }

    #[tokio::test]
    async fn challenge_response_rounds_fractional_retry_after_up() {
        // A remaining cooldown must never render as `Retry-After: 0` — that reads as
        // "retry immediately" and would hammer a service that is already failing.
        for (interval, expected) in [
            (Duration::from_millis(1), "1"),
            (Duration::from_millis(1500), "2"),
            (Duration::ZERO, "0"),
        ] {
            let (mut session, _client) = make_session("GET", "/api").await;
            write_challenge_response()
                .session(&mut session)
                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                .challenges(&[])
                .retry_after(interval)
                .body(&ErrorBodyResponse::default())
                .call()
                .await
                .unwrap();
            let resp = session.response_written().unwrap();
            assert_eq!(
                resp.headers.get("retry-after").unwrap(),
                expected,
                "{interval:?} should render as {expected}",
            );
        }
    }

    #[tokio::test]
    async fn challenge_response_403() {
        let (mut session, _client) = make_session("GET", "/admin").await;

        write_challenge_response()
            .session(&mut session)
            .status(http::StatusCode::FORBIDDEN)
            .challenges(&["Bearer error=\"insufficient_scope\"".to_owned()])
            .body(&ErrorBodyResponse::default())
            .call()
            .await
            .unwrap();

        let resp = session.response_written().unwrap();
        assert_eq!(resp.status.as_u16(), 403);
    }

    #[tokio::test]
    async fn challenge_with_crlf_does_not_split_response() {
        // Header-injection safety. An application-supplied `CheckError` description flows
        // into the `error_description` quoted-string of a WWW-Authenticate challenge; the
        // upstream quoted-string escaper handles `"`/`\` but NOT CR/LF. The sole remaining
        // line of defense is the `http` crate's `HeaderValue` validator, which rejects
        // control bytes — so a challenge carrying a raw CRLF + a forged header must fail
        // the write rather than split the response. This pins that guarantee at the crate
        // boundary so an `http`-crate behavior change can't silently reopen it.
        let (mut session, _client) = make_session("GET", "/admin").await;
        let malicious = "Bearer error=\"insufficient_scope\", \
             error_description=\"nope\r\nInjected-Header: evil\""
            .to_owned();

        let result = write_challenge_response()
            .session(&mut session)
            .status(http::StatusCode::FORBIDDEN)
            .challenges(&[malicious])
            .body(&ErrorBodyResponse::default())
            .call()
            .await;

        // Fail closed: the CRLF value is rejected and nothing is committed downstream —
        // no split, no injected header.
        assert!(
            result.is_err(),
            "CRLF-bearing challenge must be rejected, not written"
        );
        assert!(
            session.response_written().is_none(),
            "no response header may reach the client"
        );
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
    #[tokio::test]
    async fn custom_body_preserves_headers_and_head_semantics() {
        for method in ["GET", "HEAD"] {
            let (mut session, mut client) = make_session(method, "/api").await;
            let body =
                ErrorBodyResponse::new("unavailable", http::HeaderValue::from_static("text/plain"));
            let challenges = vec!["Bearer realm=\"api\"".into(), "DPoP realm=\"api\"".into()];
            write_challenge_response()
                .session(&mut session)
                .status(http::StatusCode::UNAUTHORIZED)
                .challenges(&challenges)
                .dpop_nonce("nonce")
                .retry_after(Duration::from_millis(1500))
                .body(&body)
                .call()
                .await
                .unwrap();
            let resp = session.response_written().unwrap();
            assert_eq!(resp.status.as_u16(), 401);
            assert_eq!(resp.headers.get_all("www-authenticate").iter().count(), 2);
            assert_eq!(resp.headers["dpop-nonce"], "nonce");
            assert_eq!(resp.headers["retry-after"], "2");
            assert_eq!(resp.headers["cache-control"], "no-store");
            assert_eq!(resp.headers["content-type"], "text/plain");
            assert_eq!(resp.headers["content-length"], "11");
            drop(session);
            let mut wire = String::new();
            client.read_to_string(&mut wire).await.unwrap();
            let (_, sent_body) = wire.split_once("\r\n\r\n").unwrap();
            assert_eq!(sent_body, if method == "HEAD" { "" } else { "unavailable" });
        }
    }
}
