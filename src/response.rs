use pingora_error::{Error, ErrorType::InternalError};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

/// Writes the RFC 9728 protected resource metadata JSON response.
///
/// Returns 200 OK with `content-type: application/json` and
/// `cache-control: max-age=3600`.
pub(crate) async fn write_resource_metadata_response(
    session: &mut Session,
    body: &bytes::Bytes,
) -> Result<(), Box<Error>> {
    let mut resp = ResponseHeader::build(200, Some(3))
        .map_err(|e| Error::because(InternalError, "failed to build response header", e))?;

    resp.insert_header(http::header::CONTENT_TYPE, "application/json")
        .map_err(|e| Error::because(InternalError, "failed to set content-type header", e))?;

    resp.insert_header(http::header::CONTENT_LENGTH, body.len())
        .map_err(|e| Error::because(InternalError, "failed to set content-length header", e))?;

    resp.insert_header(http::header::CACHE_CONTROL, "max-age=3600")
        .map_err(|e| Error::because(InternalError, "failed to set cache-control header", e))?;

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
    let mut resp = ResponseHeader::build(status.as_u16(), Some(capacity))
        .map_err(|e| Error::because(InternalError, "failed to build response header", e))?;

    for challenge in challenges {
        resp.append_header(http::header::WWW_AUTHENTICATE, challenge)
            .map_err(|e| {
                Error::because(InternalError, "failed to append WWW-Authenticate header", e)
            })?;
    }

    if let Some(nonce) = dpop_nonce {
        resp.insert_header("DPoP-Nonce", nonce)
            .map_err(|e| Error::because(InternalError, "failed to set DPoP-Nonce header", e))?;
    }

    resp.insert_header(http::header::CONTENT_LENGTH, 0)
        .map_err(|e| Error::because(InternalError, "failed to set content-length header", e))?;

    resp.insert_header(http::header::CACHE_CONTROL, "no-store")
        .map_err(|e| Error::because(InternalError, "failed to set cache-control header", e))?;

    session.write_response_header(Box::new(resp), true).await?;

    Ok(())
}

/// Writes a 405 Method Not Allowed response with an `Allow` header.
pub(crate) async fn write_method_not_allowed(
    session: &mut Session,
    allow: &str,
) -> Result<(), Box<Error>> {
    let mut resp = ResponseHeader::build(405, Some(3))
        .map_err(|e| Error::because(InternalError, "failed to build response header", e))?;

    resp.insert_header(http::header::ALLOW, allow)
        .map_err(|e| Error::because(InternalError, "failed to set Allow header", e))?;

    resp.insert_header(http::header::CONTENT_LENGTH, 0)
        .map_err(|e| Error::because(InternalError, "failed to set content-length header", e))?;

    resp.insert_header(http::header::CACHE_CONTROL, "no-store")
        .map_err(|e| Error::because(InternalError, "failed to set cache-control header", e))?;

    session.write_response_header(Box::new(resp), true).await?;

    Ok(())
}
