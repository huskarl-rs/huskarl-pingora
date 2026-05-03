use pingora_error::{Error, ErrorType::InternalError};
use pingora_http::ResponseHeader;
use pingora_proxy::Session;

/// Writes a JSON response with 200 OK and `content-type: application/json`.
pub(crate) async fn write_json_response(
    session: &mut Session,
    body: &[u8],
) -> Result<(), Box<Error>> {
    let mut resp = ResponseHeader::build(200, Some(2))
        .map_err(|e| Error::because(InternalError, "failed to build response header", e))?;

    resp.insert_header(http::header::CONTENT_TYPE, "application/json")
        .map_err(|e| {
            Error::because(InternalError, "failed to set content-type header", e)
        })?;

    resp.insert_header(http::header::CONTENT_LENGTH, body.len())
        .map_err(|e| {
            Error::because(InternalError, "failed to set content-length header", e)
        })?;

    session
        .write_response_header(Box::new(resp), false)
        .await?;

    session
        .write_response_body(Some(bytes::Bytes::copy_from_slice(body)), true)
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
    let mut resp =
        ResponseHeader::build(status.as_u16(), Some(challenges.len() + 1)).map_err(|e| {
            Error::because(InternalError, "failed to build response header", e)
        })?;

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

    session
        .write_response_header(Box::new(resp), true)
        .await?;

    Ok(())
}
