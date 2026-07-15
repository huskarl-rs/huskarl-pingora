use pingora_proxy::Session;
use tokio::io::{AsyncWriteExt, DuplexStream};

use crate::{
    resource::scopes::HasScopes,
    resource_server::{
        error::{ToRfc6750Error, TokenErrorCode, TokenValidationError},
        validator::{extract::TokenType, metadata::ValidatorMetadata},
    },
};

/// Builds a downstream [`Session`] from a raw request line plus `extra_headers`
/// (each `"Name: value\r\n"`). Returns the session and the client half of the
/// duplex stream, which must be kept alive until response writing completes.
pub(crate) async fn make_session_with_headers(
    method: &str,
    path: &str,
    extra_headers: &str,
) -> (Session, DuplexStream) {
    let raw = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{extra_headers}\r\n");
    let (mut client, server) = tokio::io::duplex(4096);
    client.write_all(raw.as_bytes()).await.unwrap();
    let mut session = Session::new_h1(Box::new(server));
    session.downstream_session.read_request().await.unwrap();
    (session, client)
}

/// [`make_session_with_headers`] with no extra headers.
pub(crate) async fn make_session(method: &str, path: &str) -> (Session, DuplexStream) {
    make_session_with_headers(method, path, "").await
}

#[derive(Debug, Clone)]
pub(crate) struct MockClaims {
    pub scopes: Option<String>,
}

impl HasScopes for MockClaims {
    fn has_scope(&self, scope: &str) -> bool {
        self.scopes
            .as_ref()
            .is_some_and(|s| s.split_whitespace().any(|t| t == scope))
    }
}

#[derive(Debug)]
pub(crate) struct MockError;

impl ToRfc6750Error for MockError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }
    fn token_error(&self) -> TokenValidationError {
        TokenValidationError::Client(TokenErrorCode::InvalidToken)
    }
    fn error_description(&self) -> Option<String> {
        Some("mock invalid token".into())
    }
}

/// Convenience implementation for any validator built on [`MockClaims`]/[`MockError`].
pub(crate) fn mock_validator_metadata(resource: Option<&str>) -> ValidatorMetadata {
    ValidatorMetadata::builder()
        .maybe_resource(resource)
        .build()
}
