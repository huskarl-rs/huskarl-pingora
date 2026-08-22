use pingora_proxy::Session;
use tokio::io::{AsyncWriteExt, DuplexStream};

use crate::{
    resource::scopes::HasScopes,
    resource_server::{
        error::{Challenge, ServerStatus, ToRfc6750Error, TokenErrorCode, TokenValidationError},
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

/// Why a [`MockError`] rejected. Each kind shapes the [`Challenge`] so the trait's own
/// `validation_outcome` derivation — the path a real validator takes — produces a
/// distinct classification for the guard to label.
///
/// `Expired` has no kind here: it is indistinguishable from `InvalidToken` in the
/// challenge, so only a validator that overrides `validation_outcome` reports it. That
/// mapping is covered by a direct unit test instead.
#[derive(Debug, Clone, Copy)]
pub(crate) enum MockErrorKind {
    /// A judged-and-rejected token: `invalid_token`.
    InvalidToken,
    /// Credentials could not be parsed out of the request headers.
    ExtractError,
    /// A `DPoP`/mTLS sender-constraint binding check failed.
    BindingError,
    /// A `DPoP` nonce is required; the client retries with the supplied one.
    NonceRequired,
    /// The resource server could not reach a backing service — a 5xx, not a token
    /// judgement. Carries the retry interval such a failure may supply.
    ServerError,
}

#[derive(Debug)]
pub(crate) struct MockError(pub(crate) MockErrorKind);

/// Counts how many times [`CountingError::challenge`] is called.
///
/// A `Challenge` owns its description and parameters, so building one per ingredient
/// clones them repeatedly on a path an attacker controls the rate of. The guard is
/// expected to build exactly one per rejection and read everything off it.
#[derive(Debug, Default)]
pub(crate) struct ChallengeCounter(pub(crate) std::sync::atomic::AtomicUsize);

impl ChallengeCounter {
    pub(crate) fn get(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// A [`MockError`] that tallies each `challenge()` call into a shared counter.
#[derive(Debug)]
pub(crate) struct CountingError(pub(crate) std::sync::Arc<ChallengeCounter>);

impl std::fmt::Display for CountingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("counting mock rejection")
    }
}

impl std::error::Error for CountingError {}

impl ToRfc6750Error for CountingError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }

    fn challenge(&self) -> Challenge {
        self.0.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Challenge::new(TokenValidationError::Client(TokenErrorCode::InvalidToken))
            .with_description("counting mock rejection")
    }
}

impl MockError {
    /// The retry interval a [`MockErrorKind::ServerError`] reports.
    pub(crate) const RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(42);

    /// The default rejection: a plain client `invalid_token`.
    pub(crate) const fn invalid_token() -> Self {
        Self(MockErrorKind::InvalidToken)
    }
}

impl std::fmt::Display for MockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mock rejection: {:?}", self.0)
    }
}

impl std::error::Error for MockError {}

impl ToRfc6750Error for MockError {
    fn attempted_scheme(&self) -> Option<TokenType> {
        None
    }

    fn challenge(&self) -> Challenge {
        let error = match self.0 {
            MockErrorKind::InvalidToken => {
                TokenValidationError::Client(TokenErrorCode::InvalidToken)
            }
            MockErrorKind::ExtractError => {
                TokenValidationError::Client(TokenErrorCode::InvalidRequest)
            }
            MockErrorKind::BindingError => {
                TokenValidationError::Client(TokenErrorCode::InvalidDPoPProof)
            }
            MockErrorKind::NonceRequired => {
                TokenValidationError::Client(TokenErrorCode::UseDPoPNonce)
            }
            MockErrorKind::ServerError => TokenValidationError::Server {
                status: ServerStatus::SERVICE_UNAVAILABLE,
                retry_after: Some(Self::RETRY_AFTER),
            },
        };
        Challenge::new(error).with_description("mock rejection")
    }
}

/// Convenience implementation for any validator built on [`MockClaims`]/[`MockError`].
pub(crate) fn mock_validator_metadata(resource: Option<&str>) -> ValidatorMetadata {
    ValidatorMetadata::builder()
        .maybe_resource(resource)
        .build()
}
