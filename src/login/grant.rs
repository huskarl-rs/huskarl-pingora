//! Authorization Code Grant abstraction.
//!
//! [`LoginGrant`] decouples [`LoginProxy`](super::LoginProxy) from the
//! concrete grant type. A blanket implementation is provided for
//! [`AuthorizationCodeGrant`](huskarl::grant::authorization_code::AuthorizationCodeGrant),
//! which automatically handles PAR, JAR, DPoP, and PKCE based on the grant's
//! own configuration.

use huskarl::{
    core::{
        BoxedError, client_auth::ClientAuthentication, dpop::AuthorizationServerDPoP,
        http::HttpClient,
    },
    grant::{
        authorization_code::{
            AuthorizationCodeGrant, CompleteInput, Jar, PendingState, StartInput, StartOutput,
        },
        core::{OAuth2ExchangeGrant, TokenResponse},
        refresh::RefreshGrantParameters,
    },
    token::RefreshToken,
};
use serde::{Deserialize, Serialize};

/// The result of a successful login completion.
///
/// Contains the token response and, when the authorization server returns an
/// ID token (OIDC), the validated identity claims extracted from it.
pub struct CompletedLogin {
    token_response: TokenResponse,
    id_claims: Option<IdClaims>,
}

impl CompletedLogin {
    /// Creates a `CompletedLogin` without ID token claims (non-OIDC flow).
    pub fn without_id_claims(token_response: TokenResponse) -> Self {
        Self {
            token_response,
            id_claims: None,
        }
    }

    /// Creates a `CompletedLogin` with validated ID token claims.
    pub fn with_id_claims(token_response: TokenResponse, id_claims: IdClaims) -> Self {
        Self {
            token_response,
            id_claims: Some(id_claims),
        }
    }

    /// Returns the token response.
    pub fn token_response(&self) -> &TokenResponse {
        &self.token_response
    }

    /// Returns the validated ID token claims, if present.
    pub fn id_claims(&self) -> Option<&IdClaims> {
        self.id_claims.as_ref()
    }

    /// Consumes the `CompletedLogin`, returning the token response and
    /// optional ID claims.
    pub fn into_parts(self) -> (TokenResponse, Option<IdClaims>) {
        (self.token_response, self.id_claims)
    }
}

/// Validated identity claims from the ID token.
///
/// These are the standard OIDC claims useful for session management:
/// subject identification, session binding, and authentication context.
pub struct IdClaims {
    /// Subject identifier — unique user ID at the issuer.
    pub sub: Option<String>,
    /// Session ID (`sid` claim) — used for frontchannel/backchannel logout.
    ///
    /// Per the OIDC Session Management spec, `sid` is an optional claim in the
    /// ID token that identifies a specific login session at the OP. When
    /// present, it enables per-session logout rather than blanket user-level
    /// logout.
    ///
    /// Extracted from the ID token's extra claims by serializing the grant's
    /// `Extra` type parameter and looking for a `"sid"` field. This works
    /// automatically with the default `HashMap<String, Value>` extra type,
    /// or any custom extra type that includes a `sid` field.
    pub sid: Option<String>,
    /// Authentication Context Class Reference.
    pub acr: Option<String>,
    /// Authentication Methods References.
    pub amr: Vec<String>,
    /// Authentication time (Unix timestamp).
    pub auth_time: Option<u64>,
}

/// Abstracts the Authorization Code Grant start/complete lifecycle.
///
/// Implementations handle PAR, JAR, DPoP, PKCE, and state/nonce generation
/// automatically. A blanket implementation is provided for
/// [`AuthorizationCodeGrant`].
pub trait LoginGrant: Send + Sync {
    fn start(
        &self,
        http_client: &impl HttpClient,
        scopes: Vec<String>,
    ) -> impl Future<Output = Result<StartOutput, BoxedError>> + Send;

    fn complete(
        &self,
        http_client: &impl HttpClient,
        pending_state: &PendingState,
        code: String,
        state: String,
        iss: Option<String>,
    ) -> impl Future<Output = Result<CompletedLogin, BoxedError>> + Send;

    fn refresh(
        &self,
        http_client: &impl HttpClient,
        refresh_token: &RefreshToken,
    ) -> impl Future<Output = Result<TokenResponse, BoxedError>> + Send;
}

impl<Auth, D, J, Extra> LoginGrant for AuthorizationCodeGrant<Auth, D, J, Extra>
where
    Auth: ClientAuthentication + Clone + Send + Sync + 'static,
    D: AuthorizationServerDPoP + Send + Sync + 'static,
    J: Jar + Send + Sync + 'static,
    Extra: Clone + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static,
{
    async fn start(
        &self,
        http_client: &impl HttpClient,
        scopes: Vec<String>,
    ) -> Result<StartOutput, BoxedError> {
        // The inherent start() takes StartInput; LoginGrant::start takes Vec<String>.
        // Different signatures mean self.start(...) unambiguously calls the inherent method.
        self.start(http_client, StartInput::scopes(scopes))
            .await
            .map_err(BoxedError::from_err)
    }

    async fn complete(
        &self,
        http_client: &impl HttpClient,
        pending_state: &PendingState,
        code: String,
        state: String,
        iss: Option<String>,
    ) -> Result<CompletedLogin, BoxedError> {
        // The inherent complete() takes CompleteInput; LoginGrant::complete takes individual
        // parameters — again, no ambiguity when calling self.complete(...).
        let input = match iss {
            Some(iss) => CompleteInput::builder()
                .code(code)
                .state(state)
                .iss(iss)
                .build(),
            None => CompleteInput::builder().code(code).state(state).build(),
        };
        let (token_response, validated_id_token) = self
            .complete_oidc(http_client, pending_state, input)
            .await
            .map_err(BoxedError::from_err)?;

        let id_claims = validated_id_token.map(|jwt| {
            // `sid` (OIDC Session Management) is not a standard IdTokenClaims
            // field — it lives in the flattened extra claims. Serialize the
            // Extra to Value to extract it regardless of the concrete type.
            let sid = serde_json::to_value(&jwt.claims.extra)
                .ok()
                .and_then(|v| v.get("sid")?.as_str().map(String::from));
            IdClaims {
                sub: jwt.subject,
                sid,
                acr: jwt.claims.acr,
                amr: jwt.claims.amr,
                auth_time: jwt.claims.auth_time,
            }
        });

        match id_claims {
            Some(claims) => Ok(CompletedLogin::with_id_claims(token_response, claims)),
            None => Ok(CompletedLogin::without_id_claims(token_response)),
        }
    }

    async fn refresh(
        &self,
        http_client: &impl HttpClient,
        refresh_token: &RefreshToken,
    ) -> Result<TokenResponse, BoxedError> {
        self.to_refresh_grant()
            .exchange(
                http_client,
                RefreshGrantParameters::refresh_token(refresh_token.clone()),
            )
            .await
            .map_err(BoxedError::from_err)
    }
}
