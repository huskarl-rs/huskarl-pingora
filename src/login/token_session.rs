//! Token lifetime introspection for sessions.
//!
//! [`TokenSession`] exposes the timing and token state that
//! [`LoginProxy`](super::LoginProxy) needs to enforce session policies (max
//! lifetime, idle timeout, token-bound expiry) and perform automatic token
//! refresh.
//!
//! [`TokenState`] holds the 6 common token/timing fields shared by all session
//! types. Session types embed `TokenState` and implement [`TokenSession`] with
//! two methods — [`token_state`](TokenSession::token_state) for reads and
//! [`set_token_state`](TokenSession::set_token_state) for replacement. All
//! other trait methods have default implementations.
//!
//! State is never mutated in place. Events like [`refreshed`](TokenState::refreshed)
//! and [`with_activity`](TokenState::with_activity) produce a new `TokenState`
//! value, which is then set back via the trait. This matches the
//! load→transform→save model required for distributed session stores.

use std::time::{Duration, SystemTime};

use huskarl::{
    grant::core::TokenResponse,
    token::{IdToken, RefreshToken},
};
use serde::{Deserialize, Serialize};

use super::serde_time::{option_unix_secs, unix_secs};

/// Common token and timing state shared by all session types.
///
/// This is an opaque value type — fields are not publicly accessible. Session
/// types embed it and implement [`TokenSession`] by providing read access and
/// a replacement method. State changes are produced by event methods
/// ([`refreshed`](Self::refreshed), [`with_activity`](Self::with_activity))
/// that return a new value rather than mutating in place.
#[derive(Clone, Serialize, Deserialize)]
pub struct TokenState {
    pub(crate) raw_token_response: serde_json::Value,
    #[serde(with = "option_unix_secs")]
    pub(crate) token_expiry: Option<SystemTime>,
    pub(crate) refresh_token: Option<RefreshToken>,
    pub(crate) id_token: Option<IdToken>,
    #[serde(with = "unix_secs")]
    pub(crate) created_at: SystemTime,
    #[serde(with = "unix_secs")]
    pub(crate) last_active: SystemTime,
}

impl TokenState {
    /// Creates a `TokenState` from a completed login, extracting token data
    /// and computing the token expiry from `expires_in`.
    pub(crate) fn from_completed(
        completed: &super::grant::CompletedLogin,
    ) -> Result<Self, serde_json::Error> {
        let now = SystemTime::now();
        let token_response = completed.token_response();
        let raw = serde_json::to_value(token_response.raw_token_response())?;
        let token_expiry = raw
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .map(|secs| now + Duration::from_secs(secs));

        Ok(Self {
            raw_token_response: raw,
            token_expiry,
            refresh_token: token_response.refresh_token().cloned(),
            id_token: token_response.id_token().cloned(),
            created_at: now,
            last_active: now,
        })
    }

    /// Produces a new `TokenState` with tokens updated from a refresh response.
    ///
    /// Replaces the raw token response and recomputes token expiry. If the
    /// refresh response includes a rotated refresh token, it replaces the old
    /// one; otherwise the existing refresh token is preserved.
    pub fn refreshed(&self, token_response: &TokenResponse) -> Self {
        let now = SystemTime::now();
        let mut new = self.clone();

        if let Ok(raw) = serde_json::to_value(token_response.raw_token_response()) {
            new.token_expiry = raw
                .get("expires_in")
                .and_then(|v| v.as_u64())
                .map(|s| now + Duration::from_secs(s));
            new.raw_token_response = raw;
        }

        if let Some(rt) = token_response.refresh_token() {
            new.refresh_token = Some(rt.clone());
        }

        new.last_active = now;
        new
    }

    /// Produces a new `TokenState` with the last-active timestamp set to now.
    pub fn with_activity(&self) -> Self {
        let mut new = self.clone();
        new.last_active = SystemTime::now();
        new
    }
}

/// Exposes token and timing state from a session so the proxy can enforce
/// lifetime policies (max lifetime, idle timeout, token-bound expiry) and
/// perform token refresh.
///
/// Implement this on the session type used with [`LoginProxy`](super::LoginProxy).
/// Only two methods are required — [`token_state`](Self::token_state) for
/// reads and [`set_token_state`](Self::set_token_state) for replacement. All
/// others have default implementations.
///
/// State is never mutated through interior references. Event methods produce
/// a new [`TokenState`] value and set it back via `set_token_state`, matching
/// the load→transform→save model needed for distributed session stores.
pub trait TokenSession {
    /// Returns a shared reference to the embedded [`TokenState`].
    fn token_state(&self) -> &TokenState;

    /// Replaces the embedded [`TokenState`] with a new value.
    fn set_token_state(&mut self, state: TokenState);

    /// Absolute expiry of the access token (`received_at + expires_in`).
    ///
    /// Returns `None` if the authorization server did not include `expires_in`.
    fn token_expiry(&self) -> Option<SystemTime> {
        self.token_state().token_expiry
    }

    /// The refresh token, if the authorization server issued one.
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.token_state().refresh_token.as_ref()
    }

    /// The ID token (identity assertion), if present.
    fn id_token(&self) -> Option<&IdToken> {
        self.token_state().id_token.as_ref()
    }

    /// When the session was created (initial login).
    fn created_at(&self) -> SystemTime {
        self.token_state().created_at
    }

    /// When the session was last active (last request that used this session).
    fn last_active(&self) -> SystemTime {
        self.token_state().last_active
    }

    /// The raw token response from the authorization server.
    fn raw_token_response(&self) -> &serde_json::Value {
        &self.token_state().raw_token_response
    }

    /// Apply tokens from a refresh response.
    ///
    /// Produces a new [`TokenState`] via [`TokenState::refreshed`] and sets it.
    fn apply_refresh(&mut self, token_response: &TokenResponse) {
        let new_state = self.token_state().refreshed(token_response);
        self.set_token_state(new_state);
    }

    /// Record that the session was active.
    ///
    /// Produces a new [`TokenState`] via [`TokenState::with_activity`] and sets it.
    fn record_activity(&mut self) {
        let new_state = self.token_state().with_activity();
        self.set_token_state(new_state);
    }
}
