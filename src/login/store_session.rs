//! External-store-backed session storage.
//!
//! [`StoreBackedSessionStore`] keeps an encrypted pointer cookie in the browser
//! and delegates actual session data to an [`ExternalSessionStore`] (Redis, a
//! database, etc.). The external store receives [`CoreSessionData`] on creation
//! and returns its own `Session` type, which may enrich the core data with
//! domain-specific fields.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use huskarl::core::crypto::cipher::{
    AeadSealer, AeadUnsealer, AeadV1Sealer, AeadV1Unsealer, BoxedAeadCipher,
};
use pingora_http::ResponseHeader;
use serde::{Deserialize, Serialize};

use super::{
    cookie::{cookie_attrs, get_cookie},
    session::{SessionDriver, to_session_err},
    token_session::{TokenSession, TokenState},
};

/// Trait for external session data stores (Redis, database, etc.).
///
/// This is the only trait users need to implement to use store-backed sessions.
/// The cookie mechanics (pointer cookie encryption, session key generation) are
/// handled by [`StoreBackedSessionStore`].
///
/// The associated [`Session`](Self::Session) type is what the proxy works with
/// after login. For the simplest case, use [`CoreSessionData`] directly. For
/// enriched sessions (e.g. with user profile data), define a custom type that
/// implements [`TokenSession`] and delegates to an embedded `CoreSessionData`.
pub trait ExternalSessionStore: Send + Sync {
    /// The session type returned by this store.
    ///
    /// Must implement [`TokenSession`] so the proxy can inspect token expiry,
    /// refresh tokens, etc.
    type Session: TokenSession + Send + Sync;

    /// The error type returned by store operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Extract the session key from a session.
    ///
    /// The session key is the random identifier stored (encrypted) in the
    /// browser's pointer cookie. The store must be able to extract it from
    /// its session type so that [`StoreBackedSessionStore`] can set the cookie.
    fn session_key(session: &Self::Session) -> &str;

    /// Create a new session from core OAuth data.
    ///
    /// Called after a successful OAuth callback. The store should persist the
    /// session and return its (possibly enriched) session type.
    fn create(
        &self,
        core: CoreSessionData,
    ) -> impl Future<Output = Result<Self::Session, Self::Error>> + Send;

    /// Load a session by its key. Returns `None` if the key does not exist.
    fn load(
        &self,
        session_key: &str,
    ) -> impl Future<Output = Result<Option<Self::Session>, Self::Error>> + Send;

    /// Save a session. Called when the session has been mutated (e.g. after a
    /// token refresh).
    fn save(&self, session: &Self::Session)
    -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Extend the TTL of a session without rewriting data.
    ///
    /// Called on every authenticated request that doesn't trigger a full save.
    /// Implementations may choose to no-op or throttle this.
    fn touch(
        &self,
        session: &Self::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Delete a session.
    fn delete(
        &self,
        session: &Self::Session,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Core session data produced by the OAuth flow.
///
/// Contains the session key, token data, and timing fields that the proxy
/// needs. This is passed to [`ExternalSessionStore::create`] after a
/// successful login.
///
/// For simple stores that don't need to enrich sessions, use
/// `CoreSessionData` directly as your [`ExternalSessionStore::Session`] type.
///
/// For enriched sessions, embed this in your custom session type and delegate
/// the [`TokenSession`] methods to it.
#[derive(Serialize, Deserialize)]
pub struct CoreSessionData {
    session_key: String,
    sub: Option<String>,
    sid: Option<String>,
    #[serde(flatten)]
    state: TokenState,
}

impl CoreSessionData {
    /// The random session key used as the primary lookup key in the external store.
    pub fn session_key(&self) -> &str {
        &self.session_key
    }

    /// The subject identifier (`sub` claim) from the ID token, if present.
    ///
    /// Useful for indexing sessions by user (e.g. "list all sessions for this
    /// user" or "revoke all sessions for user X").
    pub fn sub(&self) -> Option<&str> {
        self.sub.as_deref()
    }

    /// The session identifier (`sid` claim) from the ID token, if present.
    ///
    /// Used for frontchannel and backchannel logout — the authorization server
    /// sends a `sid` to identify which session to terminate.
    pub fn sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    /// Consumes the `CoreSessionData`, returning its parts for enriched session
    /// construction.
    pub fn into_parts(self) -> (String, Option<String>, Option<String>, TokenState) {
        (self.session_key, self.sub, self.sid, self.state)
    }
}

impl TokenSession for CoreSessionData {
    fn token_state(&self) -> &TokenState {
        &self.state
    }
    fn set_token_state(&mut self, state: TokenState) {
        self.state = state;
    }
}

/// Generates a time-ordered session key using UUID v7.
///
/// UUID v7 provides millisecond-precision timestamps in the high bits,
/// giving natural sort order for database indexes while retaining 74 bits
/// of cryptographic randomness.
fn generate_session_key() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// A session store that keeps an encrypted pointer cookie in the browser and
/// stores session data in an external [`ExternalSessionStore`].
///
/// The pointer cookie contains the encrypted session key (a random string).
/// The actual session data is stored via the external store, which receives
/// [`CoreSessionData`] on creation and returns its own session type.
pub struct StoreBackedSessionStore<E> {
    external: E,
    sealer: AeadV1Sealer<BoxedAeadCipher>,
    unsealer: AeadV1Unsealer<BoxedAeadCipher>,
    cookie_name: String,
    secure: bool,
    cookie_path: String,
}

impl<E: ExternalSessionStore> StoreBackedSessionStore<E> {
    /// Creates a new store-backed session store.
    ///
    /// - `external` — the external store implementation (Redis, DB, etc.)
    /// - `cipher` — AEAD cipher for encrypting/decrypting the pointer cookie
    /// - `cookie_name` — name of the pointer cookie
    /// - `secure` — whether to set the `Secure` cookie attribute
    /// - `cookie_path` — the `Path` cookie attribute
    pub fn new(
        external: E,
        cipher: BoxedAeadCipher,
        cookie_name: impl Into<String>,
        secure: bool,
        cookie_path: impl Into<String>,
    ) -> Self {
        Self {
            external,
            sealer: AeadV1Sealer::new(cipher.clone()),
            unsealer: AeadV1Unsealer::new(cipher),
            cookie_name: cookie_name.into(),
            secure,
            cookie_path: cookie_path.into(),
        }
    }

    fn cookie_attrs(&self) -> String {
        cookie_attrs(self.secure, &self.cookie_path)
    }

    /// Encrypt and set the pointer cookie.
    async fn set_pointer_cookie(
        &self,
        session_key: &str,
        response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        let bundle = self
            .sealer
            .seal(session_key.as_bytes(), b"session_ptr")
            .await
            .map_err(to_session_err)?;
        let cookie_value = URL_SAFE_NO_PAD.encode(&bundle);
        let attrs = self.cookie_attrs();
        response
            .append_header(
                http::header::SET_COOKIE,
                format!("{}={cookie_value}; {attrs}", self.cookie_name),
            )
            .map_err(to_session_err)?;
        Ok(())
    }

    /// Read and decrypt the pointer cookie to get the session key.
    async fn read_pointer_cookie(&self, headers: &http::HeaderMap) -> Option<String> {
        let encoded = get_cookie(headers, &self.cookie_name)?;
        let bundle = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        let plaintext = self
            .unsealer
            .unseal(None, &bundle, b"session_ptr")
            .await
            .ok()?;
        String::from_utf8(plaintext).ok()
    }
}

// ── Internal methods used by SessionDriver impl ──────────────────────────────

impl<E: ExternalSessionStore> StoreBackedSessionStore<E> {
    pub(crate) async fn create_session(
        &self,
        completed: &super::grant::CompletedLogin,
    ) -> Result<E::Session, super::session::SessionError> {
        let state = TokenState::from_completed(completed)?;
        let session_key = generate_session_key();

        // Extract sub/sid from validated ID token claims.
        let (sub, sid) = match completed.id_claims() {
            Some(claims) => (claims.sub.clone(), claims.sid.clone()),
            None => (None, None),
        };

        let core = CoreSessionData {
            session_key,
            sub,
            sid,
            state,
        };

        self.external
            .create(core)
            .await
            .map_err(to_session_err)
    }

    pub(crate) async fn load_session(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<Option<E::Session>, E::Error> {
        let Some(session_key) = self.read_pointer_cookie(headers).await else {
            return Ok(None);
        };

        self.external.load(&session_key).await
    }

    pub(crate) async fn save_session(
        &self,
        session: &E::Session,
        response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        self.external
            .save(session)
            .await
            .map_err(to_session_err)?;
        self.set_pointer_cookie(E::session_key(session), response)
            .await?;
        Ok(())
    }

    pub(crate) async fn touch_session(
        &self,
        session: &E::Session,
        _response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        self.external
            .touch(session)
            .await
            .map_err(to_session_err)?;
        Ok(())
    }

    pub(crate) async fn delete_session(
        &self,
        session: &E::Session,
        response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        self.external
            .delete(session)
            .await
            .map_err(to_session_err)?;
        // Clear the pointer cookie.
        let attrs = self.cookie_attrs();
        let _ = response.append_header(
            http::header::SET_COOKIE,
            format!("{}=; {attrs}; Max-Age=0", self.cookie_name),
        );
        Ok(())
    }
}

impl<E: ExternalSessionStore> super::session::sealed::Sealed for StoreBackedSessionStore<E> {}

impl<E: ExternalSessionStore> SessionDriver for StoreBackedSessionStore<E> {
    type Session = E::Session;
    type LoadError = E::Error;

    async fn create(
        &self,
        completed: super::grant::CompletedLogin,
    ) -> Result<E::Session, super::session::SessionError> {
        self.create_session(&completed).await
    }

    async fn load(&self, headers: &http::HeaderMap) -> Result<Option<E::Session>, E::Error> {
        self.load_session(headers).await
    }

    async fn save(
        &self,
        session: &E::Session,
        response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        self.save_session(session, response).await
    }

    async fn touch(
        &self,
        session: &E::Session,
        response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        self.touch_session(session, response).await
    }

    async fn delete(
        &self,
        session: &E::Session,
        response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        self.delete_session(session, response).await
    }
}
