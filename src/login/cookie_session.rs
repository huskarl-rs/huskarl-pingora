//! Cookie-based session storage.
//!
//! [`CookieSessionStore`] encrypts the entire session into chunked browser
//! cookies using AEAD, so no server-side session store is needed. Large
//! payloads are automatically split across multiple cookies (`.0`, `.1`, …)
//! to stay within browser size limits.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use huskarl::core::crypto::cipher::{
    AeadSealer, AeadUnsealer, AeadV1Sealer, AeadV1Unsealer, BoxedAeadCipher,
};
use pingora_http::ResponseHeader;
use serde::{Deserialize, Serialize};

use super::{
    cookie::cookie_attrs,
    session::{SessionDriver, to_session_err},
    token_session::{TokenSession, TokenState},
};

const CHUNK_SIZE: usize = 3800;
const MAX_CHUNKS: usize = 10;

/// A session that stores token state encrypted in browser cookies.
///
/// This is the session type used with [`CookieSessionStore`]. It is a
/// transparent newtype over [`TokenState`], so existing encrypted cookies
/// deserialize correctly.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct CookieSession(TokenState);

impl TokenSession for CookieSession {
    fn token_state(&self) -> &TokenState {
        &self.0
    }
    fn set_token_state(&mut self, state: TokenState) {
        self.0 = state;
    }
}

/// A built-in session store that encrypts session data into chunked cookies.
///
/// Large payloads are automatically split across multiple cookies (`.0`, `.1`,
/// etc.) to stay within browser cookie size limits. Decryption failure is
/// treated as "no session" rather than an error.
///
/// # Cookie format
///
/// - Cookie name: `{name}.0`, `{name}.1`, etc.
/// - Chunk 0 value: `{count}:{base64_data}` where count is the total number of chunks
/// - Other chunks: raw base64 continuation
/// - Attributes: `HttpOnly; SameSite=Lax; Path={path}` plus optional `Secure`
pub struct CookieSessionStore {
    sealer: AeadV1Sealer<BoxedAeadCipher>,
    unsealer: AeadV1Unsealer<BoxedAeadCipher>,
    cookie_name: String,
    secure: bool,
    cookie_path: String,
}

impl CookieSessionStore {
    /// Creates a new cookie session store.
    ///
    /// - `cipher` — AEAD cipher for encrypting/decrypting session data
    /// - `cookie_name` — base name for the session cookies (e.g. `"huskarl_session"`)
    /// - `secure` — whether to set the `Secure` cookie attribute
    /// - `cookie_path` — the `Path` cookie attribute (e.g. `"/"`)
    pub fn new(
        cipher: BoxedAeadCipher,
        cookie_name: impl Into<String>,
        secure: bool,
        cookie_path: impl Into<String>,
    ) -> Self {
        Self {
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
}

// ── Internal methods used by SessionDriver impl ──────────────────────────────

impl CookieSessionStore {
    pub(crate) fn create_session(
        completed: &super::grant::CompletedLogin,
    ) -> Result<CookieSession, super::session::SessionError> {
        Ok(CookieSession(TokenState::from_completed(completed)?))
    }

    pub(crate) async fn load_session(&self, headers: &http::HeaderMap) -> Option<CookieSession> {
        let mut chunks: std::collections::HashMap<usize, String> = std::collections::HashMap::new();

        for value in headers.get_all(http::header::COOKIE) {
            let Ok(s) = value.to_str() else { continue };
            for pair in s.split(';') {
                if let Some((k, v)) = pair.trim().split_once('=') {
                    let k = k.trim();
                    if let Some(suffix) = k.strip_prefix(&self.cookie_name)
                        && let Some(num_str) = suffix.strip_prefix('.')
                        && let Ok(num) = num_str.parse::<usize>()
                    {
                        chunks.insert(num, v.trim().to_string());
                    }
                }
            }
        }

        let chunk0 = chunks.get(&0)?;
        let (count_str, data0) = chunk0.split_once(':')?;
        let count = count_str.parse::<usize>().ok()?;

        let mut raw_encoded = data0.to_string();
        for i in 1..count {
            raw_encoded.push_str(chunks.get(&i)?);
        }

        let bundle = URL_SAFE_NO_PAD.decode(&raw_encoded).ok()?;
        let plaintext = self.unsealer.unseal(None, &bundle, b"session").await.ok()?;
        serde_json::from_slice(&plaintext).ok()
    }

    pub(crate) async fn save_session(
        &self,
        session: &CookieSession,
        response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        let payload = serde_json::to_vec(session)?;
        let bundle = self
            .sealer
            .seal(&payload, b"session")
            .await
            .map_err(to_session_err)?;

        let cookie_value = URL_SAFE_NO_PAD.encode(&bundle);
        let chunks: Vec<&str> = cookie_value
            .as_bytes()
            .chunks(CHUNK_SIZE)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();

        let num_chunks = chunks.len();
        if num_chunks > MAX_CHUNKS {
            return Err(format!(
                "session payload too large: requires {num_chunks} chunks (max {MAX_CHUNKS})"
            )
            .into());
        }

        let attrs = self.cookie_attrs();
        for (i, chunk) in chunks.iter().enumerate() {
            let val = if i == 0 {
                format!("{num_chunks}:{chunk}")
            } else {
                chunk.to_string()
            };
            response
                .append_header(
                    http::header::SET_COOKIE,
                    format!("{}.{i}={val}; {attrs}", self.cookie_name),
                )
                .map_err(to_session_err)?;
        }
        // Clear leftover chunks from a previously larger session.
        for i in num_chunks..MAX_CHUNKS {
            let _ = response.append_header(
                http::header::SET_COOKIE,
                format!("{}.{i}=; {attrs}; Max-Age=0", self.cookie_name),
            );
        }
        // Clear the old base name in case it was left over from a previous version.
        let _ = response.append_header(
            http::header::SET_COOKIE,
            format!("{}=; {attrs}; Max-Age=0", self.cookie_name),
        );

        Ok(())
    }

    pub(crate) async fn delete_session(
        &self,
        response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        let attrs = self.cookie_attrs();
        let _ = response.append_header(
            http::header::SET_COOKIE,
            format!("{}=; {attrs}; Max-Age=0", self.cookie_name),
        );
        for i in 0..MAX_CHUNKS {
            let _ = response.append_header(
                http::header::SET_COOKIE,
                format!("{}.{i}=; {attrs}; Max-Age=0", self.cookie_name),
            );
        }
        Ok(())
    }
}

impl super::session::sealed::Sealed for CookieSessionStore {}

impl SessionDriver for CookieSessionStore {
    type Session = CookieSession;
    type LoadError = std::convert::Infallible;

    async fn create(
        &self,
        completed: super::grant::CompletedLogin,
    ) -> Result<CookieSession, super::session::SessionError> {
        Self::create_session(&completed)
    }

    async fn load(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<Option<CookieSession>, std::convert::Infallible> {
        Ok(self.load_session(headers).await)
    }

    async fn save(
        &self,
        session: &CookieSession,
        response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        self.save_session(session, response).await
    }

    async fn touch(
        &self,
        _session: &CookieSession,
        _response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        Ok(()) // Cookie sessions don't need touch — no server-side TTL.
    }

    async fn delete(
        &self,
        _session: &CookieSession,
        response: &mut ResponseHeader,
    ) -> Result<(), super::session::SessionError> {
        self.delete_session(response).await
    }
}
