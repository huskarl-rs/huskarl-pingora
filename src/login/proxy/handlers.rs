use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{StatusCode, header};
use huskarl::core::{
    crypto::cipher::{AeadSealer, AeadUnsealer},
    http::HttpClient,
};
use pingora_error::{Error, ErrorType::InternalError, Result};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use serde::Deserialize;

use super::{LoginProxy, LoginStateCookie, is_navigation_request};
use crate::login::{
    HasLoginSession,
    cookie::{get_cookie, login_state_cookie_name},
    grant::LoginGrant,
    session::SessionDriver,
    token_session::TokenSession,
    url::{build_end_session_url, default_post_logout_redirect, original_url},
};

// ── Error helpers ─────────────────────────────────────────────────────────────

pub(super) fn std_err(
    context: &'static str,
    e: impl std::error::Error + Send + Sync + 'static,
) -> Box<Error> {
    Error::because(InternalError, context, e)
}

pub(super) fn str_err(context: &'static str, msg: impl std::fmt::Display) -> Box<Error> {
    Error::explain(InternalError, format!("{context}: {msg}"))
}

// ── Core login logic ──────────────────────────────────────────────────────────

impl<P, G, SD, H> LoginProxy<P, G, SD, H>
where
    P: ProxyHttp + Send + Sync,
    P::CTX: HasLoginSession<SD::Session> + Send + Sync,
    G: LoginGrant + Send + Sync,
    SD: SessionDriver + Send + Sync,
    SD::Session: TokenSession,
    H: HttpClient + Send + Sync,
{
    /// Redirects to the authorization server and sets a login-state cookie.
    ///
    /// If `expired_session` is provided, the session is deleted (cookie
    /// cleared) on the same response so the browser forgets it.
    pub(super) async fn redirect_to_as(
        &self,
        session: &mut Session,
        expired_session: Option<&SD::Session>,
    ) -> Result<()> {
        let original_url =
            original_url(&self.config, &session.req_header().uri).unwrap_or_else(|| {
                let base = &self.config.base_url;
                let scheme = base.scheme_str().unwrap_or("https");
                let authority = base.authority().map(|a| a.as_str()).unwrap_or_default();
                format!("{scheme}://{authority}/")
            });

        let start = self
            .grant
            .start(&self.http_client, self.config.scopes.clone())
            .await
            .map_err(|e| Error::because(InternalError, "authorization request failed", e))?;

        let state = start.pending_state.state.clone();

        let payload = serde_json::to_vec(&LoginStateCookie {
            original_url,
            pending_state: start.pending_state,
        })
        .map_err(|e| str_err("failed to serialize login state", e))?;

        let bundle = self
            .sealer
            .seal(&payload, state.as_bytes())
            .await
            .map_err(|e| Error::because(InternalError, "failed to seal login state cookie", e))?;

        let cookie_name = login_state_cookie_name(
            &state,
            self.config.secure,
            &self.config.browser_callback_path,
        );
        let cookie_value = URL_SAFE_NO_PAD.encode(&bundle);

        let mut resp = ResponseHeader::build(StatusCode::FOUND, Some(2))
            .map_err(|e| std_err("failed to build redirect response", e))?;
        resp.insert_header(header::LOCATION, start.authorization_url.to_string())
            .map_err(|e| std_err("failed to set Location header", e))?;
        let secure = if self.config.secure { "; Secure" } else { "" };
        let callback_path = &self.config.browser_callback_path;
        resp.insert_header(
            header::SET_COOKIE,
            format!("{cookie_name}={cookie_value}; HttpOnly; SameSite=Lax; Path={callback_path}; Max-Age=600{secure}"),
        )
        .map_err(|e| std_err("failed to set login state cookie header", e))?;

        if let Some(s) = expired_session {
            self.session_store.delete(s, &mut resp).await.map_err(|e| {
                Error::because(InternalError, "failed to delete expired session", e)
            })?;
        }

        session.write_response_header(Box::new(resp), true).await?;
        Ok(())
    }

    /// Handles the authorization server callback.
    ///
    /// Validates the state cookie, exchanges the code, creates a session via
    /// the session store, clears the login-state cookie, saves the session,
    /// and redirects to the original URL.
    pub(super) async fn handle_callback(&self, session: &mut Session) -> Result<bool> {
        let uri = session.req_header().uri.clone();
        let query = uri.query().unwrap_or("");

        #[derive(Deserialize)]
        struct CallbackParams {
            code: Option<String>,
            state: Option<String>,
            iss: Option<String>,
            error: Option<String>,
            error_description: Option<String>,
        }
        let params: CallbackParams = serde_html_form::from_str(query).unwrap_or(CallbackParams {
            code: None,
            state: None,
            iss: None,
            error: None,
            error_description: None,
        });

        // Handle authorization server error responses (RFC 6749 §4.1.2.1).
        if let Some(error) = params.error {
            let message = match params.error_description {
                Some(desc) => format!("authorization denied: {desc}"),
                None => format!("authorization denied ({error})"),
            };
            return self
                .error_response(session, StatusCode::FORBIDDEN, &message, None)
                .await;
        }

        let (Some(code), Some(state), iss) = (params.code, params.state, params.iss) else {
            return self
                .error_response(
                    session,
                    StatusCode::BAD_REQUEST,
                    "missing code or state",
                    None,
                )
                .await;
        };

        // Locate and validate the login-state cookie.
        let cookie_name = login_state_cookie_name(
            &state,
            self.config.secure,
            &self.config.browser_callback_path,
        );
        let cookie_encoded = match get_cookie(&session.req_header().headers, &cookie_name) {
            Some(v) => v.to_owned(),
            None => {
                return self
                    .error_response(
                        session,
                        StatusCode::BAD_REQUEST,
                        "invalid or missing state",
                        None,
                    )
                    .await;
            }
        };

        // Decrypt and deserialize the cookie payload.
        let bundle = match URL_SAFE_NO_PAD.decode(&cookie_encoded) {
            Ok(b) => b,
            Err(_) => {
                return self
                    .error_response(
                        session,
                        StatusCode::BAD_REQUEST,
                        "malformed state cookie",
                        None,
                    )
                    .await;
            }
        };
        let plaintext = match self.unsealer.unseal(None, &bundle, state.as_bytes()).await {
            Ok(p) => p,
            Err(_) => {
                return self
                    .error_response(
                        session,
                        StatusCode::BAD_REQUEST,
                        "state cookie decryption failed",
                        None,
                    )
                    .await;
            }
        };
        let login_state: LoginStateCookie = match serde_json::from_slice(&plaintext) {
            Ok(s) => s,
            Err(_) => {
                return self
                    .error_response(
                        session,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "corrupt login state",
                        None,
                    )
                    .await;
            }
        };

        // Exchange the code for tokens.
        let completed_login = match self
            .grant
            .complete(
                &self.http_client,
                &login_state.pending_state,
                code,
                state,
                iss,
            )
            .await
        {
            Ok(cl) => cl,
            Err(e) => {
                log::error!("token exchange failed: {e}");
                return self
                    .error_response(
                        session,
                        StatusCode::BAD_GATEWAY,
                        "token exchange failed",
                        None,
                    )
                    .await;
            }
        };

        // Create a session from the completed login.
        let new_session = match self.session_store.create(completed_login).await {
            Ok(s) => s,
            Err(e) => {
                log::error!("failed to create session: {e}");
                return self
                    .error_response(
                        session,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to create session",
                        None,
                    )
                    .await;
            }
        };

        // Build the redirect response.
        let secure = if self.config.secure { "; Secure" } else { "" };
        let callback_path = &self.config.browser_callback_path;
        let clear_login = format!(
            "{cookie_name}=; HttpOnly; SameSite=Lax; Path={callback_path}; Max-Age=0{secure}"
        );

        let mut resp = ResponseHeader::build(StatusCode::FOUND, Some(3))
            .map_err(|e| std_err("failed to build callback redirect", e))?;
        resp.insert_header(header::LOCATION, &login_state.original_url)
            .map_err(|e| std_err("failed to set Location header", e))?;
        resp.insert_header(header::SET_COOKIE, &clear_login)
            .map_err(|e| std_err("failed to clear login cookie header", e))?;

        // Persist the session (appends Set-Cookie headers).
        if let Err(e) = self.session_store.save(&new_session, &mut resp).await {
            log::error!("failed to save session: {e}");
            return self
                .error_response(
                    session,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to save session",
                    None,
                )
                .await;
        }

        session.write_response_header(Box::new(resp), true).await?;
        Ok(true)
    }

    pub(super) async fn error_response(
        &self,
        session: &mut Session,
        status: StatusCode,
        message: &str,
        expired_session: Option<&SD::Session>,
    ) -> Result<bool> {
        let rendered = self.error_page.render(status, message);

        let mut resp = ResponseHeader::build(status, Some(2))
            .map_err(|e| std_err("failed to build error response", e))?;
        resp.insert_header(header::CONTENT_TYPE, rendered.content_type)
            .map_err(|e| std_err("failed to set content-type", e))?;
        resp.insert_header(header::CACHE_CONTROL, "no-store")
            .map_err(|e| std_err("failed to set cache-control", e))?;

        if let Some(s) = expired_session {
            self.session_store.delete(s, &mut resp).await.map_err(|e| {
                Error::because(InternalError, "failed to delete expired session", e)
            })?;
        }

        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(rendered.body), true)
            .await?;
        Ok(true)
    }

    /// Handles a logout request.
    ///
    /// Loads and deletes the current session, then redirects the browser:
    ///
    /// - If [`LoginConfig::end_session_endpoint`] is set: redirects there with
    ///   `id_token_hint` (when the session holds an ID token) and
    ///   `post_logout_redirect_uri` (when configured) as query parameters.
    /// - Otherwise: redirects to [`LoginConfig::post_logout_redirect_uri`], or
    ///   [`LoginConfig::base_url`] when that is also absent.
    pub(super) async fn handle_logout(&self, session: &mut Session) -> Result<bool> {
        // Load session — a missing or unreadable session is not an error here.
        let loaded_session = match self.session_store.load(&session.req_header().headers).await {
            Ok(s) => s,
            Err(e) => {
                log::warn!("failed to load session during logout: {e}");
                None
            }
        };

        let default_redirect;
        let post_logout = match self.config.post_logout_redirect_uri.as_deref() {
            Some(uri) => uri,
            None => {
                default_redirect = default_post_logout_redirect(&self.config);
                default_redirect.as_str()
            }
        };

        let redirect_target = match &self.config.end_session_endpoint {
            Some(endpoint) => {
                let id_token_hint = loaded_session
                    .as_ref()
                    .and_then(|s| s.id_token())
                    .map(|t| t.token());
                build_end_session_url(endpoint, id_token_hint, Some(post_logout))
                    .map_err(|e| str_err("failed to build end_session URL", e))?
            }
            None => post_logout.to_owned(),
        };

        let mut resp = ResponseHeader::build(StatusCode::FOUND, Some(3))
            .map_err(|e| std_err("failed to build logout response", e))?;
        resp.insert_header(header::LOCATION, &redirect_target)
            .map_err(|e| std_err("failed to set Location header on logout", e))?;
        resp.insert_header(header::CACHE_CONTROL, "no-store")
            .map_err(|e| std_err("failed to set Cache-Control header on logout", e))?;

        if let Some(ref s) = loaded_session {
            self.session_store.delete(s, &mut resp).await.map_err(|e| {
                Error::because(InternalError, "failed to delete session on logout", e)
            })?;
        }

        session.write_response_header(Box::new(resp), true).await?;
        Ok(true)
    }

    /// Expires a session: deletes it and redirects (navigation) or returns 401.
    pub(super) async fn expire_session(
        &self,
        session: &mut Session,
        expired: Option<&SD::Session>,
    ) -> Result<bool> {
        if is_navigation_request(session) {
            if let Err(e) = self.redirect_to_as(session, expired).await {
                log::error!("failed to redirect to authorization server: {e}");
                return self
                    .error_response(
                        session,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to start login",
                        None,
                    )
                    .await;
            }
            Ok(true)
        } else {
            self.error_response(
                session,
                StatusCode::UNAUTHORIZED,
                "session expired",
                expired,
            )
            .await
        }
    }
}
