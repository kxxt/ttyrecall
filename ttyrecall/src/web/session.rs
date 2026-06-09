use std::{sync::Arc, time::Instant};

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use constant_time_eq::constant_time_eq;
use nix::unistd::User;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::{
    pam,
    state::{AppState, Session},
};

#[derive(Debug, Deserialize)]
pub(super) struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct TokenLoginRequest {
    token: String,
}

#[derive(Debug, Serialize)]
struct MeResponse {
    username: String,
    uid: u32,
    search_enabled: bool,
}

pub(super) struct SessionInfo {
    pub(super) username: String,
    pub(super) uid: u32,
}

pub(super) async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    if state.single_user.is_some() {
        return (StatusCode::FORBIDDEN, "Use token login").into_response();
    }
    if payload.username.trim().is_empty() || payload.password.is_empty() {
        return (StatusCode::BAD_REQUEST, "Missing credentials").into_response();
    }

    match pam::authenticate(&state.pam_service, &payload.username, &payload.password) {
        Ok(()) => {}
        Err(_) => return (StatusCode::UNAUTHORIZED, "Authentication failed").into_response(),
    }

    let user =
        match User::from_name(&payload.username).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(Some(user)) => user,
            _ => return (StatusCode::UNAUTHORIZED, "Unknown user").into_response(),
        };

    create_session(&state, payload.username, user.uid.as_raw()).await
}

pub(super) async fn token_login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TokenLoginRequest>,
) -> impl IntoResponse {
    let single_user = match state.single_user.as_ref() {
        Some(single_user) => single_user,
        None => return (StatusCode::FORBIDDEN, "Not available").into_response(),
    };
    let token = match state.single_user_token.as_deref() {
        Some(token) => token,
        None => return (StatusCode::FORBIDDEN, "Not available").into_response(),
    };
    if !constant_time_eq(payload.token.as_bytes(), token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "Invalid token").into_response();
    }

    create_session(&state, single_user.username.clone(), single_user.uid).await
}

pub(super) async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(token) = session_token(&headers) {
        state.sessions.write().await.remove(&token);
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_static("session=; HttpOnly; Max-Age=0; Path=/"),
    );
    (StatusCode::OK, response_headers).into_response()
}

pub(super) async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    match require_session(&state, &headers).await {
        Ok(session) => Json(MeResponse {
            username: session.username,
            uid: session.uid,
            search_enabled: state.search_enabled,
        })
        .into_response(),
        Err(status) => (status, "Not authenticated").into_response(),
    }
}

async fn create_session(state: &AppState, username: String, uid: u32) -> Response {
    let token = new_session_token();
    let session = Session {
        username: username.clone(),
        uid,
        last_seen: Instant::now(),
    };
    state.sessions.write().await.insert(token.clone(), session);

    let cookie = format!("session={}; HttpOnly; SameSite=Strict; Path=/", token);
    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());

    (
        StatusCode::OK,
        headers,
        Json(MeResponse {
            username,
            uid,
            search_enabled: state.search_enabled,
        }),
    )
        .into_response()
}

pub(super) fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("session=") {
            return Some(value.to_string());
        }
    }
    None
}

pub(super) async fn require_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<SessionInfo, StatusCode> {
    let token = session_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let mut sessions = state.sessions.write().await;
    if let Some(session) = sessions.get_mut(&token) {
        if session.last_seen.elapsed() > state.session_ttl {
            sessions.remove(&token);
            return Err(StatusCode::UNAUTHORIZED);
        }
        session.last_seen = Instant::now();
        return Ok(SessionInfo {
            username: session.username.clone(),
            uid: session.uid,
        });
    }
    Err(StatusCode::UNAUTHORIZED)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, RwLock as StdRwLock},
        time::{Duration, Instant},
    };

    use axum::body::to_bytes;
    use serde_json::Value;
    use tokio::sync::RwLock;

    use super::*;
    use crate::{catalog::RecordingIndex, search::RipgrepSearchConfig};

    fn single_user_state(token: Option<&str>, ttl: Duration) -> Arc<AppState> {
        Arc::new(AppState::new(
            PathBuf::from("/tmp/ttyrecall"),
            Arc::new(StdRwLock::new(RecordingIndex::default())),
            "login".to_string(),
            ttl,
            Some(super::super::config::SingleUser {
                uid: 1000,
                username: "alice".to_string(),
            }),
            PathBuf::from("/tmp/frontend"),
            token.map(str::to_string),
            true,
            RipgrepSearchConfig {
                ripgrep_path: "rg".to_string(),
                max_results: 50,
            },
        ))
    }

    fn session_cookie_from(response: &Response) -> String {
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    async fn json_body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    #[test]
    fn session_token_reads_trimmed_cookie_parts() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; session=abc123; other=value"),
        );

        assert_eq!(session_token(&headers).as_deref(), Some("abc123"));
    }

    #[test]
    fn new_session_token_is_url_safe_and_unpadded() {
        let token = new_session_token();

        assert_eq!(token.len(), 43);
        assert!(!token.contains('='));
        assert!(token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'));
    }

    #[tokio::test]
    async fn token_login_creates_cookie_and_me_reads_session() {
        let state = single_user_state(Some("secret"), Duration::from_secs(60));

        let response = token_login(
            State(state.clone()),
            Json(TokenLoginRequest {
                token: "secret".to_string(),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let cookie = session_cookie_from(&response);
        let body = json_body(response).await;
        assert_eq!(body["username"], "alice");
        assert_eq!(body["uid"], 1000);
        assert_eq!(body["search_enabled"], true);

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
        let response = me(State(state), headers).await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["username"], "alice");
    }

    #[tokio::test]
    async fn token_login_rejects_bad_or_unavailable_tokens() {
        let state = single_user_state(Some("secret"), Duration::from_secs(60));
        let response = token_login(
            State(state.clone()),
            Json(TokenLoginRequest {
                token: "wrong".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let state = single_user_state(None, Duration::from_secs(60));
        let response = token_login(
            State(state),
            Json(TokenLoginRequest {
                token: "secret".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn require_session_rejects_missing_unknown_and_expired_sessions() {
        let state = single_user_state(Some("secret"), Duration::from_secs(1));
        assert_eq!(
            require_session(&state, &HeaderMap::new())
                .await
                .err()
                .unwrap(),
            StatusCode::UNAUTHORIZED
        );

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("session=missing"));
        assert_eq!(
            require_session(&state, &headers).await.err().unwrap(),
            StatusCode::UNAUTHORIZED
        );

        *state.sessions.write().await = HashMap::from([(
            "expired".to_string(),
            Session {
                username: "alice".to_string(),
                uid: 1000,
                last_seen: Instant::now() - Duration::from_secs(5),
            },
        )]);
        headers.insert(header::COOKIE, HeaderValue::from_static("session=expired"));

        assert_eq!(
            require_session(&state, &headers).await.err().unwrap(),
            StatusCode::UNAUTHORIZED
        );
        assert!(!state.sessions.read().await.contains_key("expired"));
    }

    #[tokio::test]
    async fn logout_removes_existing_session_and_clears_cookie() {
        let state = single_user_state(Some("secret"), Duration::from_secs(60));
        *state.sessions.write().await = HashMap::from([(
            "active".to_string(),
            Session {
                username: "alice".to_string(),
                uid: 1000,
                last_seen: Instant::now(),
            },
        )]);
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_static("session=active"));

        let response = logout(State(state.clone()), headers).await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!state.sessions.read().await.contains_key("active"));
        assert!(response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("Max-Age=0"));
    }

    #[tokio::test]
    async fn password_login_is_forbidden_in_single_user_mode_and_validates_inputs() {
        let single_user = single_user_state(Some("secret"), Duration::from_secs(60));
        let response = login(
            State(single_user),
            Json(LoginRequest {
                username: "alice".to_string(),
                password: "secret".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let state = Arc::new(AppState {
            storage_root: PathBuf::from("/tmp/ttyrecall"),
            recording_index: Arc::new(StdRwLock::new(RecordingIndex::default())),
            pam_service: "login".to_string(),
            sessions: RwLock::new(HashMap::new()),
            session_ttl: Duration::from_secs(60),
            single_user: None,
            frontend_root: PathBuf::from("/tmp/frontend"),
            single_user_token: None,
            cast_cache: tokio::sync::Mutex::new(super::super::state::CastCache::default()),
            search_enabled: false,
            search: RipgrepSearchConfig {
                ripgrep_path: "rg".to_string(),
                max_results: 50,
            },
        });

        let response = login(
            State(state),
            Json(LoginRequest {
                username: " ".to_string(),
                password: "secret".to_string(),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
