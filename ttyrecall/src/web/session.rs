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
            search_enabled: state.search.is_some(),
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
            search_enabled: state.search.is_some(),
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
