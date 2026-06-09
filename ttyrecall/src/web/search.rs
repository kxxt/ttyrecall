use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::search::{search_recordings, SearchResult};

use super::{session::require_session, state::AppState};

#[derive(Debug, Deserialize)]
pub(super) struct SearchQuery {
    q: String,
}

#[derive(Debug, Serialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
}

pub(super) async fn search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> impl IntoResponse {
    let session = match require_session(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return (status, "Not authenticated").into_response(),
    };

    if !state.search_enabled {
        return (StatusCode::NOT_FOUND, "Search is disabled").into_response();
    }

    let storage_root = state.storage_root.clone();
    let search_config = state.search.clone();
    let query = query.q;
    let result = tokio::task::spawn_blocking(move || {
        search_recordings(&storage_root, session.uid, &query, &search_config)
    })
    .await;

    match result {
        Ok(Ok(results)) => Json(SearchResponse { results }).into_response(),
        Ok(Err(err)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Search failed: {err}"),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Search task failed: {err}"),
        )
            .into_response(),
    }
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
    use crate::{
        catalog::RecordingIndex,
        search::RipgrepSearchConfig,
        web::{config::SingleUser, state::Session},
    };

    fn state(search_enabled: bool, ripgrep_path: &str) -> Arc<AppState> {
        Arc::new(AppState {
            storage_root: PathBuf::from("/tmp/ttyrecall-missing-search-root"),
            recording_index: Arc::new(StdRwLock::new(RecordingIndex::default())),
            pam_service: "login".to_string(),
            sessions: RwLock::new(HashMap::from([(
                "active".to_string(),
                Session {
                    username: "alice".to_string(),
                    uid: 1000,
                    last_seen: Instant::now(),
                },
            )])),
            session_ttl: Duration::from_secs(60),
            single_user: Some(SingleUser {
                uid: 1000,
                username: "alice".to_string(),
            }),
            frontend_root: PathBuf::from("/tmp/frontend"),
            single_user_token: Some("token".to_string()),
            cast_cache: tokio::sync::Mutex::new(super::super::state::CastCache::default()),
            search_enabled,
            search: RipgrepSearchConfig {
                ripgrep_path: ripgrep_path.to_string(),
                max_results: 50,
            },
        })
    }

    fn auth_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            "session=active".parse().unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn search_requires_authentication() {
        let response = search(
            State(state(true, "rg")),
            HeaderMap::new(),
            Query(SearchQuery {
                q: "hello".to_string(),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn search_returns_not_found_when_disabled() {
        let response = search(
            State(state(false, "rg")),
            auth_headers(),
            Query(SearchQuery {
                q: "hello".to_string(),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn search_returns_empty_results_when_user_root_is_missing() {
        let response = search(
            State(state(true, "rg")),
            auth_headers(),
            Query(SearchQuery {
                q: "hello".to_string(),
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(body["results"].as_array().unwrap().len(), 0);
    }
}
