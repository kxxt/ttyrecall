use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::indexer::SearchResult;

use super::{session::require_session, state::AppState};

#[derive(Debug, Deserialize)]
pub(super) struct SearchQuery {
    q: Option<String>,
}

#[derive(Debug, Serialize)]
struct SearchResponse {
    results: Vec<SearchResult>,
}

pub(super) async fn search_recordings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> impl IntoResponse {
    let session = match require_session(&state, &headers).await {
        Ok(session) => session,
        Err(status) => return (status, "Not authenticated").into_response(),
    };

    let Some(search) = &state.search else {
        return (StatusCode::NOT_FOUND, "Search is disabled").into_response();
    };

    let query = query.q.unwrap_or_default();
    let query = query.trim();
    if query.is_empty() {
        return Json(SearchResponse {
            results: Vec::new(),
        })
        .into_response();
    }

    match search.search(session.uid, query).await {
        Ok(results) => Json(SearchResponse { results }).into_response(),
        Err(err) => {
            log::warn!("search failed: {err}");
            (StatusCode::BAD_GATEWAY, "Search failed").into_response()
        }
    }
}
