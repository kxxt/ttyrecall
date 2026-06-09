use std::{path::PathBuf, sync::Arc};

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
};

use super::state::AppState;

pub(super) async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    serve_html(state.frontend_root.join("index.html")).await
}

pub(super) async fn view(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    serve_html(state.frontend_root.join("view.html")).await
}

async fn serve_html(path: PathBuf) -> impl IntoResponse {
    match tokio::fs::read_to_string(&path).await {
        Ok(html) => Html(html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Not found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{Arc, RwLock as StdRwLock},
        time::Duration,
    };

    use axum::{body::to_bytes, http::header};

    use super::*;
    use crate::{catalog::RecordingIndex, search::RipgrepSearchConfig};

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("ttyrecall-web-pages-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn state(frontend_root: PathBuf) -> Arc<AppState> {
        Arc::new(AppState::new(
            PathBuf::from("/tmp/storage"),
            Arc::new(StdRwLock::new(RecordingIndex::default())),
            "login".to_string(),
            Duration::from_secs(60),
            None,
            frontend_root,
            None,
            false,
            RipgrepSearchConfig {
                ripgrep_path: "rg".to_string(),
                max_results: 50,
            },
        ))
    }

    #[tokio::test]
    async fn serve_html_returns_html_or_not_found() {
        let root = temp_root("serve");
        let page = root.join("index.html");
        tokio::fs::write(&page, "<html>ttyrecall</html>")
            .await
            .unwrap();

        let response = serve_html(page).await.into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/html"));
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"<html>ttyrecall</html>");

        let response = serve_html(root.join("missing.html")).await.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn index_and_view_serve_expected_frontend_files() {
        let root = temp_root("routes");
        tokio::fs::write(root.join("index.html"), "index")
            .await
            .unwrap();
        tokio::fs::write(root.join("view.html"), "view")
            .await
            .unwrap();
        let state = state(root.clone());

        let index_response = index(State(state.clone())).await.into_response();
        let view_response = view(State(state)).await.into_response();

        assert_eq!(
            &to_bytes(index_response.into_body(), usize::MAX)
                .await
                .unwrap()[..],
            b"index"
        );
        assert_eq!(
            &to_bytes(view_response.into_body(), usize::MAX)
                .await
                .unwrap()[..],
            b"view"
        );

        let _ = std::fs::remove_dir_all(root);
    }
}
