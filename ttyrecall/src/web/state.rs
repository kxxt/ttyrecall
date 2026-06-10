use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock as StdRwLock},
    time::{Duration, Instant, SystemTime},
};

use tokio::sync::RwLock;

use crate::{catalog::RecordingIndex, search::RipgrepSearchConfig};

use super::config::SingleUser;

#[derive(Debug)]
pub(super) struct Session {
    pub(super) username: String,
    pub(super) uid: u32,
    pub(super) last_seen: Instant,
}

#[derive(Debug)]
pub(super) struct LoginAttempt {
    pub(super) failures: u32,
    pub(super) last_failure: Instant,
    pub(super) locked_until: Option<Instant>,
}

#[derive(Debug)]
pub(super) struct AppState {
    pub(super) storage_root: PathBuf,
    pub(super) recording_index: Arc<StdRwLock<RecordingIndex>>,
    pub(super) pam_service: String,
    pub(super) sessions: RwLock<HashMap<String, Session>>,
    pub(super) login_attempts: RwLock<HashMap<String, LoginAttempt>>,
    pub(super) session_ttl: Duration,
    pub(super) single_user: Option<SingleUser>,
    pub(super) frontend_root: PathBuf,
    pub(super) single_user_token: Option<String>,
    pub(super) cast_cache: tokio::sync::Mutex<CastCache>,
    pub(super) search_enabled: bool,
    pub(super) search: RipgrepSearchConfig,
}

#[derive(Debug)]
pub(super) struct CastCacheEntry {
    pub(super) mtime: SystemTime,
    pub(super) bytes: Vec<u8>,
    pub(super) last_access: Instant,
}

#[derive(Debug, Default)]
pub(super) struct CastCache {
    pub(super) entries: HashMap<PathBuf, CastCacheEntry>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        storage_root: PathBuf,
        recording_index: Arc<StdRwLock<RecordingIndex>>,
        pam_service: String,
        session_ttl: Duration,
        single_user: Option<SingleUser>,
        frontend_root: PathBuf,
        single_user_token: Option<String>,
        search_enabled: bool,
        search: RipgrepSearchConfig,
    ) -> Self {
        Self {
            storage_root,
            recording_index,
            pam_service,
            sessions: RwLock::new(HashMap::new()),
            login_attempts: RwLock::new(HashMap::new()),
            session_ttl,
            single_user,
            frontend_root,
            single_user_token,
            cast_cache: tokio::sync::Mutex::new(CastCache::default()),
            search_enabled,
            search,
        }
    }
}

impl CastCache {
    pub(super) fn get(&mut self, path: &std::path::Path, mtime: SystemTime) -> Option<Vec<u8>> {
        if let Some(entry) = self.entries.get_mut(path) {
            if entry.mtime == mtime {
                entry.last_access = Instant::now();
                return Some(entry.bytes.clone());
            }
        }
        self.entries.remove(path);
        None
    }

    pub(super) fn insert(&mut self, path: PathBuf, mtime: SystemTime, bytes: Vec<u8>) {
        self.entries.insert(
            path,
            CastCacheEntry {
                mtime,
                bytes,
                last_access: Instant::now(),
            },
        );
        if self.entries.len() > super::recordings::CAST_CACHE_MAX_ENTRIES {
            self.evict_oldest();
        }
    }

    fn evict_oldest(&mut self) {
        if let Some((oldest, _)) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_access)
            .map(|(path, entry)| (path.clone(), entry.last_access))
        {
            self.entries.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_state_new_populates_runtime_fields() {
        let index = Arc::new(StdRwLock::new(RecordingIndex::default()));
        let search = RipgrepSearchConfig {
            ripgrep_path: "rg".to_string(),
            max_results: 25,
        };

        let state = AppState::new(
            PathBuf::from("/tmp/ttyrecall"),
            index.clone(),
            "login".to_string(),
            Duration::from_secs(30),
            Some(SingleUser {
                uid: 1000,
                username: "alice".to_string(),
            }),
            PathBuf::from("/tmp/frontend"),
            Some("token".to_string()),
            true,
            search.clone(),
        );

        assert_eq!(state.storage_root, PathBuf::from("/tmp/ttyrecall"));
        assert!(Arc::ptr_eq(&state.recording_index, &index));
        assert_eq!(state.pam_service, "login");
        assert_eq!(state.session_ttl, Duration::from_secs(30));
        assert_eq!(state.single_user.unwrap().username, "alice");
        assert_eq!(state.frontend_root, PathBuf::from("/tmp/frontend"));
        assert_eq!(state.single_user_token.as_deref(), Some("token"));
        assert!(state.search_enabled);
        assert_eq!(state.search.ripgrep_path, search.ripgrep_path);
        assert_eq!(state.search.max_results, search.max_results);
    }

    #[test]
    fn cast_cache_hits_only_when_mtime_matches() {
        let mut cache = CastCache::default();
        let path = PathBuf::from("/tmp/a.cast");
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1);

        cache.insert(path.clone(), mtime, b"first".to_vec());

        assert_eq!(cache.get(&path, mtime), Some(b"first".to_vec()));
        assert_eq!(
            cache.get(&path, SystemTime::UNIX_EPOCH + Duration::from_secs(2)),
            None
        );
        assert!(!cache.entries.contains_key(&path));
    }

    #[test]
    fn cast_cache_evicts_least_recently_used_entry() {
        let mut cache = CastCache::default();
        let mtime = SystemTime::UNIX_EPOCH;
        let first = PathBuf::from("/tmp/first.cast");
        cache.insert(first.clone(), mtime, b"first".to_vec());

        for i in 0..super::super::recordings::CAST_CACHE_MAX_ENTRIES {
            cache.insert(
                PathBuf::from(format!("/tmp/{i}.cast")),
                mtime,
                vec![i as u8],
            );
        }

        assert_eq!(
            cache.entries.len(),
            super::super::recordings::CAST_CACHE_MAX_ENTRIES
        );
        assert!(!cache.entries.contains_key(&first));
    }
}
