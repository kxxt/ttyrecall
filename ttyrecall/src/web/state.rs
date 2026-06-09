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
pub(super) struct AppState {
    pub(super) storage_root: PathBuf,
    pub(super) recording_index: Arc<StdRwLock<RecordingIndex>>,
    pub(super) pam_service: String,
    pub(super) sessions: RwLock<HashMap<String, Session>>,
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
