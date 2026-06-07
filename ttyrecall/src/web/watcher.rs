use std::{
    path::{Path, PathBuf},
    sync::{Arc, RwLock as StdRwLock},
};

use crate::{catalog::RecordingIndex, watcher::RecordingEventHandler};

#[derive(Debug)]
struct CatalogRecordingHandler {
    storage_root: PathBuf,
    index: Arc<StdRwLock<RecordingIndex>>,
}

impl RecordingEventHandler for CatalogRecordingHandler {
    fn clear(&mut self) {
        self.index.write().unwrap().clear();
    }

    fn upsert_file(&mut self, path: &Path) {
        self.index
            .write()
            .unwrap()
            .upsert_path(&self.storage_root, path);
    }

    fn remove_file(&mut self, path: &Path) {
        self.index
            .write()
            .unwrap()
            .remove_path(&self.storage_root, path);
    }

    fn remove_tree(&mut self, path: &Path) {
        self.index
            .write()
            .unwrap()
            .remove_tree(&self.storage_root, path);
    }
}

pub(super) fn spawn_recording_watcher(
    storage_root: PathBuf,
    scan_roots: Vec<PathBuf>,
    index: Arc<StdRwLock<RecordingIndex>>,
) -> color_eyre::Result<()> {
    crate::watcher::spawn_recording_watcher(
        scan_roots,
        CatalogRecordingHandler {
            storage_root,
            index,
        },
        "ttyrecall-inotify",
    )
}
