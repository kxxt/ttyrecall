use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{Arc, RwLock as StdRwLock},
};

use color_eyre::eyre::Context;
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use log::{error, warn};

use crate::catalog::RecordingIndex;

#[derive(Debug)]
struct RecordingWatcher {
    storage_root: PathBuf,
    scan_roots: Vec<PathBuf>,
    index: Arc<StdRwLock<RecordingIndex>>,
    inotify: Inotify,
    watch_paths: std::collections::HashMap<PathBuf, WatchDescriptor>,
    watched_dirs: std::collections::HashMap<WatchDescriptor, PathBuf>,
}

impl RecordingWatcher {
    fn new(
        storage_root: PathBuf,
        scan_roots: Vec<PathBuf>,
        index: Arc<StdRwLock<RecordingIndex>>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            storage_root,
            scan_roots,
            index,
            inotify: Inotify::init()?,
            watch_paths: std::collections::HashMap::new(),
            watched_dirs: std::collections::HashMap::new(),
        })
    }

    fn rebuild(&mut self) -> color_eyre::Result<()> {
        self.inotify = Inotify::init().with_context(|| "failed to init inotify")?;
        self.watch_paths.clear();
        self.watched_dirs.clear();
        self.index.write().unwrap().clear();
        for root in self.scan_roots.clone() {
            match self.scan_dir_recursive(root) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    fn run(&mut self) -> color_eyre::Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let events = self.inotify.read_events_blocking(&mut buffer)?;
            let events: Vec<_> = events.map(|event| event.to_owned()).collect();
            for event in events {
                self.handle_event(event)?;
            }
        }
    }

    fn handle_event(&mut self, event: inotify::Event<OsString>) -> color_eyre::Result<()> {
        if event.mask.contains(EventMask::Q_OVERFLOW) {
            warn!("recording watcher queue overflowed; rebuilding index");
            return self.rebuild();
        }

        if event.mask.contains(EventMask::IGNORED) {
            if let Some(path) = self.watched_dirs.remove(&event.wd) {
                self.watch_paths.remove(&path);
            }
            return Ok(());
        }

        if event.mask.contains(EventMask::UNMOUNT) {
            warn!("recording storage was unmounted; rebuilding index");
            return self.rebuild();
        }

        let Some(parent) = self.watched_dirs.get(&event.wd).cloned() else {
            return Ok(());
        };

        if event.mask.contains(EventMask::MOVE_SELF) {
            return self.rebuild();
        }

        let Some(name) = event.name else {
            return Ok(());
        };
        let path = parent.join(name);

        if event.mask.contains(EventMask::ISDIR) {
            return self.handle_dir_event(path, event.mask);
        }

        self.handle_file_event(path, event.mask);
        Ok(())
    }

    fn handle_dir_event(&mut self, path: PathBuf, mask: EventMask) -> color_eyre::Result<()> {
        if mask.intersects(EventMask::MOVED_FROM | EventMask::MOVED_TO) {
            return self.rebuild();
        }

        if mask.contains(EventMask::CREATE) {
            return match self.scan_dir_recursive(path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err.into()),
            };
        }

        if mask.intersects(EventMask::DELETE | EventMask::DELETE_SELF) {
            self.index
                .write()
                .unwrap()
                .remove_tree(&self.storage_root, &path);
        }

        Ok(())
    }

    fn handle_file_event(&mut self, path: PathBuf, mask: EventMask) {
        if mask.intersects(
            EventMask::CREATE | EventMask::MOVED_TO | EventMask::CLOSE_WRITE | EventMask::ATTRIB,
        ) {
            self.index
                .write()
                .unwrap()
                .upsert_path(&self.storage_root, &path);
        }

        if mask.intersects(EventMask::DELETE | EventMask::MOVED_FROM) {
            self.index
                .write()
                .unwrap()
                .remove_path(&self.storage_root, &path);
        }
    }

    fn scan_dir_recursive(&mut self, dir: PathBuf) -> std::io::Result<()> {
        self.watch_dir(&dir)?;

        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                warn!(
                    "failed to read recording directory {}: {err}",
                    dir.display()
                );
                return Ok(());
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!("failed to read recording directory entry: {err}");
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(err) => {
                    warn!(
                        "failed to read recording entry type {}: {err}",
                        path.display()
                    );
                    continue;
                }
            };

            if file_type.is_dir() {
                self.scan_dir_recursive(path)?;
            } else if file_type.is_file() {
                self.index
                    .write()
                    .unwrap()
                    .upsert_path(&self.storage_root, &path);
            }
        }

        Ok(())
    }

    fn watch_dir(&mut self, dir: &Path) -> std::io::Result<()> {
        if self.watch_paths.contains_key(dir) {
            return Ok(());
        }

        let watch = self.inotify.watches().add(
            dir,
            WatchMask::CREATE
                | WatchMask::DELETE
                | WatchMask::MOVED_FROM
                | WatchMask::MOVED_TO
                | WatchMask::CLOSE_WRITE
                | WatchMask::ATTRIB
                | WatchMask::DELETE_SELF
                | WatchMask::MOVE_SELF
                | WatchMask::ONLYDIR,
        )?;

        self.watch_paths.insert(dir.to_path_buf(), watch.clone());
        self.watched_dirs.insert(watch, dir.to_path_buf());
        Ok(())
    }
}

pub(super) fn spawn_recording_watcher(
    storage_root: PathBuf,
    scan_roots: Vec<PathBuf>,
    index: Arc<StdRwLock<RecordingIndex>>,
) -> color_eyre::Result<()> {
    let mut watcher = RecordingWatcher::new(storage_root, scan_roots, index)?;
    watcher.rebuild()?;
    std::thread::Builder::new()
        .name("ttyrecall-inotify".to_string())
        .spawn(move || {
            if let Err(err) = watcher.run() {
                error!("recording watcher stopped: {err}");
            }
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::{Arc, RwLock as StdRwLock},
    };

    use crate::catalog::RecordingIndex;

    use super::RecordingWatcher;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("ttyrecall-watcher-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn single_user_rebuild_does_not_watch_other_user_dirs() {
        let root = temp_root("single-user-scope");
        let user_dir = root.join("1000/2026/06/06");
        let other_dir = root.join("1001");
        fs::create_dir_all(&user_dir).unwrap();
        fs::create_dir_all(&other_dir).unwrap();
        fs::set_permissions(&other_dir, fs::Permissions::from_mode(0o000)).unwrap();

        let index = Arc::new(StdRwLock::new(RecordingIndex::default()));
        let mut watcher =
            RecordingWatcher::new(root.clone(), vec![root.join("1000")], index).unwrap();

        let result = watcher.rebuild();

        fs::set_permissions(&other_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert!(result.is_ok());
        assert!(watcher
            .watch_paths
            .keys()
            .all(|path| path.starts_with(root.join("1000"))));
    }

    #[test]
    fn missing_single_user_dir_rebuilds_as_empty_index() {
        let root = temp_root("missing-user-dir");
        let index = Arc::new(StdRwLock::new(RecordingIndex::default()));
        let mut watcher =
            RecordingWatcher::new(root.clone(), vec![root.join("1000")], index.clone()).unwrap();

        watcher.rebuild().unwrap();

        assert!(watcher.watch_paths.is_empty());
        assert!(index.read().unwrap().list_for_user(1000).is_empty());

        fs::remove_dir_all(&root).unwrap();
    }
}
