use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{Arc, RwLock as StdRwLock},
};

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use log::{error, warn};

use crate::catalog::RecordingIndex;

#[derive(Debug)]
struct RecordingWatcher {
    storage_root: PathBuf,
    index: Arc<StdRwLock<RecordingIndex>>,
    inotify: Inotify,
    watch_paths: std::collections::HashMap<PathBuf, WatchDescriptor>,
    watched_dirs: std::collections::HashMap<WatchDescriptor, PathBuf>,
}

impl RecordingWatcher {
    fn new(storage_root: PathBuf, index: Arc<StdRwLock<RecordingIndex>>) -> std::io::Result<Self> {
        Ok(Self {
            storage_root,
            index,
            inotify: Inotify::init()?,
            watch_paths: std::collections::HashMap::new(),
            watched_dirs: std::collections::HashMap::new(),
        })
    }

    fn rebuild(&mut self) -> std::io::Result<()> {
        self.inotify = Inotify::init()?;
        self.watch_paths.clear();
        self.watched_dirs.clear();
        self.index.write().unwrap().clear();
        self.scan_dir_recursive(self.storage_root.clone())
    }

    fn run(&mut self) -> std::io::Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let events = self.inotify.read_events_blocking(&mut buffer)?;
            let events: Vec<_> = events.map(|event| event.to_owned()).collect();
            for event in events {
                self.handle_event(event)?;
            }
        }
    }

    fn handle_event(&mut self, event: inotify::Event<OsString>) -> std::io::Result<()> {
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

    fn handle_dir_event(&mut self, path: PathBuf, mask: EventMask) -> std::io::Result<()> {
        if mask.intersects(EventMask::MOVED_FROM | EventMask::MOVED_TO) {
            return self.rebuild();
        }

        if mask.contains(EventMask::CREATE) {
            return match self.scan_dir_recursive(path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err),
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
    index: Arc<StdRwLock<RecordingIndex>>,
) -> color_eyre::Result<()> {
    let mut watcher = RecordingWatcher::new(storage_root, index)?;
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
