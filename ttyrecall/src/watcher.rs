use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use color_eyre::eyre::Context;
use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use log::{error, warn};

pub(crate) trait RecordingEventHandler: Send + 'static {
    fn clear(&mut self);
    fn upsert_file(&mut self, path: &Path);
    fn remove_file(&mut self, path: &Path);
    fn remove_tree(&mut self, path: &Path);
}

#[derive(Debug)]
pub(crate) struct RecordingWatcher<H> {
    scan_roots: Vec<PathBuf>,
    handler: H,
    inotify: Inotify,
    watch_paths: std::collections::HashMap<PathBuf, WatchDescriptor>,
    watched_dirs: std::collections::HashMap<WatchDescriptor, PathBuf>,
}

impl<H: RecordingEventHandler> RecordingWatcher<H> {
    pub(crate) fn new(scan_roots: Vec<PathBuf>, handler: H) -> std::io::Result<Self> {
        Ok(Self {
            scan_roots,
            handler,
            inotify: Inotify::init()?,
            watch_paths: std::collections::HashMap::new(),
            watched_dirs: std::collections::HashMap::new(),
        })
    }

    pub(crate) fn rebuild(&mut self) -> color_eyre::Result<()> {
        self.inotify = Inotify::init().with_context(|| "failed to init inotify")?;
        self.watch_paths.clear();
        self.watched_dirs.clear();
        self.handler.clear();
        for root in self.scan_roots.clone() {
            match self.scan_dir_recursive(root) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    pub(crate) fn run(&mut self) -> color_eyre::Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let events = self.inotify.read_events_blocking(&mut buffer)?;
            let events: Vec<_> = events.map(|event| event.to_owned()).collect();
            for event in events {
                self.handle_event(event)?;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn watched_paths(&self) -> impl Iterator<Item = &PathBuf> {
        self.watch_paths.keys()
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
            self.handler.remove_tree(&path);
        }

        Ok(())
    }

    fn handle_file_event(&mut self, path: PathBuf, mask: EventMask) {
        if mask.intersects(
            EventMask::CREATE | EventMask::MOVED_TO | EventMask::CLOSE_WRITE | EventMask::ATTRIB,
        ) {
            self.handler.upsert_file(&path);
        }

        if mask.intersects(EventMask::DELETE | EventMask::MOVED_FROM) {
            self.handler.remove_file(&path);
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
                self.handler.upsert_file(&path);
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

pub(crate) fn spawn_recording_watcher<H: RecordingEventHandler>(
    scan_roots: Vec<PathBuf>,
    handler: H,
    thread_name: &str,
) -> color_eyre::Result<()> {
    let mut watcher = RecordingWatcher::new(scan_roots, handler)?;
    watcher.rebuild()?;
    let thread_name = thread_name.to_string();
    std::thread::Builder::new()
        .name(thread_name)
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
        path::{Path, PathBuf},
        sync::{Arc, RwLock as StdRwLock},
    };

    use super::{RecordingEventHandler, RecordingWatcher};

    #[derive(Debug, Default)]
    struct TestHandler {
        files: Arc<StdRwLock<Vec<PathBuf>>>,
    }

    impl RecordingEventHandler for TestHandler {
        fn clear(&mut self) {
            self.files.write().unwrap().clear();
        }

        fn upsert_file(&mut self, path: &Path) {
            self.files.write().unwrap().push(path.to_path_buf());
        }

        fn remove_file(&mut self, _path: &Path) {}

        fn remove_tree(&mut self, _path: &Path) {}
    }

    fn temp_root(name: &str) -> PathBuf {
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

        let handler = TestHandler::default();
        let mut watcher = RecordingWatcher::new(vec![root.join("1000")], handler).unwrap();

        let result = watcher.rebuild();

        fs::set_permissions(&other_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert!(result.is_ok());
        assert!(watcher
            .watched_paths()
            .all(|path| path.starts_with(root.join("1000"))));
    }

    #[test]
    fn missing_single_user_dir_rebuilds_as_empty_index() {
        let root = temp_root("missing-user-dir");
        let files = Arc::new(StdRwLock::new(Vec::new()));
        let handler = TestHandler {
            files: files.clone(),
        };
        let mut watcher = RecordingWatcher::new(vec![root.join("1000")], handler).unwrap();

        watcher.rebuild().unwrap();

        assert_eq!(watcher.watched_paths().count(), 0);
        assert!(files.read().unwrap().is_empty());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rebuild_indexes_existing_files() {
        let root = temp_root("rebuild-indexes");
        let recording = root.join("1000/2026/06/06/bash-pty2-10:30.cast");
        fs::create_dir_all(recording.parent().unwrap()).unwrap();
        fs::write(&recording, "{}").unwrap();

        let files = Arc::new(StdRwLock::new(Vec::new()));
        let handler = TestHandler {
            files: files.clone(),
        };
        let mut watcher = RecordingWatcher::new(vec![root.join("1000")], handler).unwrap();

        watcher.rebuild().unwrap();

        assert_eq!(files.read().unwrap().as_slice(), &[recording]);

        fs::remove_dir_all(&root).unwrap();
    }
}
