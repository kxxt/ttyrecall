use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::Debug,
    fs::File,
    io::{self, BufWriter, Write},
    num::NonZeroUsize,
    path::PathBuf,
    rc::Rc,
    time::Duration,
};

use chrono::Utc;
use color_eyre::eyre::{bail, Report};
use log::{error, info};
use pathrs::{flags::RenameFlags, Root};
use serde::Serialize;
use thiserror::Error;
use ttyrecall_common::Size;

use crate::{daemon::Compress, manager::Manager};

/// A running pty session
struct PtySession {
    writer: Option<Box<dyn Write>>,
    recording_root: Root,
    unfinished_path: PathBuf,
    final_path: PathBuf,
    unfinished_rel_path: PathBuf,
    final_rel_path: PathBuf,
    measurer: Measurer,
    start_ns: u64,
    comm: String,
    /// Wait for the first resize event to correctly populate the width/height metadata.
    staged_events: Option<Vec<StagedEvent>>,
    budget: Option<NonZeroUsize>,
}

#[derive(Error, Debug)]
enum Error {
    #[error("io failure")]
    Io(#[from] io::Error),
    #[error("budget overran, {actual} > {budget}")]
    BudgetOverran { budget: usize, actual: usize },
    #[error("json serialization failure")]
    JsonSerialization(#[from] serde_json::Error),
    #[error("other")]
    Other(#[from] Report),
}

impl PtySession {
    pub fn new(
        manager: &Manager,
        pty_id: u32,
        uid: u32,
        comm: String,
        start_ns: u64,
    ) -> Result<Self, Error> {
        let pending_recording = manager.create_recording_file(uid.into(), pty_id, &comm)?;
        let file = MeasuredFile::from(pending_recording.file);
        let measurer = file.measurer();
        let writer: Box<dyn Write> = match manager.compress {
            Compress::None => Box::new(BufWriter::new(file)),
            // zstd has its own internal buffer
            Compress::Zstd(level) => {
                Box::new(zstd::Encoder::new(file, level.unwrap_or(0))?.auto_finish())
            }
        };
        Ok(Self {
            writer: Some(writer),
            recording_root: pending_recording.root,
            unfinished_path: pending_recording.unfinished_path,
            final_path: pending_recording.final_path,
            unfinished_rel_path: pending_recording.unfinished_rel_path,
            final_rel_path: pending_recording.final_rel_path,
            start_ns,
            measurer,
            comm,
            staged_events: Some(Vec::new()),
            budget: None,
        })
    }

    pub fn with_budget(mut self, budget: Option<NonZeroUsize>) -> Self {
        self.budget = budget;
        self
    }

    fn writer_mut(&mut self) -> &mut dyn Write {
        self.writer
            .as_mut()
            .expect("recording writer was already finalized")
            .as_mut()
    }

    /// Write all staged events and remove staging buffer
    pub fn flush_staged(&mut self) -> Result<(), Error> {
        for e in self.staged_events.take().unwrap() {
            match e {
                StagedEvent::Metadata { size, timestamp } => {
                    writeln!(
                        self.writer_mut(),
                        r#"{{"version": 2, "width": {}, "height": {}, "timestamp": {}, "env": {{"TERM": "xterm-256color"}}}}"#,
                        size.width,
                        size.height,
                        timestamp
                    )?;
                }
                StagedEvent::Write { content, time_ns } => {
                    self.write(&content, time_ns)?;
                }
            }
        }
        Ok(())
    }

    pub fn stage_event(&mut self, value: StagedEvent) {
        if let Some(staged) = self.staged_events.as_mut() {
            staged.push(value);
        } else {
            panic!("No staging buffer");
        }
    }

    pub fn staged_event_count(&self) -> Option<usize> {
        self.staged_events.as_ref().map(|e| e.len())
    }

    pub fn write(&mut self, content: &str, time_ns: u64) -> Result<(), Error> {
        self.budget_overran()?;
        let diff_secs = Duration::from_nanos(time_ns - self.start_ns).as_secs_f64();
        {
            let mut ser = serde_json::Serializer::new(self.writer_mut());
            (diff_secs, "o", content).serialize(&mut ser)?;
        }
        writeln!(self.writer_mut())?;
        Ok(())
    }

    pub fn resize(&mut self, size: Size, time_ns: u64) -> Result<(), Error> {
        self.budget_overran()?;
        let diff_secs = Duration::from_nanos(time_ns - self.start_ns).as_secs_f64();
        {
            let mut ser = serde_json::Serializer::new(self.writer_mut());
            (diff_secs, "r", format!("{}x{}", size.width, size.height)).serialize(&mut ser)?;
        }
        writeln!(self.writer_mut())?;
        Ok(())
    }

    pub fn budget_overran(&self) -> Result<(), Error> {
        if let Some(budget) = self.budget {
            let measure = self.measurer.measure();
            let budget = budget.into();
            if measure > budget {
                Err(Error::BudgetOverran {
                    budget,
                    actual: measure,
                })
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    pub fn first_staged_event_mut(&mut self) -> Option<&mut StagedEvent> {
        self.staged_events.as_mut().and_then(|e| e.first_mut())
    }

    fn finalize_recording(&mut self) -> Result<(), Error> {
        if self.staged_events.is_some() {
            self.flush_staged()?;
        }

        let Some(mut writer) = self.writer.take() else {
            return Ok(());
        };
        writer.flush()?;
        drop(writer);

        self.recording_root
            .rename(
                &self.unfinished_rel_path,
                &self.final_rel_path,
                RenameFlags::RENAME_NOREPLACE,
            )
            .map_err(Report::new)?;
        info!(
            "finalized recording {} -> {}",
            self.unfinished_path.display(),
            self.final_path.display()
        );
        Ok(())
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        if let Err(err) = self.finalize_recording() {
            error!(
                "failed to finalize recording {} -> {}: {err}",
                self.unfinished_path.display(),
                self.final_path.display()
            );
        }
    }
}

pub struct PtySessionManager {
    sessions: HashMap<u32, PtySession>,
    manager: Rc<Manager>,
    budget: Option<NonZeroUsize>,
}

const STAGED_EVENT_MAX: usize = 50;

impl PtySessionManager {
    pub fn new(manager: Rc<Manager>, budget: Option<NonZeroUsize>) -> Self {
        Self {
            sessions: HashMap::new(),
            manager,
            budget,
        }
    }

    pub fn add_session(
        &mut self,
        pty_id: u32,
        uid: u32,
        comm: String,
        start_ns: u64,
    ) -> color_eyre::Result<()> {
        info!("add_session({pty_id}, {uid}, {comm}, {start_ns})");
        if self.sessions.contains_key(&pty_id) {
            bail!("A pty session numbered {pty_id} already exists!");
        }
        let mut session =
            PtySession::new(&self.manager, pty_id, uid, comm, start_ns)?.with_budget(self.budget);
        session.stage_event(StagedEvent::Metadata {
            size: Size::default(),
            timestamp: Utc::now().timestamp(),
        });
        self.sessions.insert(pty_id, session);
        Ok(())
    }

    pub fn resize_session(&mut self, id: u32, time_ns: u64, size: Size) -> color_eyre::Result<()> {
        let Some(session) = self.sessions.get_mut(&id) else {
            bail!("Pty session {id} does not exist");
        };
        if size.is_zero() {
            // Ignore resize event with zero size
            return Ok(());
        }
        let r = if let Some(first) = session.first_staged_event_mut() {
            match first {
                StagedEvent::Metadata { size: psize, .. } => *psize = size,
                _ => unreachable!(),
            }
            session.flush_staged()
        } else {
            session.resize(size, time_ns)
        };
        match r {
            Err(Error::BudgetOverran { budget, actual }) => {
                info!(
                    "pty{id} from {comm} has written {actual} bytes, overran budget {budget}. Stop tracking it.",
                    comm = session.comm
                );
                self.sessions.remove(&id);
            }
            r => r?,
        }
        Ok(())
    }

    pub fn write_to(&mut self, id: u32, content: &str, time_ns: u64) -> color_eyre::Result<()> {
        let Some(session) = self.sessions.get_mut(&id) else {
            bail!("Pty session {id} does not exist");
        };
        let r = if let Some(cnt) = session.staged_event_count() {
            if cnt < STAGED_EVENT_MAX {
                session.stage_event(StagedEvent::Write {
                    content: content.to_owned(),
                    time_ns,
                });
                return Ok(());
            } else {
                session.flush_staged()
            }
        } else {
            session.write(content, time_ns)
        };
        match r {
            Err(Error::BudgetOverran { budget, actual }) => {
                info!(
                    "pty{id} from {comm} has written {actual} bytes, overran budget {budget}. Stop tracking it.",
                    comm = session.comm
                );
                self.sessions.remove(&id);
            }
            r => r?,
        }
        Ok(())
    }

    pub fn exists(&self, id: u32) -> bool {
        self.sessions.contains_key(&id)
    }

    pub fn remove_session(&mut self, id: u32) {
        info!("remove_session({id})");
        self.sessions.remove(&id);
    }
}

#[derive(Debug)]
enum StagedEvent {
    Metadata { size: Size, timestamp: i64 },
    Write { content: String, time_ns: u64 },
}

/// A measured [`File`] that records the amount of writes that occurred.
struct MeasuredFile {
    inner: File,
    total_writes: Rc<RefCell<usize>>,
}

struct Measurer(Rc<RefCell<usize>>);

impl MeasuredFile {
    pub fn measurer(&self) -> Measurer {
        Measurer(self.total_writes.clone())
    }
}

impl From<File> for MeasuredFile {
    fn from(value: File) -> Self {
        Self {
            inner: value,
            total_writes: Rc::new(RefCell::new(0)),
        }
    }
}

impl Measurer {
    pub fn measure(&self) -> usize {
        *self.0.borrow()
    }
}

impl Write for MeasuredFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner
            .write(buf)
            .inspect(|size| *self.total_writes.borrow_mut() += size)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod test {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use nix::unistd::Uid;

    use super::*;
    use crate::{
        catalog::read_cast_bytes,
        manager::{unfinished_path_for, Manager, RECORDING_UNFINISHED_SUFFIX},
    };

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("ttyrecall-session-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn recording_files(root: &PathBuf) -> Vec<PathBuf> {
        let mut files = Vec::new();
        collect_files(root, &mut files);
        files.sort();
        files
    }

    fn collect_files(dir: &PathBuf, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                collect_files(&path, files);
            } else {
                files.push(path);
            }
        }
    }

    fn write_test_session(root: &Path, compress: Compress) -> PtySession {
        let manager = Manager::for_test(root.to_owned(), compress);
        let uid = Uid::current().as_raw();
        let mut session = PtySession::new(&manager, 7, uid, "bash".to_string(), 1_000).unwrap();
        session.stage_event(StagedEvent::Metadata {
            size: Size {
                width: 80,
                height: 24,
            },
            timestamp: 1_780_000_000,
        });
        session.stage_event(StagedEvent::Write {
            content: "hello from unfinished recording".to_string(),
            time_ns: 1_001_000_000,
        });
        session
    }

    fn only_recording_content(root: &Path) -> String {
        let files = recording_files(&root.to_path_buf());
        let final_path = files
            .iter()
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(".cast")
            })
            .unwrap();
        String::from_utf8(read_cast_bytes(final_path).unwrap()).unwrap()
    }

    #[test]
    fn session_publishes_recording_only_after_drop() {
        let root = temp_root("publish-on-drop");
        let session = write_test_session(&root, Compress::None);

        let files = recording_files(&root);
        assert_eq!(files.len(), 1);
        assert!(files[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(RECORDING_UNFINISHED_SUFFIX));
        assert!(!session.final_path.exists());
        assert_eq!(
            unfinished_path_for(&session.final_path),
            session.unfinished_path
        );

        let final_path = session.final_path.clone();
        drop(session);

        assert!(final_path.exists());
        assert!(!unfinished_path_for(&final_path).exists());
        let content = String::from_utf8(read_cast_bytes(&final_path).unwrap()).unwrap();
        assert!(content.contains(r#""version": 2"#));
        assert!(content.contains("hello from unfinished recording"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn zstd_session_is_readable_after_finalization() {
        let root = temp_root("zstd-finalized");
        let session = write_test_session(&root, Compress::Zstd(None));
        let final_path = session.final_path.clone();

        assert!(session
            .unfinished_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".cast.zst.unfinished"));

        drop(session);

        let content = String::from_utf8(read_cast_bytes(&final_path).unwrap()).unwrap();
        assert!(content.contains("hello from unfinished recording"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn resize_flushes_staged_metadata_and_writes() {
        let root = temp_root("resize-flush");
        {
            let manager = Rc::new(Manager::for_test(root.clone(), Compress::None));
            let uid = Uid::current().as_raw();
            let mut sessions = PtySessionManager::new(manager, None);

            sessions
                .add_session(3, uid, "bash".to_string(), 1_000)
                .unwrap();
            sessions
                .write_to(3, "before resize", 1_001_000_000)
                .unwrap();
            sessions
                .resize_session(
                    3,
                    1_002_000_000,
                    Size {
                        width: 100,
                        height: 30,
                    },
                )
                .unwrap();
            sessions.write_to(3, "after resize", 1_003_000_000).unwrap();
            sessions.remove_session(3);
        }

        let content = only_recording_content(&root);
        assert!(content.contains(r#""width": 100, "height": 30"#));
        assert!(content.contains("before resize"));
        assert!(content.contains("after resize"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn zero_size_resize_does_not_flush_staged_events() {
        let root = temp_root("zero-resize");
        {
            let manager = Rc::new(Manager::for_test(root.clone(), Compress::None));
            let uid = Uid::current().as_raw();
            let mut sessions = PtySessionManager::new(manager, None);

            sessions
                .add_session(4, uid, "bash".to_string(), 1_000)
                .unwrap();
            sessions
                .resize_session(
                    4,
                    1_001_000_000,
                    Size {
                        width: 0,
                        height: 0,
                    },
                )
                .unwrap();
            assert_eq!(
                sessions.sessions.get(&4).unwrap().staged_event_count(),
                Some(1)
            );
            sessions.remove_session(4);
        }

        let content = only_recording_content(&root);
        assert!(content.contains(r#""width": 0, "height": 0"#));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn manager_rejects_duplicate_and_missing_sessions() {
        let root = temp_root("errors");
        let manager = Rc::new(Manager::for_test(root.clone(), Compress::None));
        let uid = Uid::current().as_raw();
        let mut sessions = PtySessionManager::new(manager, None);

        sessions
            .add_session(5, uid, "bash".to_string(), 1_000)
            .unwrap();
        assert!(sessions
            .add_session(5, uid, "bash".to_string(), 1_000)
            .unwrap_err()
            .to_string()
            .contains("already exists"));
        assert!(sessions
            .write_to(99, "missing", 1_000)
            .unwrap_err()
            .to_string()
            .contains("does not exist"));
        assert!(sessions
            .resize_session(
                99,
                1_000,
                Size {
                    width: 80,
                    height: 24
                }
            )
            .unwrap_err()
            .to_string()
            .contains("does not exist"));

        sessions.remove_session(5);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn staged_buffer_flushes_after_event_limit() {
        let root = temp_root("staged-limit");
        {
            let manager = Rc::new(Manager::for_test(root.clone(), Compress::None));
            let uid = Uid::current().as_raw();
            let mut sessions = PtySessionManager::new(manager, None);

            sessions
                .add_session(6, uid, "bash".to_string(), 1_000)
                .unwrap();
            for i in 0..STAGED_EVENT_MAX {
                sessions
                    .write_to(6, &format!("event-{i} "), 1_001_000_000 + i as u64)
                    .unwrap();
            }
            assert!(sessions
                .sessions
                .get(&6)
                .unwrap()
                .staged_event_count()
                .is_none());
            sessions.write_to(6, "after flush", 2_000_000_000).unwrap();
            sessions.remove_session(6);
        }

        let content = only_recording_content(&root);
        assert!(content.contains("event-0"));
        assert!(content.contains("after flush"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn budget_overrun_removes_session() {
        let root = temp_root("budget");
        {
            let manager = Rc::new(Manager::for_test(root.clone(), Compress::None));
            let uid = Uid::current().as_raw();
            let mut sessions = PtySessionManager::new(manager, Some(NonZeroUsize::new(1).unwrap()));

            sessions
                .add_session(7, uid, "bash".to_string(), 1_000)
                .unwrap();
            sessions
                .resize_session(
                    7,
                    1_001_000_000,
                    Size {
                        width: 80,
                        height: 24,
                    },
                )
                .unwrap();
            sessions
                .write_to(7, &"x".repeat(16 * 1024), 1_002_000_000)
                .unwrap();
            sessions
                .write_to(7, "trigger budget check", 1_003_000_000)
                .unwrap();

            assert!(!sessions.exists(7));
        }

        let _ = fs::remove_dir_all(root);
    }
}
