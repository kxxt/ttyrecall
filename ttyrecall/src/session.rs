use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::Debug,
    fs::{self, File},
    io::{self, BufWriter, ErrorKind, Write},
    num::NonZeroUsize,
    path::PathBuf,
    rc::Rc,
    time::Duration,
};

use chrono::Utc;
use color_eyre::eyre::{bail, Report};
use log::{error, info};
use serde::Serialize;
use thiserror::Error;
use ttyrecall_common::Size;

use crate::{daemon::Compress, manager::Manager};

/// A running pty session
struct PtySession {
    writer: Option<Box<dyn Write>>,
    unfinished_path: PathBuf,
    final_path: PathBuf,
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
            unfinished_path: pending_recording.unfinished_path,
            final_path: pending_recording.final_path,
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

        if self.final_path.exists() {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!(
                    "final recording path {} already exists",
                    self.final_path.display()
                ),
            )
            .into());
        }

        fs::rename(&self.unfinished_path, &self.final_path)?;
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
}
