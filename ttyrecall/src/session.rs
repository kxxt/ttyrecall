use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::Debug,
    fs::File,
    io::{self, BufWriter, Write},
    num::NonZeroUsize,
    rc::Rc,
    time::Duration,
};

use chrono::Utc;
use color_eyre::eyre::{bail, Report};
use log::info;
use serde::Serialize;
use thiserror::Error;
use ttyrecall_common::Size;

use crate::{daemon::Compress, manager::Manager};

/// A running pty session
struct PtySession {
    writer: Box<dyn Write>,
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
        let file = MeasuredFile::from(manager.create_recording_file(uid.into(), pty_id, &comm)?);
        let measurer = file.measurer();
        let writer: Box<dyn Write> = match manager.compress {
            Compress::None => Box::new(BufWriter::new(file)),
            // zstd has its own internal buffer
            Compress::Zstd(level) => {
                Box::new(zstd::Encoder::new(file, level.unwrap_or(0))?.auto_finish())
            }
        };
        Ok(Self {
            writer,
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

    /// Write all staged events and remove staging buffer
    pub fn flush_staged(&mut self) -> Result<(), Error> {
        for e in self.staged_events.take().unwrap() {
            match e {
                StagedEvent::Metadata { size, timestamp } => {
                    writeln!(
                        self.writer,
                        r#"{{"version": 2, "width": {}, "height": {}, "timestamp": {}, "env": {{"TERM": "xterm-256color"}}}}"#,
                        size.width, size.height, timestamp
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
        let mut ser = serde_json::Serializer::new(&mut self.writer);
        (diff_secs, "o", content).serialize(&mut ser)?;
        writeln!(self.writer)?;
        Ok(())
    }

    pub fn resize(&mut self, size: Size, time_ns: u64) -> Result<(), Error> {
        self.budget_overran()?;
        let diff_secs = Duration::from_nanos(time_ns - self.start_ns).as_secs_f64();
        let mut ser = serde_json::Serializer::new(&mut self.writer);
        (diff_secs, "r", format!("{}x{}", size.width, size.height)).serialize(&mut ser)?;
        writeln!(self.writer)?;
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
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // flush all staged events
        if self.staged_events.is_some() {
            self.flush_staged().unwrap();
        }
        // By default BufWriter will ignore errors when dropping.
        self.writer.flush().unwrap();
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

/// A measured [`File`]` that records the amount of writes occurred.
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
mod test {}
