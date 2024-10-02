use std::{
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
    rc::Rc,
    time::Duration,
};

use color_eyre::eyre::bail;
use nix::unistd::Uid;
use serde::Serialize;
use ttyrecall_common::Size;

use crate::manager::Manager;

/// A running pty session
#[derive(Debug)]
struct PtySession {
    writer: BufWriter<File>,
    pty_id: u32,
    uid: Uid,
    counter: u64,
    start_ns: u64,
    comm: String,
}

impl PtySession {
    pub fn new(
        manager: &Manager,
        pty_id: u32,
        uid: u32,
        comm: String,
        start_ns: u64,
        size: Size,
    ) -> color_eyre::Result<Self> {
        let file = manager.create_recording_file(uid.into(), pty_id, &comm)?;
        let mut writer = BufWriter::new(file);
        writeln!(
            writer,
            r#"{{"version": 2, "width": {}, "height": {}, "timestamp": 1504467315, "title": "Demo", "env": {{"TERM": "xterm-256color", "SHELL": "/bin/zsh"}}}}"#,
            size.width, size.height
        )?;
        Ok(Self {
            writer,
            pty_id,
            uid: Uid::from_raw(uid),
            counter: 0,
            start_ns,
            comm,
        })
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // By default BufWriter will ignore errors when dropping.
        self.writer.flush().unwrap();
    }
}

#[derive(Debug)]
pub struct PtySessionManager {
    sessions: HashMap<u32, PtySession>,
    manager: Rc<Manager>,
}

impl PtySessionManager {
    pub fn new(manager: Rc<Manager>) -> Self {
        Self {
            sessions: HashMap::new(),
            manager,
        }
    }

    pub fn add_session(
        &mut self,
        pty_id: u32,
        uid: u32,
        comm: String,
        start_ns: u64,
        size: Size,
    ) -> color_eyre::Result<()> {
        if self.sessions.contains_key(&pty_id) {
            bail!("A pty session numbered {pty_id} already exists!");
        }
        self.sessions.insert(
            pty_id,
            PtySession::new(&self.manager, pty_id, uid, comm, start_ns, size)?,
        );
        Ok(())
    }

    pub fn resize_session(
        &mut self,
        pty_id: u32,
        time_ns: u64,
        size: Size,
    ) -> color_eyre::Result<()> {
        let Some(session) = self.sessions.get_mut(&pty_id) else {
            bail!("Pty session {pty_id} does not exist");
        };
        let diff_secs = Duration::from_nanos(time_ns - session.start_ns).as_secs_f64();
        let mut ser = serde_json::Serializer::new(&mut session.writer);
        (diff_secs, "r", format!("{}x{}", size.width, size.height)).serialize(&mut ser)?;
        writeln!(session.writer)?;
        Ok(())
    }

    pub fn write_to(&mut self, id: u32, content: &str, time_ns: u64) -> color_eyre::Result<()> {
        let Some(session) = self.sessions.get_mut(&id) else {
            bail!("Pty session {id} does not exist");
        };
        let diff_secs = Duration::from_nanos(time_ns - session.start_ns).as_secs_f64();
        let mut ser = serde_json::Serializer::new(&mut session.writer);
        (diff_secs, "o", content).serialize(&mut ser)?;
        writeln!(session.writer)?;
        Ok(())
    }

    pub fn exists(&self, id: u32) -> bool {
        self.sessions.contains_key(&id)
    }

    pub fn remove_session(&mut self, id: u32) {
        self.sessions.remove(&id);
    }
}

#[cfg(test)]
mod test {}
