use std::{
    collections::HashMap,
    ffi::CStr,
    fs::File,
    io::{BufWriter, Write},
    time::Duration,
};

use bstr::{BStr, BString};
use chrono::Datelike;
use color_eyre::eyre::bail;
use either::Either;
use nix::unistd::{Uid, User};
use serde::Serialize;

/// A running pty session
#[derive(Debug)]
struct PtySession {
    writer: BufWriter<File>,
    pty_id: u32,
    uid: Uid,
    counter: u64,
    start_ns: u64,
    comm: BString,
}

impl PtySession {
    pub fn new(pty_id: u32, uid: u32, start_ns: u64) -> color_eyre::Result<Self> {
        let time = chrono::Local::now();
        let filename = format!(
            "{year}-{month:02}-{day:02}-pty{pty_id}-{user}.log",
            year = time.year(),
            month = time.month(),
            day = time.day(),
            user = User::from_uid(Uid::from_raw(uid))
                .map(|u| u
                    .map(|u| Either::Left(u.name))
                    .unwrap_or_else(|| Either::Right(uid)))
                .unwrap_or_else(|_| Either::Right(uid))
        );
        // FIXME: handle existent file
        let file = File::create_new(filename)?;
        let mut writer = BufWriter::new(file);
        writeln!(
            writer,
            r#"{{"version": 2, "width": 236, "height": 64, "timestamp": 1504467315, "title": "Demo", "env": {{"TERM": "xterm-256color", "SHELL": "/bin/zsh"}}}}"#
        )?;
        Ok(Self {
            writer,
            pty_id,
            uid: Uid::from_raw(uid),
            counter: 0,
            start_ns,
            comm: BString::default(), // TODO
        })
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // By default BufWriter will ignore errors when dropping.
        self.writer.flush().unwrap();
    }
}

#[derive(Debug, Default)]
pub struct PtySessionManager {
    sessions: HashMap<u32, PtySession>,
}

impl PtySessionManager {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_session(&mut self, pty_id: u32, uid: u32, start_ns: u64) -> color_eyre::Result<()> {
        if self.sessions.contains_key(&pty_id) {
            bail!("A pty session numbered {pty_id} already exists!");
        }
        self.sessions
            .insert(pty_id, PtySession::new(pty_id, uid, start_ns)?);
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
