use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    os::{fd::RawFd, unix::fs::MetadataExt},
    path::PathBuf,
    rc::Rc,
};

use color_eyre::eyre::eyre;
use log::{debug, error, info, warn};
use nix::unistd::User;
use tokio::{
    io::unix::AsyncFd,
    select,
    signal::{unix::signal, unix::SignalKind},
    time::{interval, MissedTickBehavior},
};
use ttyrecall_common::{
    EventKind, RawShortEvent, RawWriteChunkEvent, WriteEventHead, RAW_EVENT_KIND_WRITE_CHUNK,
};

use crate::{manager::Manager, session::PtySessionManager};

mod config;
mod ebpf;

pub use config::*;

pub struct Daemon {
    manager: Rc<Manager>,
    mode: Mode,
    uids: HashSet<u32>,
    excluded_comms: HashSet<Comm>,
    budget: Option<NonZeroUsize>,
}

impl Daemon {
    pub fn new(config: DaemonConfig) -> color_eyre::Result<Self> {
        Ok(Self {
            manager: Rc::new(Manager::new(config.root, true, config.compress)?),
            mode: config.mode,
            uids: {
                let mut uids = config.uids;
                for user in config.users {
                    uids.insert(
                        User::from_name(&user)?
                            .ok_or_else(|| eyre!("User {user} listed in `users` does not exist"))?
                            .uid
                            .as_raw(),
                    );
                }
                uids
            },
            excluded_comms: config.excluded_comms,
            budget: NonZeroUsize::new(config.soft_budget),
        })
    }

    pub async fn run(&self) -> color_eyre::Result<()> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        let mut backend =
            ebpf::EbpfBackend::load(self.mode as u64, &self.uids, &self.excluded_comms)?;
        info!("Waiting for Ctrl-C...");
        let mut async_fd = AsyncFd::new(EventFd(backend.event_fd()))?;
        let mut sessions = SessionDispatcher::new(
            PtySessionManager::new(self.manager.clone(), self.budget),
            self.mode,
            self.uids.clone(),
        );
        let mut interrupt_stream = signal(SignalKind::interrupt())?;
        let mut termination_stream = signal(SignalKind::terminate())?;
        let mut event_poll = interval(std::time::Duration::from_millis(100));
        event_poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            select! {
                _ = termination_stream.recv()  => {
                    warn!("Termination signal received. Exiting");
                    break;
                }
                _ = interrupt_stream.recv()  => {
                    break;
                }
                _ = event_poll.tick() => {
                    sessions.resolve_pending()?;
                    backend.consume(&mut |read| Self::handle_event(read, &mut sessions))?;
                }
                guard = async_fd.readable_mut() => {
                    let mut guard = guard?;
                    backend.consume(&mut |read| Self::handle_event(read, &mut sessions))?;
                    guard.clear_ready();
                }
            }
        }
        info!("Exiting...");
        Ok(())
    }

    fn handle_event(read: &[u8], sessions: &mut SessionDispatcher) -> color_eyre::Result<()> {
        const SHORT_EVENT_SIZE: usize = std::mem::size_of::<RawShortEvent>();
        const WRITE_CHUNK_EVENT_SIZE: usize = std::mem::size_of::<RawWriteChunkEvent>();
        match read.len() {
            SHORT_EVENT_SIZE => {
                let raw = read_plain::<RawShortEvent>(read);
                let Some(event) = raw.short_event() else {
                    warn!("unknown eBPF short event kind {}", raw.kind);
                    return Ok(());
                };
                match event.kind {
                    EventKind::PtyInstall { comm } => {
                        sessions.add_session(
                            event.id,
                            event.uid,
                            Self::escape_comm(comm),
                            event.time,
                        )?;
                    }
                    EventKind::PtyRemove => {
                        sessions.remove_session(event.id);
                    }
                    EventKind::PtyResize { size } => {
                        sessions.resize_session(event.id, event.time, size)?;
                    }
                }
            }
            WRITE_CHUNK_EVENT_SIZE => {
                let event = read_plain::<RawWriteChunkEvent>(read);
                if event.kind == RAW_EVENT_KIND_WRITE_CHUNK {
                    let len = (event.len as usize).min(event.data.len());
                    Self::write_to_session(sessions, event.id, event.time, &event.data[..len])?;
                } else {
                    Self::handle_write_event(read, sessions)?;
                }
            }
            size if size > SHORT_EVENT_SIZE => {
                Self::handle_write_event(read, sessions)?;
            }
            _ => warn!("invalid eBPF event size {}", read.len()),
        }
        Ok(())
    }

    fn handle_write_event(read: &[u8], sessions: &mut SessionDispatcher) -> color_eyre::Result<()> {
        const WRITE_EVENT_HEAD_SIZE: usize = std::mem::size_of::<WriteEventHead>();
        if read.len() < WRITE_EVENT_HEAD_SIZE {
            warn!("invalid eBPF write event size {}", read.len());
            return Ok(());
        }
        let head = read_plain::<WriteEventHead>(&read[..WRITE_EVENT_HEAD_SIZE]);
        Self::write_to_session(sessions, head.id, head.time, &read[WRITE_EVENT_HEAD_SIZE..])?;
        Ok(())
    }

    fn write_to_session(
        sessions: &mut SessionDispatcher,
        id: u32,
        time: u64,
        slice: &[u8],
    ) -> color_eyre::Result<()> {
        let str = match std::str::from_utf8(slice) {
            Ok(s) => Cow::Borrowed(s),
            Err(e) => {
                error!("Not valid utf8: {e}: {slice:?}");
                String::from_utf8_lossy(slice)
            }
        };
        sessions.write_to(id, &str, time)?;
        Ok(())
    }

    /// Escaped path safe comm
    fn escape_comm(comm: [u8; 16]) -> String {
        String::from_utf8_lossy(
            std::ffi::CStr::from_bytes_until_nul(&comm)
                .unwrap()
                .to_bytes(),
        )
        .into_owned()
        .replace('/', "_")
    }
}

struct SessionDispatcher {
    manager: PtySessionManager,
    mode: Mode,
    uids: HashSet<u32>,
    pending_sshd: HashMap<u32, PendingSshdSession>,
}

struct PendingSshdSession {
    comm: String,
    start_ns: u64,
    events: Vec<PendingEvent>,
    buffered_bytes: usize,
}

enum PendingEvent {
    Resize {
        time_ns: u64,
        size: ttyrecall_common::Size,
    },
    Write {
        time_ns: u64,
        content: String,
    },
}

enum PendingActivation {
    Activated,
    Dropped,
    StillPending,
}

const SSHD_PENDING_EVENT_MAX: usize = 256;
const SSHD_PENDING_BYTES_MAX: usize = 1024 * 1024;

impl SessionDispatcher {
    fn new(manager: PtySessionManager, mode: Mode, uids: HashSet<u32>) -> Self {
        Self {
            manager,
            mode,
            uids,
            pending_sshd: HashMap::new(),
        }
    }

    fn add_session(
        &mut self,
        pty_id: u32,
        uid: u32,
        comm: String,
        start_ns: u64,
    ) -> color_eyre::Result<()> {
        if should_resolve_sshd_owner(uid, &comm) {
            self.pending_sshd.insert(
                pty_id,
                PendingSshdSession {
                    comm,
                    start_ns,
                    events: Vec::new(),
                    buffered_bytes: 0,
                },
            );
            self.try_activate_pending(pty_id)?;
            return Ok(());
        }

        if self.should_record_uid(uid) {
            self.manager.add_session(pty_id, uid, comm, start_ns)?;
        }
        Ok(())
    }

    fn remove_session(&mut self, id: u32) {
        self.pending_sshd.remove(&id);
        self.manager.remove_session(id);
    }

    fn resize_session(
        &mut self,
        id: u32,
        time_ns: u64,
        size: ttyrecall_common::Size,
    ) -> color_eyre::Result<()> {
        match self.try_activate_pending(id)? {
            PendingActivation::Dropped => return Ok(()),
            PendingActivation::Activated | PendingActivation::StillPending => {}
        }

        if self.manager.exists(id) {
            self.manager.resize_session(id, time_ns, size)?;
        } else if let Some(pending) = self.pending_sshd.get_mut(&id) {
            pending.events.push(PendingEvent::Resize { time_ns, size });
            self.enforce_pending_limits(id);
        }
        Ok(())
    }

    fn write_to(&mut self, id: u32, content: &str, time_ns: u64) -> color_eyre::Result<()> {
        match self.try_activate_pending(id)? {
            PendingActivation::Dropped => return Ok(()),
            PendingActivation::Activated | PendingActivation::StillPending => {}
        }

        if self.manager.exists(id) {
            self.manager.write_to(id, content, time_ns)?;
        } else if let Some(pending) = self.pending_sshd.get_mut(&id) {
            pending.buffered_bytes += content.len();
            pending.events.push(PendingEvent::Write {
                time_ns,
                content: content.to_owned(),
            });
            self.enforce_pending_limits(id);
        }
        Ok(())
    }

    fn resolve_pending(&mut self) -> color_eyre::Result<()> {
        let ids: Vec<_> = self.pending_sshd.keys().copied().collect();
        for id in ids {
            self.try_activate_pending(id)?;
        }
        Ok(())
    }

    fn try_activate_pending(&mut self, id: u32) -> color_eyre::Result<PendingActivation> {
        if !self.pending_sshd.contains_key(&id) {
            return Ok(PendingActivation::Activated);
        }

        let Some(owner_uid) = pts_owner_uid(id) else {
            return Ok(PendingActivation::StillPending);
        };
        if owner_uid == 0 {
            return Ok(PendingActivation::StillPending);
        }

        if !self.should_record_uid(owner_uid) {
            info!("drop sshd pty{id}: resolved owner uid {owner_uid} is filtered by policy");
            self.pending_sshd.remove(&id);
            return Ok(PendingActivation::Dropped);
        }

        let pending = self
            .pending_sshd
            .remove(&id)
            .expect("pending sshd session checked above");
        self.manager
            .add_session(id, owner_uid, pending.comm, pending.start_ns)?;
        for event in pending.events {
            match event {
                PendingEvent::Resize { time_ns, size } => {
                    self.manager.resize_session(id, time_ns, size)?;
                }
                PendingEvent::Write { time_ns, content } => {
                    self.manager.write_to(id, &content, time_ns)?;
                }
            }
        }
        Ok(PendingActivation::Activated)
    }

    fn should_record_uid(&self, uid: u32) -> bool {
        match self.mode {
            Mode::BlockList => !self.uids.contains(&uid),
            Mode::AllowList => self.uids.contains(&uid),
        }
    }

    fn enforce_pending_limits(&mut self, id: u32) {
        let Some(pending) = self.pending_sshd.get(&id) else {
            return;
        };
        if pending.events.len() <= SSHD_PENDING_EVENT_MAX
            && pending.buffered_bytes <= SSHD_PENDING_BYTES_MAX
        {
            return;
        }
        warn!("drop sshd pty{id}: owner uid was not resolved before pending buffer limit");
        self.pending_sshd.remove(&id);
    }
}

fn should_resolve_sshd_owner(uid: u32, comm: &str) -> bool {
    uid == 0 && is_sshd_comm(comm)
}

fn is_sshd_comm(comm: &str) -> bool {
    comm == "sshd-session"
}

fn pts_owner_uid(id: u32) -> Option<u32> {
    PathBuf::from(format!("/dev/pts/{id}"))
        .metadata()
        .map(|meta| meta.uid())
        .ok()
}

fn read_plain<T: Copy>(data: &[u8]) -> T {
    assert!(data.len() >= std::mem::size_of::<T>());
    unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) }
}

#[derive(Debug)]
struct EventFd(RawFd);

impl std::os::fd::AsRawFd for EventFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{is_sshd_comm, should_resolve_sshd_owner};

    #[test]
    fn root_sshd_comms_need_owner_resolution() {
        assert!(should_resolve_sshd_owner(0, "sshd-session"));
        assert!(!should_resolve_sshd_owner(1000, "sshd-session"));
        assert!(!should_resolve_sshd_owner(0, "bash"));
    }

    #[test]
    fn sshd_comm_matches_openssh_variants() {
        assert!(is_sshd_comm("sshd-session"));
        assert!(!is_sshd_comm("sshd2"));
    }
}
