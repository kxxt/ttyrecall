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
    use std::{collections::HashSet, fs, path::PathBuf, rc::Rc};

    use ttyrecall_common::{
        RawShortEvent, RawWriteChunkEvent, Size, WriteEventHead, RAW_EVENT_KIND_WRITE_CHUNK,
    };

    use super::{
        is_sshd_comm, read_plain, should_resolve_sshd_owner, Daemon, Mode, SessionDispatcher,
    };
    use crate::{manager::Manager, session::PtySessionManager};

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("ttyrecall-daemon-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn dispatcher(root: &std::path::Path, mode: Mode, uids: HashSet<u32>) -> SessionDispatcher {
        let manager = Rc::new(Manager::for_test(root.to_path_buf(), super::Compress::None));
        SessionDispatcher::new(PtySessionManager::new(manager, None), mode, uids)
    }

    fn bytes_of<T>(value: &T) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(value).cast::<u8>(),
                std::mem::size_of::<T>(),
            )
        }
    }

    fn comm(name: &str) -> [u8; 16] {
        let mut comm = [0; 16];
        comm[..name.len()].copy_from_slice(name.as_bytes());
        comm
    }

    fn recording_contents(root: &std::path::Path) -> String {
        fn collect(dir: &std::path::Path, files: &mut Vec<PathBuf>) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_dir() {
                    collect(&path, files);
                } else if path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .ends_with(".cast")
                {
                    files.push(path);
                }
            }
        }
        let mut files = Vec::new();
        collect(root, &mut files);
        files.sort();
        fs::read_to_string(files.first().unwrap()).unwrap()
    }

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

    #[test]
    fn escape_comm_stops_at_nul_and_sanitizes_slashes() {
        assert_eq!(Daemon::escape_comm(comm("bash")), "bash");
        assert_eq!(Daemon::escape_comm(comm("foo/bar")), "foo_bar");

        let mut raw = [0; 16];
        raw[..8].copy_from_slice(b"cmd\0tail");
        assert_eq!(Daemon::escape_comm(raw), "cmd");
    }

    #[test]
    fn read_plain_reads_unaligned_struct_bytes() {
        let raw = RawShortEvent::pty_remove(1000, 7, 99);
        let mut bytes = vec![0u8];
        bytes.extend_from_slice(bytes_of(&raw));

        let decoded = read_plain::<RawShortEvent>(&bytes[1..]);

        assert_eq!(decoded.uid, 1000);
        assert_eq!(decoded.id, 7);
        assert_eq!(decoded.time, 99);
    }

    #[test]
    fn session_dispatcher_respects_blocklist_and_allowlist() {
        let root = temp_root("policy");
        let uid = nix::unistd::Uid::current().as_raw();
        let other_uid = uid.saturating_add(1);
        let mut block = dispatcher(&root, Mode::BlockList, HashSet::from([other_uid]));
        block
            .add_session(1, other_uid, "bash".to_string(), 1_000)
            .unwrap();
        assert!(!block.manager.exists(1));

        block
            .add_session(2, uid, "bash".to_string(), 1_000)
            .unwrap();
        assert!(block.manager.exists(2));

        let mut allow = dispatcher(&root, Mode::AllowList, HashSet::from([uid]));
        allow
            .add_session(3, other_uid, "bash".to_string(), 1_000)
            .unwrap();
        assert!(!allow.manager.exists(3));
        allow
            .add_session(4, uid, "bash".to_string(), 1_000)
            .unwrap();
        assert!(allow.manager.exists(4));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn handle_event_records_short_and_write_chunk_events() {
        let root = temp_root("write-chunk");
        {
            let uid = nix::unistd::Uid::current().as_raw();
            let mut sessions = dispatcher(&root, Mode::BlockList, HashSet::new());
            let install = RawShortEvent::pty_install(uid, 7, 1_000, comm("bash"));
            Daemon::handle_event(bytes_of(&install), &mut sessions).unwrap();
            let resize = RawShortEvent::pty_resize(
                uid,
                7,
                2_000,
                Size {
                    width: 80,
                    height: 24,
                },
            );
            Daemon::handle_event(bytes_of(&resize), &mut sessions).unwrap();

            let mut write = RawWriteChunkEvent {
                time: 3_000,
                id: 7,
                kind: RAW_EVENT_KIND_WRITE_CHUNK,
                len: 5,
                ..RawWriteChunkEvent::default()
            };
            write.data[..5].copy_from_slice(b"hello");
            Daemon::handle_event(bytes_of(&write), &mut sessions).unwrap();

            let remove = RawShortEvent::pty_remove(uid, 7, 4_000);
            Daemon::handle_event(bytes_of(&remove), &mut sessions).unwrap();
        }

        assert!(recording_contents(&root).contains("hello"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn handle_event_records_legacy_write_event_payload() {
        let root = temp_root("legacy-write");
        {
            let uid = nix::unistd::Uid::current().as_raw();
            let mut sessions = dispatcher(&root, Mode::BlockList, HashSet::new());
            let install = RawShortEvent::pty_install(uid, 8, 1_000, comm("bash"));
            Daemon::handle_event(bytes_of(&install), &mut sessions).unwrap();
            let resize = RawShortEvent::pty_resize(
                uid,
                8,
                2_000,
                Size {
                    width: 80,
                    height: 24,
                },
            );
            Daemon::handle_event(bytes_of(&resize), &mut sessions).unwrap();

            let head = WriteEventHead {
                time: 3_000,
                id: 8,
                ..WriteEventHead::default()
            };
            let mut bytes = bytes_of(&head).to_vec();
            bytes.extend_from_slice(b"legacy");
            Daemon::handle_event(&bytes, &mut sessions).unwrap();

            let remove = RawShortEvent::pty_remove(uid, 8, 4_000);
            Daemon::handle_event(bytes_of(&remove), &mut sessions).unwrap();
        }

        assert!(recording_contents(&root).contains("legacy"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn handle_event_ignores_unknown_or_too_short_events() {
        let root = temp_root("invalid-events");
        let mut sessions = dispatcher(&root, Mode::BlockList, HashSet::new());

        let unknown = RawShortEvent {
            kind: 99,
            ..RawShortEvent::default()
        };
        Daemon::handle_event(bytes_of(&unknown), &mut sessions).unwrap();
        Daemon::handle_event(&[1, 2, 3], &mut sessions).unwrap();

        assert!(fs::read_dir(&root).unwrap().next().is_none());
        let _ = fs::remove_dir_all(root);
    }
}
