use aya::{include_bytes_aligned, Bpf};
use aya::{programs::FExit, Btf};
use aya_log::BpfLogger;
use log::{debug, info, warn};
use session::PtySessionManager;
use tokio::io::unix::AsyncFd;
use tokio::{select, signal};
use ttyrecall_common::{Event, EventKind};

mod session;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    env_logger::init();

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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ttyrecall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ttyrecall"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;
    let pty_write_prog: &mut FExit = bpf.program_mut("pty_write").unwrap().try_into()?;
    pty_write_prog.load("pty_write", &btf)?;
    pty_write_prog.attach()?;
    let install_prog: &mut FExit = bpf.program_mut("pty_unix98_install").unwrap().try_into()?;
    install_prog.load("pty_unix98_install", &btf)?;
    install_prog.attach()?;
    let remove_prog: &mut FExit = bpf.program_mut("pty_unix98_remove").unwrap().try_into()?;
    remove_prog.load("pty_unix98_remove", &btf)?;
    remove_prog.attach()?;
    info!("Waiting for Ctrl-C...");
    let event_ring = aya::maps::RingBuf::try_from(bpf.map_mut("EVENT_RING").unwrap())?;
    let mut async_fd = AsyncFd::new(event_ring)?;
    let mut manager = PtySessionManager::new();
    loop {
        select! {
            _ = signal::ctrl_c() => {
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(read) = rb.next() {
                    let event: &Event = unsafe { &*(read.as_ptr().cast()) };
                    match event.kind {
                        EventKind::PtyWrite { len } => {
                            if manager.exists(event.id) {
                                manager.write_to(event.id,
                                    std::str::from_utf8(unsafe { &event.data.assume_init_ref()[..len] })?, event.time)?;
                            }
                        },
                        EventKind::PtyInstall { comm } => {
                            manager.add_session(event.id, event.uid, event.time)?;
                        },
                        EventKind::PtyRemove => {
                            manager.remove_session(event.id);
                        },
                    }
                }
                guard.clear_ready();
            }
        }
    }
    info!("Exiting...");
    Ok(())
}
