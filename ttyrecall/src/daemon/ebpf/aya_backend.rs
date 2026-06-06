use std::{collections::HashSet, os::fd::AsRawFd};

use aya::{include_bytes_aligned, maps::MapData, programs::FExit, Bpf, Btf};
use aya_log::BpfLogger;
use log::warn;
use ttyrecall_common::RECALL_CONFIG_INDEX_MODE;

use super::Comm;

pub(super) struct AyaBackend {
    _bpf: Bpf,
    event_ring: aya::maps::RingBuf<MapData>,
}

impl AyaBackend {
    pub(super) fn load(
        mode: u64,
        uids: &HashSet<u32>,
        excluded_comms: &HashSet<Comm>,
    ) -> color_eyre::Result<Self> {
        #[cfg(debug_assertions)]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../../../target/bpfel-unknown-none/debug/ttyrecall"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../../../target/bpfel-unknown-none/release/ttyrecall"
        ))?;
        if let Err(e) = BpfLogger::init(&mut bpf) {
            warn!("failed to initialize eBPF logger: {}", e);
        }

        let btf = Btf::from_sys_fs()?;
        let mut config =
            aya::maps::Array::<&mut MapData, u64>::try_from(bpf.map_mut("CONFIG").unwrap())?;
        config.set(RECALL_CONFIG_INDEX_MODE, mode, 0)?;

        let mut users =
            aya::maps::HashMap::<&mut MapData, u32, u8>::try_from(bpf.map_mut("USERS").unwrap())?;
        for uid in uids {
            users.insert(uid, 0u8, 0)?;
        }

        let mut excluded = aya::maps::HashMap::<&mut MapData, [u8; 16], u8>::try_from(
            bpf.map_mut("EXCLUDED_COMMS").unwrap(),
        )?;
        for comm in excluded_comms {
            excluded.insert(comm.0, 0u8, 0)?;
        }

        attach_fexit(&mut bpf, &btf, "pty_unix98_install")?;
        attach_fexit(&mut bpf, &btf, "pty_unix98_remove")?;
        attach_fexit(&mut bpf, &btf, "pty_resize")?;
        attach_fexit(&mut bpf, &btf, "tty_do_resize")?;
        attach_fexit(&mut bpf, &btf, "pty_write")?;

        let event_ring = aya::maps::RingBuf::try_from(bpf.take_map("EVENT_RING").unwrap())?;

        Ok(Self {
            _bpf: bpf,
            event_ring,
        })
    }

    pub(super) fn event_fd(&self) -> std::os::fd::RawFd {
        self.event_ring.as_raw_fd()
    }

    pub(super) fn consume(
        &mut self,
        handler: &mut dyn FnMut(&[u8]) -> color_eyre::Result<()>,
    ) -> color_eyre::Result<()> {
        while let Some(read) = self.event_ring.next() {
            handler(&read)?;
        }
        Ok(())
    }
}

fn attach_fexit(bpf: &mut Bpf, btf: &Btf, name: &str) -> color_eyre::Result<()> {
    let prog: &mut FExit = bpf.program_mut(name).unwrap().try_into()?;
    prog.load(name, btf)?;
    prog.attach()?;
    Ok(())
}
