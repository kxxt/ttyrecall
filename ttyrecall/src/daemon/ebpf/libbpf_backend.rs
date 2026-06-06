use std::{
    cell::RefCell,
    collections::{HashSet, VecDeque},
    ffi::OsStr,
    os::fd::RawFd,
    rc::Rc,
};

use color_eyre::eyre::{eyre, WrapErr};
#[cfg(debug_assertions)]
use libbpf_rs::{set_print, PrintLevel};
use libbpf_rs::{Link, MapCore, MapFlags, ObjectBuilder, RingBuffer, RingBufferBuilder};
use ttyrecall_common::RECALL_CONFIG_INDEX_MODE;

use super::Comm;

#[cfg(debug_assertions)]
const BPF_OBJECT: &[u8] = include_bytes!("../../../../target/libbpf/debug/ttyrecall.bpf.o");
#[cfg(not(debug_assertions))]
const BPF_OBJECT: &[u8] = include_bytes!("../../../../target/libbpf/release/ttyrecall.bpf.o");

pub(super) struct LibbpfBackend {
    _links: Vec<Link>,
    ringbuf: RingBuffer<'static>,
    samples: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

impl LibbpfBackend {
    pub(super) fn load(
        mode: u64,
        uids: &HashSet<u32>,
        excluded_comms: &HashSet<Comm>,
    ) -> color_eyre::Result<Self> {
        #[cfg(debug_assertions)]
        init_libbpf_logging();

        let object = ObjectBuilder::default()
            .open_memory(BPF_OBJECT)
            .wrap_err("failed to open libbpf eBPF object")?
            .load()
            .wrap_err("failed to load libbpf eBPF object")?;
        let object = Box::leak(Box::new(object));

        update_config(object, mode)?;
        update_users(object, uids)?;
        update_excluded_comms(object, excluded_comms)?;

        let links = object
            .progs_mut()
            .map(|prog| {
                prog.attach()
                    .wrap_err_with(|| format!("failed to attach {:?}", prog.name()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let samples = Rc::new(RefCell::new(VecDeque::new()));
        let callback_samples = samples.clone();
        let event_ring = object
            .maps()
            .find(|map| map.name() == OsStr::new("EVENT_RING"))
            .ok_or_else(|| eyre!("missing EVENT_RING map"))?;
        let mut builder = RingBufferBuilder::new();
        builder.add(&event_ring, move |data| {
            callback_samples.borrow_mut().push_back(data.to_vec());
            0
        })?;
        let ringbuf = builder.build()?;

        Ok(Self {
            _links: links,
            ringbuf,
            samples,
        })
    }

    pub(super) fn event_fd(&self) -> RawFd {
        self.ringbuf.epoll_fd()
    }

    pub(super) fn consume(
        &mut self,
        handler: &mut dyn FnMut(&[u8]) -> color_eyre::Result<()>,
    ) -> color_eyre::Result<()> {
        self.ringbuf.consume()?;
        while let Some(sample) = self.samples.borrow_mut().pop_front() {
            handler(&sample)?;
        }
        Ok(())
    }
}

fn update_config(object: &mut libbpf_rs::Object, mode: u64) -> color_eyre::Result<()> {
    let config = object
        .maps_mut()
        .find(|map| map.name() == OsStr::new("CONFIG"))
        .ok_or_else(|| eyre!("missing CONFIG map"))?;
    config.update(
        &RECALL_CONFIG_INDEX_MODE.to_ne_bytes(),
        &mode.to_ne_bytes(),
        MapFlags::ANY,
    )?;
    Ok(())
}

#[cfg(debug_assertions)]
fn init_libbpf_logging() {
    set_print(Some((PrintLevel::Debug, libbpf_log_callback)));
}

#[cfg(debug_assertions)]
fn libbpf_log_callback(level: PrintLevel, message: String) {
    let message = message.trim_end();
    match level {
        PrintLevel::Debug => log::debug!("libbpf: {message}"),
        PrintLevel::Info => log::info!("libbpf: {message}"),
        PrintLevel::Warn => log::warn!("libbpf: {message}"),
    }
}

fn update_users(object: &mut libbpf_rs::Object, uids: &HashSet<u32>) -> color_eyre::Result<()> {
    let users = object
        .maps_mut()
        .find(|map| map.name() == OsStr::new("USERS"))
        .ok_or_else(|| eyre!("missing USERS map"))?;
    for uid in uids {
        users.update(&uid.to_ne_bytes(), &[0], MapFlags::ANY)?;
    }
    Ok(())
}

fn update_excluded_comms(
    object: &mut libbpf_rs::Object,
    excluded_comms: &HashSet<Comm>,
) -> color_eyre::Result<()> {
    let excluded = object
        .maps_mut()
        .find(|map| map.name() == OsStr::new("EXCLUDED_COMMS"))
        .ok_or_else(|| eyre!("missing EXCLUDED_COMMS map"))?;
    for comm in excluded_comms {
        excluded.update(&comm.0, &[0], MapFlags::ANY)?;
    }
    Ok(())
}
