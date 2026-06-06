use std::{collections::HashSet, os::fd::RawFd};

use super::Comm;

#[cfg(all(feature = "ebpf-aya", feature = "ebpf-libbpf"))]
compile_error!("features `ebpf-aya` and `ebpf-libbpf` are mutually exclusive");

#[cfg(not(any(feature = "ebpf-aya", feature = "ebpf-libbpf")))]
compile_error!("one of `ebpf-aya` or `ebpf-libbpf` must be enabled");

#[cfg(feature = "ebpf-aya")]
mod aya_backend;
#[cfg(feature = "ebpf-libbpf")]
mod libbpf_backend;

pub(super) struct EbpfBackend {
    inner: Backend,
}

enum Backend {
    #[cfg(feature = "ebpf-aya")]
    Aya(aya_backend::AyaBackend),
    #[cfg(feature = "ebpf-libbpf")]
    Libbpf(libbpf_backend::LibbpfBackend),
}

impl EbpfBackend {
    pub(super) fn load(
        mode: u64,
        uids: &HashSet<u32>,
        excluded_comms: &HashSet<Comm>,
    ) -> color_eyre::Result<Self> {
        let inner = {
            #[cfg(feature = "ebpf-aya")]
            {
                Backend::Aya(aya_backend::AyaBackend::load(mode, uids, excluded_comms)?)
            }
            #[cfg(feature = "ebpf-libbpf")]
            {
                Backend::Libbpf(libbpf_backend::LibbpfBackend::load(
                    mode,
                    uids,
                    excluded_comms,
                )?)
            }
        };
        Ok(Self { inner })
    }

    pub(super) fn event_fd(&self) -> RawFd {
        match &self.inner {
            #[cfg(feature = "ebpf-aya")]
            Backend::Aya(backend) => backend.event_fd(),
            #[cfg(feature = "ebpf-libbpf")]
            Backend::Libbpf(backend) => backend.event_fd(),
        }
    }

    pub(super) fn consume(
        &mut self,
        handler: &mut dyn FnMut(&[u8]) -> color_eyre::Result<()>,
    ) -> color_eyre::Result<()> {
        match &mut self.inner {
            #[cfg(feature = "ebpf-aya")]
            Backend::Aya(backend) => backend.consume(handler),
            #[cfg(feature = "ebpf-libbpf")]
            Backend::Libbpf(backend) => backend.consume(handler),
        }
    }
}
