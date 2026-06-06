#![no_std]

#[derive(Debug, Clone, Copy, Default)]
pub struct Size {
    pub width: u16,
    pub height: u16,
}

impl Size {
    pub fn is_zero(&self) -> bool {
        self.width == 0 && self.height == 0
    }
}

#[derive(Debug)]
pub enum EventKind {
    PtyInstall { comm: [u8; 16] },
    PtyResize { size: Size },
    PtyRemove,
}

pub const RAW_EVENT_KIND_PTY_INSTALL: u32 = 1;
pub const RAW_EVENT_KIND_PTY_RESIZE: u32 = 2;
pub const RAW_EVENT_KIND_PTY_REMOVE: u32 = 3;
pub const RAW_EVENT_KIND_WRITE_CHUNK: u32 = 4;
pub const RAW_WRITE_CHUNK_SIZE: usize = 128;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RawShortEvent {
    pub time: u64,
    pub uid: u32,
    pub id: u32,
    pub kind: u32,
    pub reserved: u32,
    pub width: u16,
    pub height: u16,
    pub comm: [u8; 16],
}

impl RawShortEvent {
    pub fn pty_install(uid: u32, id: u32, time: u64, comm: [u8; 16]) -> Self {
        Self {
            time,
            uid,
            id,
            kind: RAW_EVENT_KIND_PTY_INSTALL,
            comm,
            ..Self::default()
        }
    }

    pub fn pty_resize(uid: u32, id: u32, time: u64, size: Size) -> Self {
        Self {
            time,
            uid,
            id,
            kind: RAW_EVENT_KIND_PTY_RESIZE,
            width: size.width,
            height: size.height,
            ..Self::default()
        }
    }

    pub fn pty_remove(uid: u32, id: u32, time: u64) -> Self {
        Self {
            time,
            uid,
            id,
            kind: RAW_EVENT_KIND_PTY_REMOVE,
            ..Self::default()
        }
    }

    pub fn short_event(self) -> Option<ShortEvent> {
        let kind = match self.kind {
            RAW_EVENT_KIND_PTY_INSTALL => EventKind::PtyInstall { comm: self.comm },
            RAW_EVENT_KIND_PTY_RESIZE => EventKind::PtyResize {
                size: Size {
                    width: self.width,
                    height: self.height,
                },
            },
            RAW_EVENT_KIND_PTY_REMOVE => EventKind::PtyRemove,
            _ => return None,
        };
        Some(ShortEvent {
            uid: self.uid,
            id: self.id,
            time: self.time,
            kind,
        })
    }
}

#[derive(Debug)]
pub struct ShortEvent {
    pub uid: u32,
    pub id: u32,
    pub time: u64,
    pub kind: EventKind,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
// This struct should be bigger than `ShortEvent`
// because we are leaveraging this to determine if a event
// is a `ShortEvent`
pub struct WriteEventHead {
    pub time: u64,
    pub id: u32,
    pub reserved: u32,
    pub comm: [u8; 16],
    pub _padding: [u8; 24],
}

const _: () = assert!(
    size_of::<RawShortEvent>() < size_of::<WriteEventHead>(),
    "RawShortEvent should be shorter than WriteEventHead!"
);

#[derive(Debug)]
#[repr(C)]
pub struct WriteEvent {
    pub head: WriteEventHead,
    // There is no padding between the two members! Do NOT BREAK it!
    pub data: [u8],
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RawWriteChunkEvent {
    pub time: u64,
    pub id: u32,
    pub kind: u32,
    pub len: u32,
    pub reserved: u32,
    pub data: [u8; RAW_WRITE_CHUNK_SIZE],
}

impl Default for RawWriteChunkEvent {
    fn default() -> Self {
        Self {
            time: 0,
            id: 0,
            kind: RAW_EVENT_KIND_WRITE_CHUNK,
            len: 0,
            reserved: 0,
            data: [0; RAW_WRITE_CHUNK_SIZE],
        }
    }
}

// TTY_BUFFER_PAGE: https://elixir.bootlin.com/linux/v6.11/source/drivers/tty/tty_buffer.c#L41
// #define TTY_BUFFER_PAGE	(((PAGE_SIZE - sizeof(struct tty_buffer)) / 2) & ~TTYB_ALIGN_MASK)

const PAGE_SIZE: usize = 4096;
// This should be enough for most systems.
pub const TTY_WRITE_MAX: usize = PAGE_SIZE / 2;

pub const RECALL_CONFIG_INDEX_MODE: u32 = 0;

pub const RECALL_CONFIG_MODE_BLOCKLIST: u64 = 0;
pub const RECALL_CONFIG_MODE_ALLOWLIST: u64 = 1;
