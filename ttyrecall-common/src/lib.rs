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

#[derive(Debug)]
pub struct ShortEvent {
    pub uid: u32,
    pub id: u32,
    pub time: u64,
    pub kind: EventKind,
}

#[derive(Debug, Default)]
#[repr(C)]
// This struct should be bigger than `ShortEvent`
// because we are leaveraging this to determine if a event
// is a `ShortEvent`
pub struct WriteEventHead {
    pub id: u32,
    pub time: u64,
    pub comm: [u8; 16],
    pub _padding: [u8; 16],
}

const _: () = assert!(
    size_of::<ShortEvent>() < size_of::<WriteEventHead>(),
    "ShortEvent should be shorter than WriteEventHead!"
);

#[derive(Debug)]
#[repr(C)]
pub struct WriteEvent {
    pub head: WriteEventHead,
    // There is no padding between the two members! Do NOT BREAK it!
    pub data: [u8],
}

// TTY_BUFFER_PAGE: https://elixir.bootlin.com/linux/v6.11/source/drivers/tty/tty_buffer.c#L41
// #define TTY_BUFFER_PAGE	(((PAGE_SIZE - sizeof(struct tty_buffer)) / 2) & ~TTYB_ALIGN_MASK)

const PAGE_SIZE: usize = 4096;
// This should be enough for most systems.
pub const TTY_WRITE_MAX: usize = PAGE_SIZE / 2;

pub const RECALL_CONFIG_INDEX_MODE: u32 = 0;

pub const RECALL_CONFIG_MODE_BLOCKLIST: u64 = 0;
pub const RECALL_CONFIG_MODE_ALLOWLIST: u64 = 1;
