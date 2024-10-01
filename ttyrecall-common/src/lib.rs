#![no_std]

use core::mem::MaybeUninit;

#[derive(Debug)]
pub enum EventKind {
    PtyInstall { comm: [u8; 16] },
    PtyRemove,
}

#[derive(Debug)]
pub struct ShortEvent {
    pub uid: u32,
    pub id: u32,
    pub time: u64,
    pub kind: EventKind,
}

#[derive(Debug)]
pub struct WriteEvent {
    pub id: u32,
    pub time: u64,
    pub len: usize,
    pub data: MaybeUninit<[u8; TTY_WRITE_MAX]>,
}

// TTY_BUFFER_PAGE: https://elixir.bootlin.com/linux/v6.11/source/drivers/tty/tty_buffer.c#L41
// #define TTY_BUFFER_PAGE	(((PAGE_SIZE - sizeof(struct tty_buffer)) / 2) & ~TTYB_ALIGN_MASK)

const PAGE_SIZE: usize = 4096;
// This should be enough for most systems.
pub const TTY_WRITE_MAX: usize = PAGE_SIZE / 2;
