#![no_std]
#![no_main]

#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(clippy::absolute_paths)]
#[allow(clippy::upper_case_acronyms)]
#[allow(clippy::zero_repeat_side_effects)]
#[allow(non_upper_case_globals)]
#[warn(single_use_lifetimes)]
mod vmlinux {
    include!("generated_vmlinux.rs");
}

use core::mem::MaybeUninit;

use aya_ebpf::{
    bpf_printk,
    cty::{c_int, ssize_t},
    helpers::{
        bpf_get_current_comm, bpf_ktime_get_tai_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{fexit, map},
    maps::{PerCpuArray, RingBuf},
    programs::FExitContext,
    EbpfContext,
};
use aya_log_ebpf::{error, info, trace};
use ttyrecall_common::{EventKind, ShortEvent, Size, WriteEvent, TTY_WRITE_MAX};
use vmlinux::{tty_driver, tty_struct, winsize};

// assuming we have 128 cores, each core is writing 2048 byte to a different pty, that
// will cause 2048 * 128 bytes to be accumlated on our buffer.
// Let's reserve 512 times it for now. It should be enough.
#[map]
static EVENT_RING: RingBuf = RingBuf::with_byte_size(128 * 1024 * 1024, 0); // 128 MiB

#[map]
static EVENT_CACHE: PerCpuArray<WriteEvent> = PerCpuArray::with_max_entries(1, 0);

#[fexit(function = "pty_write")]
pub fn pty_write(ctx: FExitContext) -> u32 {
    match try_pty_write(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[fexit(function = "pty_unix98_install")]
pub fn pty_unix98_install(ctx: FExitContext) -> u32 {
    match try_pty_unix98_install(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[fexit(function = "pty_unix98_remove")]
pub fn pty_unix98_remove(ctx: FExitContext) -> u32 {
    match try_pty_unix98_remove(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[fexit(function = "pty_resize")]
pub fn pty_resize(ctx: FExitContext) -> u32 {
    match try_pty_resize(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[fexit(function = "tty_do_resize")]
pub fn tty_do_resize(ctx: FExitContext) -> u32 {
    match try_tty_do_resize(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// TODO:
// hook
// - devpts_pty_new: node creation in /dev/pts
// - devpts_pty_kill: node deletion in /dev/pts

// TODO:
// 1. send pty output to userspace
// 2.
// C
// static ssize_t pty_write(struct tty_struct *tty, const u8 *buf, size_t c)
fn try_pty_write(ctx: FExitContext) -> Result<u32, u32> {
    trace!(&ctx, "function pty_write called");
    // Arguments
    let tty: *const tty_struct = unsafe { ctx.arg(0) };
    let buf: *const u8 = unsafe { ctx.arg(1) };
    let size: ssize_t = unsafe { ctx.arg(2) };
    let ret: ssize_t = unsafe { ctx.arg(3) };
    if ret < 0 {
        return Err(u32::MAX);
    }
    // Creds
    let pid = ctx.pid();
    let uid = ctx.uid();
    // id: /dev/pts/{id}
    let id = unsafe { bpf_probe_read_kernel(&(*tty).index).unwrap() } as u32;
    let driver = unsafe { bpf_probe_read_kernel(&(*tty).driver).unwrap() };
    // https://elixir.bootlin.com/linux/v6.11/source/include/linux/tty_driver.h#L568-L571
    let subtype = unsafe { bpf_probe_read_kernel(&(*driver).subtype).unwrap() };
    const PTY_TYPE_SLAVE: i16 = 0x0002;
    if subtype != PTY_TYPE_SLAVE {
        return Ok(0);
    }
    let time = unsafe { bpf_ktime_get_tai_ns() };
    let Some(event) = EVENT_CACHE.get_ptr_mut(0) else {
        return Err(u32::MAX);
    };
    unsafe {
        event.write(WriteEvent {
            id,
            time,
            len: 0,
            data: MaybeUninit::uninit(),
        })
    };
    // FIXME: this assume_init_mut call is probably UB
    let dest_slice =
        &mut unsafe { (*event).data.assume_init_mut() }[..(ret as usize + 2).min(TTY_WRITE_MAX)];
    let len = match unsafe { bpf_probe_read_kernel_str_bytes(buf, dest_slice) } {
        Ok(slice) => slice.len().min(ret as usize),
        Err(_) => return Err(u32::MAX),
    };
    unsafe { (*event).len = len }
    if let Err(_) = EVENT_RING.output(unsafe { &*event }, 0) {
        error!(&ctx, "Failed to output event!");
    }
    Ok(0)
}

// C
// static int pty_unix98_install(struct tty_driver *driver, struct tty_struct *tty)
fn try_pty_unix98_install(ctx: FExitContext) -> Result<u32, u32> {
    info!(&ctx, "function pty_unix98_install called");
    // Arguments
    let _driver: *const tty_driver = unsafe { ctx.arg(0) };
    let tty: *const tty_struct = unsafe { ctx.arg(1) };
    let ret: c_int = unsafe { ctx.arg(2) };
    if ret < 0 {
        return Ok(1);
    }
    // Creds
    let uid = ctx.uid();
    // Read Info
    // id: /dev/pts/{id}
    let id = unsafe { bpf_probe_read_kernel(&(*tty).index).unwrap() } as u32;
    let time = unsafe { bpf_ktime_get_tai_ns() };
    let comm = bpf_get_current_comm().unwrap();
    let Some(mut reserved) = EVENT_RING.reserve::<ShortEvent>(0) else {
        error!(&ctx, "Failed to reserve event!");
        return Err(u32::MAX);
    };
    let winsize = unsafe { bpf_probe_read_kernel(&(*tty).winsize).unwrap() };
    reserved.write(ShortEvent {
        uid,
        id,
        time,
        kind: EventKind::PtyInstall {
            comm,
            size: Size {
                width: winsize.ws_col,
                height: winsize.ws_row,
            },
        },
    });
    reserved.submit(0);
    info!(
        &ctx,
        "pty_unix98_install uid={}, id={}, ret={}", uid, id, ret
    );
    Ok(0)
}

// C
// /* this is called once with whichever end is closed last */
// static void pty_unix98_remove(struct tty_driver *driver, struct tty_struct *tty)
fn try_pty_unix98_remove(ctx: FExitContext) -> Result<u32, u32> {
    info!(&ctx, "function pty_unix98_remove called");
    // Arguments
    let _driver: *const tty_driver = unsafe { ctx.arg(0) };
    let tty: *const tty_struct = unsafe { ctx.arg(1) };
    // Creds
    let uid = ctx.uid();
    // Read Info
    // id: /dev/pts/{id}
    let id = unsafe { bpf_probe_read_kernel(&(*tty).index).unwrap() } as u32;
    let time = unsafe { bpf_ktime_get_tai_ns() };
    let Some(mut reserved) = EVENT_RING.reserve::<ShortEvent>(0) else {
        error!(&ctx, "Failed to reserve event!");
        return Err(u32::MAX);
    };
    reserved.write(ShortEvent {
        uid,
        id,
        time,
        kind: EventKind::PtyRemove,
    });
    reserved.submit(0);
    info!(&ctx, "pty_unix98_remove uid={}, id={}", uid, id,);
    Ok(0)
}

// pty *master side* resize
// only pty master implements resize in tty_operations
// C
// static int pty_resize(struct tty_struct *tty,  struct winsize *ws)
fn try_pty_resize(ctx: FExitContext) -> Result<u32, u32> {
    info!(&ctx, "function pty_resize called");
    // Arguments
    let tty: *const tty_struct = unsafe { ctx.arg(0) };
    let ws: *const winsize = unsafe { ctx.arg(1) };
    let ret: c_int = unsafe { ctx.arg(2) };
    if ret < 0 {
        return Ok(1);
    }
    // Creds
    let uid = ctx.uid();
    // Read Info
    // id: /dev/pts/{id}
    let time = unsafe { bpf_ktime_get_tai_ns() };
    let id = unsafe { bpf_probe_read_kernel(&(*tty).index).unwrap() } as u32;
    let winsize = unsafe { bpf_probe_read_kernel(ws).unwrap() };
    let Some(mut reserved) = EVENT_RING.reserve::<ShortEvent>(0) else {
        error!(&ctx, "Failed to reserve event!");
        return Err(u32::MAX);
    };
    reserved.write(ShortEvent {
        uid,
        id,
        time,
        kind: EventKind::PtyResize {
            size: Size {
                width: winsize.ws_col,
                height: winsize.ws_row,
            },
        },
    });
    reserved.submit(0);
    info!(
        &ctx,
        "pty_resize master{} to {}x{}", id, winsize.ws_col, winsize.ws_row
    );
    Ok(0)
}

// tty default resize
// C
//  int tty_do_resize(struct tty_struct *tty, struct winsize *ws)
fn try_tty_do_resize(ctx: FExitContext) -> Result<u32, u32> {
    // Arguments
    let tty: *const tty_struct = unsafe { ctx.arg(0) };
    let ws: *const winsize = unsafe { ctx.arg(1) };
    let ret: c_int = unsafe { ctx.arg(2) };
    if ret < 0 {
        return Ok(1);
    }
    // Creds
    let uid = ctx.uid();
    // Read Info
    // id: /dev/pts/{id}
    let time = unsafe { bpf_ktime_get_tai_ns() };
    let driver_major = unsafe { bpf_probe_read_kernel(&(*(*tty).driver).major).unwrap() };
    info!(&ctx, "function tty_do_resize major = {}", driver_major);
    // According to https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
    // pty slaves has a major of 136-143
    if !(136..=143).contains(&driver_major) {
        return Ok(2);
    }
    let id = unsafe { bpf_probe_read_kernel(&(*tty).index).unwrap() } as u32;
    let winsize = unsafe { bpf_probe_read_kernel(ws).unwrap() };
    let Some(mut reserved) = EVENT_RING.reserve::<ShortEvent>(0) else {
        error!(&ctx, "Failed to reserve event!");
        return Err(u32::MAX);
    };
    reserved.write(ShortEvent {
        uid,
        id,
        time,
        kind: EventKind::PtyResize {
            size: Size {
                width: winsize.ws_col,
                height: winsize.ws_row,
            },
        },
    });
    reserved.submit(0);
    info!(
        &ctx,
        "pty_resize slave{} to {}x{}", id, winsize.ws_col, winsize.ws_row
    );
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
