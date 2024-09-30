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

use aya_ebpf::{
    cty::{c_int, ssize_t},
    helpers::bpf_probe_read_kernel,
    macros::fexit,
    programs::FExitContext,
    EbpfContext,
};
use aya_log_ebpf::{info, trace};
use vmlinux::{tty_driver, tty_struct};

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
    let _tty: *const tty_struct = unsafe { ctx.arg(0) };
    let _buf: *const u8 = unsafe { ctx.arg(1) };
    let _size: ssize_t = unsafe { ctx.arg(2) };
    let ret: ssize_t = unsafe { ctx.arg(3) };
    // Creds
    let pid = ctx.pid();
    let uid = ctx.uid();
    trace!(
        &ctx,
        "fexit pty_write, pid: {}, ret: {}, uid: {}",
        pid,
        ret,
        uid
    );
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
    let id = unsafe { bpf_probe_read_kernel(&(*tty).index).unwrap() };
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
    let id = unsafe { bpf_probe_read_kernel(&(*tty).index).unwrap() };
    info!(&ctx, "pty_unix98_remove uid={}, id={}", uid, id,);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
