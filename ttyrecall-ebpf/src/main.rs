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

use aya_ebpf::{cty::ssize_t, macros::fexit, programs::FExitContext, EbpfContext};
use aya_log_ebpf::{info, trace};
use vmlinux::{iov_iter, kiocb};

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
fn try_pty_write(ctx: FExitContext) -> Result<u32, u32> {
    trace!(&ctx, "function pty_write called");
    let pid = ctx.pid();
    let iocb: *const kiocb = unsafe { ctx.arg(0) };
    let iter: *const iov_iter = unsafe { ctx.arg(1) };
    let ret: ssize_t = unsafe { ctx.arg(2) };
    trace!(&ctx, "fexit pty_write, pid: {}, ret: {}", pid, ret);
    Ok(0)
}

fn try_pty_unix98_install(ctx: FExitContext) -> Result<u32, u32> {
    info!(&ctx, "function pty_unix98_install called");
    Ok(0)
}

fn try_pty_unix98_remove(ctx: FExitContext) -> Result<u32, u32> {
    info!(&ctx, "function pty_unix98_remove called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
