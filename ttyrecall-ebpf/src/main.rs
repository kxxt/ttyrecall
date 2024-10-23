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

use core::{mem::MaybeUninit, ptr::addr_of, usize};

use aya_ebpf::{
    bindings::{bpf_dynptr, BPF_F_NO_PREALLOC},
    cty::{c_int, c_void, ssize_t},
    helpers::{
        bpf_dynptr_data, bpf_dynptr_write, bpf_get_current_comm, bpf_ktime_get_tai_ns,
        bpf_probe_read_kernel, bpf_ringbuf_discard_dynptr, bpf_ringbuf_reserve_dynptr,
        bpf_ringbuf_submit_dynptr, gen::bpf_probe_read_kernel as raw_bpf_probe_read_kernel,
    },
    macros::{fexit, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::FExitContext,
    EbpfContext,
};
use aya_log_ebpf::{error, info, trace, warn};
use ttyrecall_common::{
    EventKind, ShortEvent, Size, WriteEventHead, RECALL_CONFIG_MODE_ALLOWLIST,
    RECALL_CONFIG_MODE_BLOCKLIST, TTY_WRITE_MAX,
};
use vmlinux::{tty_driver, tty_struct, winsize};

// assuming we have 128 cores, each core is writing 2048 byte to a different pty, that
// will cause 2048 * 128 bytes to be accumlated on our buffer.
// Let's reserve 512 times it for now. It should be enough.
#[map]
static EVENT_RING: RingBuf = RingBuf::with_byte_size(
    if cfg!(feature = "resource-saving") {
        128
    } else {
        128
    } * 2048
        * 512,
    0,
); // 128 MiB

#[map]
static CONFIG: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static USERS: HashMap<u32, u8> = HashMap::with_max_entries(
    if cfg!(feature = "resource-saving") {
        // Only allow 1024 users in the list
        1024
    } else {
        32768
    },
    BPF_F_NO_PREALLOC,
);

/// The hash set of traced ptys
/// NR_UNIX98_PTY_MAX is 1<<20 (1048576)
/// pty slaves can have a major of 136-143
/// So it appears that we can have (143-136+1)*2**20 = 8388608 pty slaves at most
/// This needs further confirmation.
#[map]
static TRACED_PTYS: HashMap<u32, u8> = HashMap::with_max_entries(
    if cfg!(feature = "resource-saving") {
        // Only allow 4096 ptys to be traced in parallel
        4096
    } else {
        8388608
    },
    BPF_F_NO_PREALLOC,
);

/// The map of excluded comms. We won't record sessions started from such processes.
///
/// The comm must be NUL terminated and all bytes after it must also be NUL.
#[map]
static EXCLUDED_COMMS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

const INTERMEDIATE_BUFFER_SIZE: usize = 128;
const TRANSFER_LOOP_CNT_MAX: usize = TTY_WRITE_MAX / INTERMEDIATE_BUFFER_SIZE;

#[map]
static INTERMEDIATE_BUFFER: PerCpuArray<[u8; INTERMEDIATE_BUFFER_SIZE]> =
    PerCpuArray::with_max_entries(1, 0);

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
    // id: /dev/pts/{id}
    let id = unsafe { bpf_probe_read_kernel(&(*tty).index).unwrap() } as u32;
    if !should_trace(id) {
        return Ok(3);
    }
    let driver = unsafe { bpf_probe_read_kernel(&(*tty).driver).unwrap() };
    // https://elixir.bootlin.com/linux/v6.11/source/include/linux/tty_driver.h#L568-L571
    let subtype = unsafe { bpf_probe_read_kernel(&(*driver).subtype).unwrap() };
    const PTY_TYPE_SLAVE: i16 = 0x0002;
    if subtype != PTY_TYPE_SLAVE {
        return Ok(0);
    }
    let time = unsafe { bpf_ktime_get_tai_ns() };
    let slice_size = (ret as usize).min(TTY_WRITE_MAX);
    let mut dynptr = MaybeUninit::<bpf_dynptr>::uninit();
    unsafe {
        let result = bpf_ringbuf_reserve_dynptr(
            addr_of!(EVENT_RING) as *mut c_void,
            size_of::<WriteEventHead>() as u32 + slice_size as u32,
            0,
            dynptr.as_mut_ptr(),
        );
        if result < 0 {
            warn!(&ctx, "No space on ringbuf");
            bpf_ringbuf_discard_dynptr(dynptr.as_mut_ptr(), 0);
            return Err(u32::MAX);
        }
    };
    let head = WriteEventHead {
        id,
        time,
        ..Default::default()
    };
    unsafe {
        bpf_dynptr_write(
            dynptr.as_mut_ptr(),
            0,
            addr_of!(head) as *mut c_void, // Actually we don't need mut.
            size_of_val(&head) as u32,
            0,
        );
        // Guaranteed success
    }
    // Write payload chunk by chunk
    unsafe {
        let cnt = ((slice_size + INTERMEDIATE_BUFFER_SIZE - 1) / INTERMEDIATE_BUFFER_SIZE)
            .min(TRANSFER_LOOP_CNT_MAX);
        let base_offset = size_of_val(&head);
        let mut offset = 0;
        for _ in 0..cnt {
            let chunk_size = INTERMEDIATE_BUFFER_SIZE.min(slice_size - offset);
            if chunk_size == INTERMEDIATE_BUFFER_SIZE {
                let chunk = bpf_dynptr_data(
                    dynptr.as_mut_ptr(),
                    (base_offset + offset) as u32,
                    INTERMEDIATE_BUFFER_SIZE as u32,
                );
                if chunk.is_null() {
                    warn!(&ctx, "BUG! bpf_dynptr_data failure");
                    bpf_ringbuf_discard_dynptr(dynptr.as_mut_ptr(), 0);
                    return Err(u32::MAX);
                }
                raw_bpf_probe_read_kernel(chunk, chunk_size as u32, buf.byte_add(offset).cast());
                // MAYBE check result?
            } else {
                let Some(intermediate) = INTERMEDIATE_BUFFER.get_ptr(0) else {
                    // Should not happen
                    bpf_ringbuf_discard_dynptr(dynptr.as_mut_ptr(), 0);
                    return Err(u32::MAX);
                };
                let intermediate = intermediate as *mut c_void;
                raw_bpf_probe_read_kernel(
                    intermediate,
                    chunk_size as u32,
                    buf.byte_add(offset).cast(),
                );
                // MAYBE check result?
                bpf_dynptr_write(
                    dynptr.as_mut_ptr(),
                    (base_offset + offset) as u32,
                    intermediate,
                    chunk_size as u32,
                    0,
                );
            }
            offset += chunk_size;
        }
    }
    unsafe {
        bpf_ringbuf_submit_dynptr(dynptr.as_mut_ptr(), 0);
    }
    Ok(0)
}

// C
// static int pty_unix98_install(struct tty_driver *driver, struct tty_struct *tty)
fn try_pty_unix98_install(ctx: FExitContext) -> Result<u32, u32> {
    let mode = CONFIG
        .get(ttyrecall_common::RECALL_CONFIG_INDEX_MODE)
        .map(|t| *t)
        .unwrap_or_default();
    let uid = ctx.uid();
    let should_trace = match mode {
        RECALL_CONFIG_MODE_BLOCKLIST => unsafe { USERS.get(&uid) }.is_none(),
        RECALL_CONFIG_MODE_ALLOWLIST => unsafe { USERS.get(&uid) }.is_some(),
        _ => {
            error!(&ctx, "Invalid mode: {}", mode);
            false
        }
    };
    info!(&ctx, "function pty_unix98_install called");
    // Arguments
    let _driver: *const tty_driver = unsafe { ctx.arg(0) };
    let tty: *const tty_struct = unsafe { ctx.arg(1) };
    let ret: c_int = unsafe { ctx.arg(2) };
    if ret < 0 {
        return Ok(1);
    }
    // Read Info
    // id: /dev/pts/{id}
    let id = unsafe { bpf_probe_read_kernel(&(*tty).index).unwrap() } as u32;
    let time = unsafe { bpf_ktime_get_tai_ns() };
    let comm = canonicalized_comm();
    if should_trace && unsafe { EXCLUDED_COMMS.get(&comm) }.is_none() {
        TRACED_PTYS.insert(&id, &0, 0).unwrap();
    } else {
        return Ok(2);
    }
    let Some(mut reserved) = EVENT_RING.reserve::<ShortEvent>(0) else {
        error!(&ctx, "Failed to reserve event!");
        return Err(u32::MAX);
    };
    reserved.write(ShortEvent {
        uid,
        id,
        time,
        kind: EventKind::PtyInstall { comm },
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
    if !should_trace(id) {
        return Ok(3);
    }
    TRACED_PTYS.remove(&id).unwrap();
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
    if !should_trace(id) {
        return Ok(3);
    }
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
    // Read Info
    // id: /dev/pts/{id}
    let time = unsafe { bpf_ktime_get_tai_ns() };
    let driver_major = unsafe { bpf_probe_read_kernel(&(*(*tty).driver).major).unwrap() };
    // According to https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
    // pty slaves has a major of 136-143
    if !(136..=143).contains(&driver_major) {
        return Ok(2);
    }
    let id = unsafe { bpf_probe_read_kernel(&(*tty).index).unwrap() } as u32;
    if !should_trace(id) {
        return Ok(3);
    }
    let winsize = unsafe { bpf_probe_read_kernel(ws).unwrap() };
    let Some(mut reserved) = EVENT_RING.reserve::<ShortEvent>(0) else {
        error!(&ctx, "Failed to reserve event!");
        return Err(u32::MAX);
    };
    reserved.write(ShortEvent {
        uid: ctx.uid(),
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

fn canonicalized_comm() -> [u8; 16] {
    let mut comm = bpf_get_current_comm().unwrap();
    // index of first nul
    let mut idx_nul = usize::MAX;
    // Ensure the comm ends with NUL bytes
    for i in 0..comm.len() {
        if i > idx_nul {
            comm[i] = 0;
        } else if comm[i] == 0 {
            idx_nul = i;
        }
    }
    comm
}

fn should_trace(id: u32) -> bool {
    unsafe { TRACED_PTYS.get(&id) }.is_some()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
