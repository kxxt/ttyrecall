#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BPF_F_NO_PREALLOC 1

#define RECALL_CONFIG_INDEX_MODE 0
#define RECALL_CONFIG_MODE_BLOCKLIST 0
#define RECALL_CONFIG_MODE_ALLOWLIST 1

#define RAW_EVENT_KIND_PTY_INSTALL 1
#define RAW_EVENT_KIND_PTY_RESIZE 2
#define RAW_EVENT_KIND_PTY_REMOVE 3
#define RAW_EVENT_KIND_WRITE_CHUNK 4

#define PAGE_SIZE 4096
#define TTY_WRITE_MAX (PAGE_SIZE / 2)
#define RAW_WRITE_CHUNK_SIZE 128
#define TRANSFER_LOOP_CNT_MAX (TTY_WRITE_MAX / RAW_WRITE_CHUNK_SIZE)

#ifdef TTYRECALL_DEBUG
#define TTYRECALL_LOG(fmt, ...) bpf_printk("ttyrecall: " fmt, ##__VA_ARGS__)
#else
#define TTYRECALL_LOG(fmt, ...) \
    do {                        \
    } while (0)
#endif

#ifndef TTYRECALL_RESOURCE_SAVING
#define TTYRECALL_USER_MAX_ENTRIES 32768
#define TTYRECALL_TRACED_PTY_MAX_ENTRIES 8388608
#else
#define TTYRECALL_USER_MAX_ENTRIES 1024
#define TTYRECALL_TRACED_PTY_MAX_ENTRIES 4096
#endif

struct raw_short_event {
    __u64 time;
    __u32 uid;
    __u32 id;
    __u32 kind;
    __u32 reserved;
    __u16 width;
    __u16 height;
    __u8 comm[16];
};

struct write_event_head {
    __u64 time;
    __u32 id;
    __u32 reserved;
    __u8 comm[16];
    __u8 padding[24];
};

struct raw_write_chunk_event {
    __u64 time;
    __u32 id;
    __u32 kind;
    __u32 len;
    __u32 reserved;
    __u8 data[RAW_WRITE_CHUNK_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 128 * 2048 * 512);
} EVENT_RING SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} CONFIG SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TTYRECALL_USER_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, __u8);
} USERS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TTYRECALL_TRACED_PTY_MAX_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, __u8);
} TRACED_PTYS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u8[16]);
    __type(value, __u8);
} EXCLUDED_COMMS SEC(".maps");

static __always_inline __u32 current_uid(void)
{
    return (__u32)bpf_get_current_uid_gid();
}

static __always_inline void canonicalized_comm(__u8 comm[16])
{
    long ret = bpf_get_current_comm(comm, 16);
    if (ret < 0) {
        __builtin_memset(comm, 0, 16);
        return;
    }

    int seen_nul = 0;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (seen_nul) {
            comm[i] = 0;
        } else if (comm[i] == 0) {
            seen_nul = 1;
        }
    }
}

static __always_inline int should_trace(__u32 id)
{
    return bpf_map_lookup_elem(&TRACED_PTYS, &id) != 0;
}

static __always_inline int is_sshd_comm(__u8 comm[16])
{
    return comm[0] == 's' && comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd' &&
           comm[4] == '-' && comm[5] == 's' && comm[6] == 'e' && comm[7] == 's' &&
           comm[8] == 's' && comm[9] == 'i' && comm[10] == 'o' && comm[11] == 'n' &&
           comm[12] == '\0';
}

static __always_inline int emit_short_event(struct raw_short_event *event)
{
    struct raw_short_event *reserved;

    reserved = bpf_ringbuf_reserve(&EVENT_RING, sizeof(*reserved), 0);
    if (!reserved)
        return -1;

    __builtin_memcpy(reserved, event, sizeof(*reserved));
    bpf_ringbuf_submit(reserved, 0);
    return 0;
}

static __always_inline int tty_slave_subtype(struct tty_struct *tty)
{
    struct tty_driver *driver;
    int subtype;

    if (bpf_core_read(&driver, sizeof(driver), &tty->driver) < 0)
        return 0;
    if (bpf_core_read(&subtype, sizeof(subtype), &driver->subtype) < 0)
        return 0;
    return subtype;
}

SEC("fexit/pty_write")
int BPF_PROG(pty_write, struct tty_struct *tty, const unsigned char *buf, size_t count, ssize_t ret)
{
    __u32 id;
    __u64 time;
    __u32 slice_size;

    if (ret < 0)
        return 0;
    if (bpf_core_read(&id, sizeof(id), &tty->index) < 0)
        return 0;
    if (!should_trace(id))
        return 0;
    if (tty_slave_subtype(tty) != 0x0002)
        return 0;

    slice_size = ret < TTY_WRITE_MAX ? ret : TTY_WRITE_MAX;
    time = bpf_ktime_get_tai_ns();

    __u32 offset = 0;
#pragma unroll
    for (int i = 0; i < TRANSFER_LOOP_CNT_MAX; i++) {
        __u32 chunk_size;
        struct raw_write_chunk_event *event;

        if (offset >= slice_size)
            break;
        chunk_size = slice_size - offset;
        if (chunk_size > RAW_WRITE_CHUNK_SIZE)
            chunk_size = RAW_WRITE_CHUNK_SIZE;

        event = bpf_ringbuf_reserve(&EVENT_RING, sizeof(*event), 0);
        if (!event) {
            TTYRECALL_LOG("pty_write ringbuf full id=%u", id);
            break;
        }

        event->time = time;
        event->id = id;
        event->kind = RAW_EVENT_KIND_WRITE_CHUNK;
        event->len = chunk_size;
        event->reserved = 0;
        if (bpf_probe_read_kernel(event->data, chunk_size, buf + offset) < 0) {
            TTYRECALL_LOG("pty_write read failed id=%u off=%u", id, offset);
            bpf_ringbuf_discard(event, 0);
            break;
        }
        bpf_ringbuf_submit(event, 0);
        offset += chunk_size;
    }
    return 0;
}

SEC("fexit/pty_unix98_install")
int BPF_PROG(pty_unix98_install, struct tty_driver *driver, struct tty_struct *tty, int ret)
{
    __u32 key = RECALL_CONFIG_INDEX_MODE;
    __u64 *mode;
    __u32 uid = current_uid();
    __u32 id;
    __u8 value = 0;
    __u8 comm[16];
    int should_trace = 0;
    struct raw_short_event event = {};

    if (ret < 0)
        return 0;

    canonicalized_comm(comm);
    if (bpf_map_lookup_elem(&EXCLUDED_COMMS, &comm))
        return 0;

    mode = bpf_map_lookup_elem(&CONFIG, &key);
    if (!mode)
        return 0;
    if (uid == 0 && is_sshd_comm(comm))
        should_trace = 1;
    else if (*mode == RECALL_CONFIG_MODE_BLOCKLIST)
        should_trace = bpf_map_lookup_elem(&USERS, &uid) == 0;
    else if (*mode == RECALL_CONFIG_MODE_ALLOWLIST)
        should_trace = bpf_map_lookup_elem(&USERS, &uid) != 0;
    else {
        TTYRECALL_LOG("pty_install invalid mode=%llu", *mode);
        return 0;
    }

    if (!should_trace)
        return 0;

    if (bpf_core_read(&id, sizeof(id), &tty->index) < 0)
        return 0;

    bpf_map_update_elem(&TRACED_PTYS, &id, &value, BPF_ANY);

    event.time = bpf_ktime_get_tai_ns();
    event.uid = uid;
    event.id = id;
    event.kind = RAW_EVENT_KIND_PTY_INSTALL;
    __builtin_memcpy(event.comm, comm, sizeof(event.comm));
    emit_short_event(&event);
    TTYRECALL_LOG("pty_install uid=%u id=%u", uid, id);
    return 0;
}

SEC("fexit/pty_unix98_remove")
int BPF_PROG(pty_unix98_remove, struct tty_driver *driver, struct tty_struct *tty)
{
    __u32 id;
    struct raw_short_event event = {};

    if (bpf_core_read(&id, sizeof(id), &tty->index) < 0)
        return 0;
    if (!should_trace(id))
        return 0;

    bpf_map_delete_elem(&TRACED_PTYS, &id);

    event.time = bpf_ktime_get_tai_ns();
    event.uid = current_uid();
    event.id = id;
    event.kind = RAW_EVENT_KIND_PTY_REMOVE;
    emit_short_event(&event);
    TTYRECALL_LOG("pty_remove id=%u", id);
    return 0;
}

SEC("fexit/pty_resize")
int BPF_PROG(pty_resize, struct tty_struct *tty, struct winsize *ws, int ret)
{
    __u32 id;
    struct winsize winsize;
    struct raw_short_event event = {};

    if (ret < 0)
        return 0;
    if (bpf_core_read(&id, sizeof(id), &tty->index) < 0)
        return 0;
    if (!should_trace(id))
        return 0;
    if (bpf_core_read(&winsize, sizeof(winsize), ws) < 0)
        return 0;

    event.time = bpf_ktime_get_tai_ns();
    event.uid = current_uid();
    event.id = id;
    event.kind = RAW_EVENT_KIND_PTY_RESIZE;
    event.width = winsize.ws_col;
    event.height = winsize.ws_row;
    emit_short_event(&event);
    TTYRECALL_LOG("pty_resize master id=%u %ux%u", id, event.width, event.height);
    return 0;
}

SEC("fexit/tty_do_resize")
int BPF_PROG(tty_do_resize, struct tty_struct *tty, struct winsize *ws, int ret)
{
    struct tty_driver *driver;
    __u32 id;
    int major;
    struct winsize winsize;
    struct raw_short_event event = {};

    if (ret < 0)
        return 0;
    if (bpf_core_read(&driver, sizeof(driver), &tty->driver) < 0)
        return 0;
    if (bpf_core_read(&major, sizeof(major), &driver->major) < 0)
        return 0;
    if (major < 136 || major > 143)
        return 0;
    if (bpf_core_read(&id, sizeof(id), &tty->index) < 0)
        return 0;
    if (!should_trace(id))
        return 0;
    if (bpf_core_read(&winsize, sizeof(winsize), ws) < 0)
        return 0;

    event.time = bpf_ktime_get_tai_ns();
    event.uid = current_uid();
    event.id = id;
    event.kind = RAW_EVENT_KIND_PTY_RESIZE;
    event.width = winsize.ws_col;
    event.height = winsize.ws_row;
    emit_short_event(&event);
    TTYRECALL_LOG("pty_resize slave id=%u %ux%u", id, event.width, event.height);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
