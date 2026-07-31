// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "ecapture.h"
#include "tc.h"
#include "openssl_offsets.h"
#include "app_data.h"
#include "jni_discovery.h"
#include "jni_conversion.h"

/***********************************************************
 * Internal structs and definitions
 ***********************************************************/

enum ssl_data_event_type { kSSLRead, kSSLWrite };

#define INVALID_FD 0
#define DEFAULT_BIO_TYPE 0
#define BIO_TYPE_DESCRIPTOR_MASK 0x0100
#define MAX_REASONABLE_FD (1U << 20)

// Keep the perf event payload at 16KB for verifier compatibility, but emit
// multiple events for a single SSL_read/SSL_write call. This mirrors the
// segmented GoTLS capture path and raises the per-call capture ceiling to
// 256KB without silently pretending that the first 16KB is the whole call.
#define SSL_DATA_MAX_SEGMENTS 16
#define SSL_DATA_FLAG_TRUNCATED 1U

struct ssl_data_event_t {
    enum ssl_data_event_type type;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    char data[MAX_DATA_SIZE_OPENSSL];
    s32 data_len;
    char comm[TASK_COMM_LEN];
    u32 fd;
    s32 version;
    u32 bio_type;
    u64 ssl_addr;
    u64 bio_addr;
    u32 original_len;
    u32 captured_len;
    u32 chunk_offset;
    u32 flags;
};

enum quic_data_event_type { kQUICProvideData = 1 };

// SSL_provide_quic_data carries QUIC CRYPTO frames into BoringSSL. HTTP/3
// application data is handled by the QUIC stack outside SSL_read/SSL_write, so
// this metadata event lets text mode report that coverage boundary explicitly.
struct quic_data_event_t {
    u64 timestamp_ns;
    u64 ssl_addr;
    u64 data_len;
    u32 pid;
    u32 tid;
    u32 level;
    u32 event_type;
    char comm[TASK_COMM_LEN];
};

struct connect_event_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    char comm[TASK_COMM_LEN];
    u64 timestamp_ns;
    u64 sock;
    u32 pid;
    u32 tid;
    u32 fd;
    u16 family;
    u16 sport;
    u16 dport;
    u8 is_destroy;
    u8 pad[7];
} __attribute__((packed));  // NOTE: do not leave padding hole in this struct.

struct active_ssl_buf {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     * from ssl/ssl_local.h struct ssl_st
     */
    s32 version;
    u32 fd;
    u32 bio_type;
    u32 pad;
    const char* buf;
    u64 ssl_addr;
    u64 bio_addr;
};

struct tcp_fd_info {
    u64 sock;
    int fd;
};

/***********************************************************
 * BPF MAPS
 ***********************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} tls_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} quic_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} connect_events SEC(".maps");

// Key is thread ID (from bpf_get_current_pid_tgid).
// Value is a pointer to the data buffer argument to SSL_write/SSL_read.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct active_ssl_buf);
    __uint(max_entries, 1024);
} active_ssl_read_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct active_ssl_buf);
    __uint(max_entries, 1024);
} active_ssl_write_args_map SEC(".maps");

// BPF programs are limited to a 512-byte stack. We store this value per CPU
// and use it as a heap allocated value.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct ssl_data_event_t);
    __uint(max_entries, 1);
} data_buffer_heap SEC(".maps");

// store ssl fd array for SSL_set_fd function hook.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 10240);
} ssl_st_fd SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct tcp_fd_info);
    __uint(max_entries, 10240);
} tcp_fd_infos SEC(".maps");

/***********************************************************
 * General helper functions
 ***********************************************************/

static __always_inline struct ssl_data_event_t* create_ssl_data_event(u64 current_pid_tgid) {
    u32 zero = 0;
    struct ssl_data_event_t* event = bpf_map_lookup_elem(&data_buffer_heap, &zero);
    if (event == NULL) {
        return NULL;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = current_pid_tgid >> 32;
    event->tid = current_pid_tgid & 0xffffffff;
    event->fd = INVALID_FD;
    event->bio_type = DEFAULT_BIO_TYPE;
    event->ssl_addr = 0;
    event->bio_addr = 0;
    event->original_len = 0;
    event->captured_len = 0;
    event->chunk_offset = 0;
    event->flags = 0;

    return event;
}

/***********************************************************
 * BPF syscall processing functions
 ***********************************************************/

#define SSL_EMIT_SEG(ctx, event, base, total, max_chunk, seg_idx)                                         \
    do {                                                                                                  \
        const u32 _off = (u32)(seg_idx) * (max_chunk);                                                    \
        if (_off < (total)) {                                                                             \
            u32 _remain = (total) - _off;                                                                 \
            u32 _chunk = _remain < (max_chunk) ? (_remain & ((max_chunk) - 1)) : (max_chunk);             \
            if (_chunk > 0) {                                                                             \
                (event)->data_len = (s32)_chunk;                                                          \
                (event)->chunk_offset = _off;                                                             \
                if (bpf_probe_read_user(&(event)->data, _chunk, (void*)((u64)(base) + (u64)_off)) == 0) { \
                    bpf_perf_event_output(                                                                \
                        ctx, &tls_events, BPF_F_CURRENT_CPU, event, sizeof(struct ssl_data_event_t));     \
                }                                                                                         \
            }                                                                                             \
        }                                                                                                 \
    } while (0)

static __always_inline int process_SSL_data(struct pt_regs* ctx, u64 id, enum ssl_data_event_type type,
    const char* buf, u32 fd,
    s32 version, u32 bio_type, u64 ssl_addr, u64 bio_addr) {
    int len = (int)PT_REGS_RC(ctx);
    if (len <= 0 || buf == NULL) {
        return 0;
    }

    struct ssl_data_event_t* event = create_ssl_data_event(id);
    if (event == NULL) {
        return 0;
    }

    event->type = type;
    event->fd = fd;
    event->bio_type = bio_type;
    event->version = version;
    event->ssl_addr = ssl_addr;
    event->bio_addr = bio_addr;

    const u32 max_chunk = MAX_DATA_SIZE_OPENSSL;
    const u32 max_total = max_chunk * SSL_DATA_MAX_SEGMENTS;
    u32 original_len = (u32)len;
    u32 captured_len = original_len;
    if (captured_len > max_total) {
        captured_len = max_total;
        event->flags |= SSL_DATA_FLAG_TRUNCATED;
    }
    event->original_len = original_len;
    event->captured_len = captured_len;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Fully unrolled calls keep bounds visible to older BPF verifiers.
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 0);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 1);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 2);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 3);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 4);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 5);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 6);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 7);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 8);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 9);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 10);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 11);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 12);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 13);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 14);
    SSL_EMIT_SEG(ctx, event, buf, captured_len, max_chunk, 15);
    return 0;
}

static u32 process_BIO_type(u64 ssl_bio_addr) {
    u64 *ssl_bio_method_ptr, *ssl_bio_method_type_ptr;
    u64 ssl_bio_method_addr;
    u32 bio_type;
    int ret;

    // get ssl->bio->method
    ssl_bio_method_ptr = (u64*)(ssl_bio_addr + ecapture_offset_bio_st_method);
    ret = bpf_probe_read_user(&ssl_bio_method_addr, sizeof(ssl_bio_method_addr), ssl_bio_method_ptr);
    if (ret) {
        debug_bpf_printk("(OPENSSL) process_BIO_type: bpf_probe_read ssl_bio_method_ptr failed, ret: %d\n", ret);
        return DEFAULT_BIO_TYPE;
    }

    // get ssl->bio->method->type
    ssl_bio_method_type_ptr = (u64*)(ssl_bio_method_addr + ecapture_offset_bio_method_st_type);
    ret = bpf_probe_read_user(&bio_type, sizeof(bio_type), ssl_bio_method_type_ptr);
    if (ret) {
        debug_bpf_printk("(OPENSSL) process_BIO_type: bpf_probe_read ssl_bio_method_type_ptr failed, ret: %d\n", ret);
        return DEFAULT_BIO_TYPE;
    }

    debug_bpf_printk("openssl process_BIO_type bio_type: %d\n", bio_type);
    return bio_type;
}

static int process_SSL_bio(void* ssl, u64 bio_offset, u32* fd, u32* bio_type, u64* bio_addr) {
    u64* ssl_bio_ptr;
    u64 ssl_bio_addr;
    s32* ssl_bio_num_ptr;
    s32 ssl_bio_num;
    int ret;

    //  In BoringSSL, the ssl_st->s3->hs object is mainly used; ssl_st->version may be null
    ssl_bio_ptr = (u64*)(ssl + bio_offset);
    ret = bpf_probe_read_user(&ssl_bio_addr, sizeof(ssl_bio_addr), ssl_bio_ptr);
    if (ret) {
        debug_bpf_printk("(OPENSSL) bpf_probe_read ssl_bio_ptr failed, ret: %d\n", ret);
        return ret;
    }
    *bio_addr = ssl_bio_addr;
    if (ssl_bio_addr == 0) {
        return -1;
    }

    // get ssl->bio->method->type
    *bio_type = process_BIO_type(ssl_bio_addr);

    // SSL_set_fd/rfd/wfd is authoritative when the library used it.
    u64 ssl_addr = (u64)ssl;
    u64* fd_ptr = bpf_map_lookup_elem(&ssl_st_fd, &ssl_addr);
    if (fd_ptr) {
        u64 known_fd = *fd_ptr;
        if (known_fd > 0 && known_fd <= MAX_REASONABLE_FD) {
            *fd = (u32)known_fd;
            return 0;
        }
    }

    // A custom BIO (for example Cronet's async transport BIO) does not
    // necessarily store a file descriptor in bio->num. Reading it as one
    // produces plausible-looking but invalid connection IDs. Preserve the BIO
    // address above as the transport identity and only read num for descriptor
    // BIOs.
    if ((*bio_type & BIO_TYPE_DESCRIPTOR_MASK) == 0) {
        *fd = INVALID_FD;
        return 0;
    }

    // bio_st->num is an int, not a pointer-sized value.
    ssl_bio_num_ptr = (s32*)(ssl_bio_addr + ecapture_offset_bio_st_num);
    ret = bpf_probe_read_user(&ssl_bio_num, sizeof(ssl_bio_num), ssl_bio_num_ptr);
    if (ret) {
        debug_bpf_printk("(OPENSSL) bpf_probe_read ssl_bio_num_ptr failed, ret: %d\n", ret);
        return ret;
    }

    if (ssl_bio_num > 0 && (u32)ssl_bio_num <= MAX_REASONABLE_FD) {
        *fd = (u32)ssl_bio_num;
    } else {
        *fd = INVALID_FD;
    }
    return 0;
}

static __always_inline int probe_entry_SSL(struct pt_regs* ctx, void* map, u64 bio_offset) {
    if (!passes_filter(ctx)) {
        return 0;
    }

    void* ssl = (void*)PT_REGS_PARM1(ctx);
    s32* ssl_ver_ptr;
    s32 ssl_version = 0;
    int ret;

#ifdef BSSL__SSL3_STATE_VERSION
    u64 ssl_s3_addr = 0;
    u64* ssl_s3_ptr = (u64*)((uintptr_t)ssl + ecapture_offset_ssl_st_s3);
    ret = bpf_probe_read_user(&ssl_s3_addr, sizeof(ssl_s3_addr), ssl_s3_ptr);
    if (ret == 0 && ssl_s3_addr != 0) {
        s32* ssl_s3_version_ptr = (s32*)(ssl_s3_addr + ecapture_offset_ssl3_state_version);
        ret = bpf_probe_read_user(&ssl_version, sizeof(ssl_version), ssl_s3_version_ptr);
    }
    if (ret) {
        debug_bpf_printk("(OPENSSL) bpf_probe_read ssl_s3 version failed, ret: %d\n", ret);
    }
#elif !defined(SSL_SESSION_ST_SSL_VERSION)
    ssl_ver_ptr = (s32*)((uintptr_t)ssl + ecapture_offset_ssl_st_version);
    ret = bpf_probe_read_user(&ssl_version, sizeof(ssl_version), (void*)ssl_ver_ptr);
    if (ret) {
        debug_bpf_printk("(OPENSSL) bpf_probe_read ssl_ver_ptr failed, ret: %d\n", ret);
    }
#endif

    u32 fd = 0;
    u32 bio_type = 0;
    u64 bio_addr = 0;
    ret = process_SSL_bio(ssl, bio_offset, &fd, &bio_type, &bio_addr);
    if (ret == 0) {
        debug_bpf_printk("openssl uprobe/SSL entry fd: %d, version: %d\n", fd, ssl_version);
    }

    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    struct active_ssl_buf active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.fd = fd;
    active_ssl_buf_t.version = ssl_version;
    active_ssl_buf_t.buf = buf;
    active_ssl_buf_t.bio_type = bio_type;
    active_ssl_buf_t.ssl_addr = (u64)ssl;
    active_ssl_buf_t.bio_addr = bio_addr;
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(map, &current_pid_tgid, &active_ssl_buf_t, BPF_ANY);
    return 0;
}

static __always_inline int probe_ret_SSL(struct pt_regs* ctx, void* map, enum ssl_data_event_type type) {
    if (!passes_filter(ctx)) {
        return 0;
    }
    u64 current_pid_tgid = bpf_get_current_pid_tgid();

    struct active_ssl_buf* active_ssl_buf_t = bpf_map_lookup_elem(map, &current_pid_tgid);
    if (active_ssl_buf_t != NULL) {
        const char* buf;
        u32 fd = active_ssl_buf_t->fd;
        u32 bio_type = active_ssl_buf_t->bio_type;
        s32 version = active_ssl_buf_t->version;
        u64 ssl_addr = active_ssl_buf_t->ssl_addr;
        u64 bio_addr = active_ssl_buf_t->bio_addr;
        bpf_probe_read(&buf, sizeof(const char*), &active_ssl_buf_t->buf);
        process_SSL_data(ctx, current_pid_tgid, type, buf, fd, version, bio_type, ssl_addr, bio_addr);
    }
    bpf_map_delete_elem(map, &current_pid_tgid);
    return 0;
}

/***********************************************************
 * BPF probe function entry-points
 ***********************************************************/

// Function signature being probed:
// int SSL_write(SSL *ssl, const void *buf, int num);
SEC("uprobe/SSL_write")
int probe_entry_SSL_write(struct pt_regs* ctx) {
    return probe_entry_SSL(ctx, &active_ssl_write_args_map, ecapture_offset_ssl_st_wbio);
}

SEC("uretprobe/SSL_write")
int probe_ret_SSL_write(struct pt_regs* ctx) { return probe_ret_SSL(ctx, &active_ssl_write_args_map, kSSLWrite); }

// Function signature being probed:
// int SSL_read(SSL *s, void *buf, int num)
SEC("uprobe/SSL_read")
int probe_entry_SSL_read(struct pt_regs* ctx) {
    return probe_entry_SSL(ctx, &active_ssl_read_args_map, ecapture_offset_ssl_st_rbio);
}

SEC("uretprobe/SSL_read")
int probe_ret_SSL_read(struct pt_regs* ctx) { return probe_ret_SSL(ctx, &active_ssl_read_args_map, kSSLRead); }

// BoringSSL:
// int SSL_provide_quic_data(SSL *ssl, enum ssl_encryption_level_t level,
//                           const uint8_t *data, size_t len);
SEC("uprobe/SSL_provide_quic_data")
int probe_SSL_provide_quic_data(struct pt_regs* ctx) {
    if (!passes_filter(ctx)) {
        return 0;
    }

    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    struct quic_data_event_t event = {};
    event.timestamp_ns = bpf_ktime_get_ns();
    event.ssl_addr = (u64)PT_REGS_PARM1(ctx);
    event.level = (u32)PT_REGS_PARM2(ctx);
    event.data_len = (u64)PT_REGS_PARM4(ctx);
    event.pid = current_pid_tgid >> 32;
    event.tid = current_pid_tgid & 0xffffffff;
    event.event_type = kQUICProvideData;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_perf_event_output(ctx, &quic_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

static __always_inline struct tcp_fd_info* find_fd_info(struct pt_regs* regs) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    return bpf_map_lookup_elem(&tcp_fd_infos, &pid_tgid);
}

static __always_inline struct tcp_fd_info* lookup_and_delete_fd_info(struct pt_regs* regs) {
    struct tcp_fd_info* fd_info;
    u64 pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();
    fd_info = bpf_map_lookup_elem(&tcp_fd_infos, &pid_tgid);
    if (fd_info) {
        bpf_map_delete_elem(&tcp_fd_infos, &pid_tgid);
    }
    return fd_info;
}

// libc : int __connect (int fd, __CONST_SOCKADDR_ARG addr, socklen_t len)
// kernel : int __sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
SEC("kprobe/sys_connect")
int probe_connect(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct tcp_fd_info fd_info = {};

    fd_info.fd = PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&tcp_fd_infos, &pid_tgid, &fd_info, BPF_ANY);
    return 0;
}

SEC("kprobe/inet_stream_connect")
int probe_inet_stream_connect(struct pt_regs* ctx) {
    struct tcp_fd_info* fd_info;

    fd_info = find_fd_info(ctx);
    if (fd_info) {
        fd_info->sock = (u64)(void*)PT_REGS_PARM1(ctx);
    }
    return 0;
}

static __always_inline int kretprobe_connect(struct pt_regs* ctx, int fd, struct sock* sk, const bool active) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u16 address_family = 0;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u32 ports;

    if (!passes_filter(ctx)) {
        return 0;
    }

    bpf_probe_read_kernel(&address_family, sizeof(address_family), &sk->__sk_common.skc_family);
    debug_bpf_printk("@ sockaddr FM :%d\n", address_family);

    if (address_family == AF_INET) {
        u64 addrs;
        bpf_probe_read_kernel(&addrs, sizeof(addrs), &sk->__sk_common.skc_addrpair);
        saddr = (__be32)(addrs >> 32);
        daddr = (__be32)addrs;
    } else if (address_family == AF_INET6) {
        bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    } else {
        return 0;
    }

    // if the connection hasn't been established yet, the ports or addrs are 0.
    bpf_probe_read_kernel(&ports, sizeof(ports), &sk->__sk_common.skc_portpair);
    if (ports == 0 || saddr == 0 || daddr == 0) {
        return 0;
    }

    struct connect_event_t conn;
    __builtin_memset(&conn, 0, sizeof(conn));
    conn.timestamp_ns = bpf_ktime_get_ns();
    conn.pid = pid;
    conn.tid = current_pid_tgid;
    conn.fd = fd;
    conn.family = address_family;
    if (active) {
        conn.dport = bpf_ntohs((u16)ports);
        conn.sport = ports >> 16;
        conn.saddr = saddr;
        conn.daddr = daddr;
    } else {
        conn.sport = bpf_ntohs((u16)ports);
        conn.dport = ports >> 16;
        conn.saddr = daddr;
        conn.daddr = saddr;
    }
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));
    conn.sock = (u64)sk;

    bpf_perf_event_output(ctx, &connect_events, BPF_F_CURRENT_CPU, &conn, sizeof(struct connect_event_t));
    return 0;
}

SEC("kretprobe/sys_connect")
int retprobe_connect(struct pt_regs* ctx) {
    struct tcp_fd_info* fd_info;
    struct socket* sock;
    struct sock* sk;

    fd_info = lookup_and_delete_fd_info(ctx);
    if (fd_info) {
        sock = (typeof(sock))fd_info->sock;
        bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
        if (sk) {
            return kretprobe_connect(ctx, fd_info->fd, sk, true);
        }
    }
    return 0;
}

#ifndef IS_ERR_VALUE
#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((unsigned long)(void*)(x) >= (unsigned long)-MAX_ERRNO)
#endif

SEC("kprobe/inet_accept")
int probe_inet_accept(struct pt_regs* ctx) {
    struct tcp_fd_info* fd_info;

    fd_info = find_fd_info(ctx);
    if (fd_info) {
        fd_info->sock = (u64)(void*)PT_REGS_PARM2(ctx);
    }
    return 0;
}

SEC("kretprobe/__sys_accept4")
int retprobe_accept4(struct pt_regs* ctx) {
    struct tcp_fd_info* fd_info;
    struct socket* sock;
    struct sock* sk;
    int fd;

    fd = PT_REGS_RC(ctx);
    if (fd < 0) {
        return 0;
    }

    fd_info = lookup_and_delete_fd_info(ctx);
    if (fd_info) {
        sock = (typeof(sock))(void*)fd_info->sock;
        bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk);
        if (sk) {
            return kretprobe_connect(ctx, fd, sk, false);
        }
    }
    return 0;
}

SEC("kprobe/tcp_v4_destroy_sock")
int probe_tcp_v4_destroy_sock(struct pt_regs* ctx) {
    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    struct connect_event_t conn;
    u64 pid_tgid = bpf_get_current_pid_tgid();

    __builtin_memset(&conn, 0, sizeof(conn));
    conn.timestamp_ns = bpf_ktime_get_ns();
    conn.sock = (u64)sk;
    conn.pid = pid_tgid >> 32;
    conn.tid = pid_tgid;
    conn.is_destroy = 1;
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));

    bpf_perf_event_output(ctx, &connect_events, BPF_F_CURRENT_CPU, &conn, sizeof(struct connect_event_t));

    return BPF_OK;
}

// int SSL_set_fd(SSL *s, int fd)
// int SSL_set_rfd(SSL *s, int fd)
// int SSL_set_wfd(SSL *s, int fd)
SEC("uprobe/SSL_set_fd")
int probe_SSL_set_fd(struct pt_regs* ctx) {
    u64 ssl_addr = (u64)PT_REGS_PARM1(ctx);
    u64 fd = (u64)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&ssl_st_fd, &ssl_addr, &fd, BPF_ANY);
    debug_bpf_printk("SSL_set_fd hook!!, ssl_addr: %d, fd: %d\n", ssl_addr, fd);
    return 0;
}
