// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

#ifndef ECAPTURE_APP_DATA_H
#define ECAPTURE_APP_DATA_H

#define APP_HOOK_MAX_SLOTS 8
#define APP_DATA_MAX_SEGMENTS 8
#define APP_DATA_FLAG_BUFFER_INDIRECT 0x01
#define APP_DATA_FLAG_LENGTH_MEMORY 0x02
#define APP_DATA_FLAG_LENGTH_RETURN 0x04
#define APP_DATA_FLAG_CAPTURE_RETURN 0x08
#define APP_DATA_FLAG_LENGTH_INDIRECT 0x10
#define APP_DATA_FLAG_LENGTH_FIXED 0x20
#define APP_DATA_FLAG_BUFFER_LIBCXX_STRING 0x40
#define APP_DATA_FLAG_STATE_SAVE 0x80
#define APP_DATA_FLAG_STATE_LOAD 0x100
#define APP_DATA_FLAG_BUFFER_IOVEC 0x200
#define APP_DATA_FLAG_BUFFER_MSGHDR 0x400
#define APP_DATA_FLAG_USER_STACK 0x800
#define APP_DATA_FLAG_DWARF_STACK 0x1000
#define APP_DATA_EVENT_TRUNCATED 0x01
#define APP_DATA_STREAM_OFFSET_VALID 0x01
#define APP_DATA_STREAM_FIN_VALID 0x02
#define APP_DATA_STREAM_FIN 0x04
#define APP_DATA_MAX_IOVECS 16
#define APP_DATA_MAX_IOVEC_SEGMENTS 8
#define APP_DATA_MAX_STACK_DEPTH 16
#define APP_DWARF_PAGE_BITS 12
#define APP_DWARF_PAGE_SIZE (1U << APP_DWARF_PAGE_BITS)
#define APP_DWARF_PAGE_MASK (APP_DWARF_PAGE_SIZE - 1)
#define APP_DWARF_MAX_PAGE_DELTAS 2048
#define APP_DWARF_MAX_TOTAL_DELTAS (8U * 1024U * 1024U)
#define APP_DWARF_MAX_DELTA_PAIRS (APP_DWARF_MAX_TOTAL_DELTAS / 2)
#define APP_DWARF_MAX_UNWIND_INFOS 16384

#define APP_DWARF_UNWIND_FLAG_COMMAND 0x01
#define APP_DWARF_UNWIND_FLAG_FRAME 0x02
#define APP_DWARF_UNWIND_FLAG_LEAF_ONLY 0x04

#define APP_DWARF_UNWIND_REG_CFA 1
#define APP_DWARF_UNWIND_REG_PC 2
#define APP_DWARF_UNWIND_REG_SP 3
#define APP_DWARF_UNWIND_REG_FP 4
#define APP_DWARF_UNWIND_REG_LR 5

#define APP_DWARF_UNWIND_COMMAND_INVALID 0
#define APP_DWARF_UNWIND_COMMAND_STOP 1
#define APP_DWARF_UNWIND_COMMAND_SIGNAL 3
#define APP_DWARF_UNWIND_COMMAND_FRAME_POINTER 4

#define APP_DWARF_STATUS_RULE_MISSING -2
#define APP_DWARF_STATUS_MEMORY_FAULT -14
#define APP_DWARF_STATUS_INVALID_RULE -22
#define APP_DWARF_STATUS_UNSUPPORTED -95

struct app_hook_config_t {
    u32 buffer_arg;
    u32 length_arg;
    u32 direction;
    u32 flags;
    u64 buffer_offset;
    u64 length_offset;
    u32 length_size;
    u32 max_bytes;
    u32 state_id;
    u32 state_key_arg;
    u32 context_arg;
    u32 stream_arg;
    u32 vector_count_arg;
    u32 reserved;
    u64 context_offset;
    u64 stream_offset;
    u32 context_size;
    u32 stream_size;
    u32 vector_stride;
    u32 vector_base_offset;
    u32 vector_length_offset;
    u32 vector_length_size;
    u32 stream_byte_offset_arg;
    u32 stream_byte_offset_size;
    u64 stream_byte_offset_offset;
    u32 fin_arg;
    u32 fin_size;
    u64 fin_offset;
};

struct active_app_hook_t {
    u64 buffer;
    u64 length;
    u64 context_id;
    u64 stream_id;
    u64 stream_byte_offset;
    u64 result_length_address;
    u32 stream_flags;
    u32 pad;
};

struct app_hook_key_t {
    u64 pid_tgid;
    u32 slot;
    u32 pad;
};

struct app_hook_state_key_t {
    u64 tgid;
    u64 value;
    u32 state_id;
    u32 pad;
};

struct app_hook_state_t {
    u64 buffer;
    u64 maximum_length;
};

struct app_iovec_t {
    u64 base;
    u64 length;
};

/*
 * Userspace compiles .eh_frame CFI into page-local rule transitions. Page
 * headers point into a shared compact delta array instead of embedding a
 * worst-case array in every hash value. Seventeen indexes split each page
 * into 256-byte buckets. A lookup includes the preceding transition, so gaps
 * inherit the correct rule while the verifier-safe binary search examines at
 * most 257 entries instead of every transition in the 4 KiB page.
 */
struct app_dwarf_unwind_info_t {
    u8 flags;
    u8 base_reg;
    u8 aux_base_reg;
    u8 merge_opcode;
    s32 param;
    s32 aux_param;
};

struct app_dwarf_stack_delta_t {
    u16 address_low;
    u16 unwind_info;
};

struct app_dwarf_stack_delta_pair_t {
    struct app_dwarf_stack_delta_t deltas[2];
};

struct app_dwarf_unwind_page_key_t {
    u32 pid;
    u32 reserved;
    u64 page;
};

struct app_dwarf_unwind_page_t {
    u32 delta_start;
    u16 count;
    u16 buckets[17];
};

struct app_dwarf_unwind_state_t {
    u64 pc;
    u64 sp;
    u64 fp;
    u64 lr;
    u32 pid;
    u8 return_address;
    u8 lr_valid;
    u16 reserved;
};

/*
 * readv/writev expose one logical byte stream through discontiguous buffers.
 * This scratch state lets all emitted events use global offsets and identical
 * call metadata, so userspace can reconstruct the flattened stream exactly.
 */
struct app_iovec_state_t {
    u64 iovec_address;
    u64 measured_len;
    u64 return_len;
    u64 emit_consumed;
    u64 timestamp_ns;
    u64 context_id;
    u64 stream_id;
    u64 stream_byte_offset;
    u32 vector_count;
    u32 maximum;
    u32 original_len;
    u32 captured_len;
    u32 emitted_len;
    u32 segment_count;
    u32 flags;
    u32 uses_return_len;
    u32 measurement_failed;
    u32 vector_stride;
    u32 vector_base_offset;
    u32 vector_length_offset;
    u32 vector_length_size;
    u32 stream_flags;
    u32 hook_id;
    u32 direction;
    u32 fin_only;
};

struct app_data_event_t {
    u64 timestamp_ns;
    u64 buffer_addr;
    u64 context_id;
    u64 stream_id;
    u64 stream_byte_offset;
    u32 stream_flags;
    u32 pid;
    u32 tid;
    u32 hook_id;
    u32 direction;
    u32 flags;
    u32 original_len;
    u32 captured_len;
    u32 chunk_offset;
    u32 data_len;
    char comm[TASK_COMM_LEN];
    s32 user_stack_status;
    u32 user_stack_depth;
    u32 uid;
    u32 reserved;
    u64 cgroup_id;
    u64 user_stack[APP_DATA_MAX_STACK_DEPTH];
    char data[MAX_DATA_SIZE_OPENSSL];
};

#define APP_DATA_EVENT_HEADER_SIZE __builtin_offsetof(struct app_data_event_t, data)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct app_hook_config_t);
    __uint(max_entries, APP_HOOK_MAX_SLOTS);
} app_hook_configs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct app_hook_key_t);
    __type(value, struct active_app_hook_t);
    __uint(max_entries, 1024);
} active_app_hooks SEC(".maps");

struct {
    /*
     * Async operations can be cancelled before their completion hook runs.
     * LRU eviction bounds those orphaned entries instead of permanently
     * exhausting the state map.
     */
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct app_hook_state_key_t);
    __type(value, struct app_hook_state_t);
    __uint(max_entries, 1024);
} app_hook_states SEC(".maps");

struct {
    /*
     * One buffer per hook slot prevents nested libc boundaries (for example,
     * a vectored wrapper entering another hooked socket function) from
     * overwriting an outer event on the same CPU before it is emitted.
     */
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct app_data_event_t);
    __uint(max_entries, APP_HOOK_MAX_SLOTS);
} app_data_buffer_heap SEC(".maps");

struct {
    /* Keep vector accounting isolated for the same nested-hook case. */
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct app_iovec_state_t);
    __uint(max_entries, APP_HOOK_MAX_SLOTS);
} app_iovec_state_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct app_dwarf_unwind_page_key_t);
    __type(value, struct app_dwarf_unwind_page_t);
    __uint(max_entries, 131072);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} app_dwarf_unwind_pages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct app_dwarf_stack_delta_pair_t);
    __uint(max_entries, APP_DWARF_MAX_DELTA_PAIRS);
} app_dwarf_unwind_deltas SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct app_dwarf_unwind_info_t);
    __uint(max_entries, APP_DWARF_MAX_UNWIND_INFOS);
} app_dwarf_unwind_infos SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} app_data_events SEC(".maps");

static __always_inline u64 app_dwarf_register_value(
    struct app_dwarf_unwind_state_t *state, u8 reg) {
    switch (reg) {
    case APP_DWARF_UNWIND_REG_CFA:
        return state->sp;
    case APP_DWARF_UNWIND_REG_PC:
        return state->pc;
    case APP_DWARF_UNWIND_REG_SP:
        return state->sp;
    case APP_DWARF_UNWIND_REG_FP:
        return state->fp;
    case APP_DWARF_UNWIND_REG_LR:
        return state->lr;
    default:
        return 0;
    }
}

static __always_inline struct app_dwarf_unwind_page_t *
app_dwarf_find_page(u32 pid, u64 address, u64 *normalized) {
    struct app_dwarf_unwind_page_key_t key = {.pid = pid};
    /*
     * AArch64 PAC occupies otherwise-unused virtual-address bits. Linux arm64
     * commonly uses 39, 42, or 48 user VA bits; TBI may additionally leave a
     * tag in the top byte. A candidate is accepted only when its page exists
     * in the PID-scoped table, so trying all supported widths is unambiguous.
     */
    const u64 masks[6] = {
        ~0ULL,
        0x00ffffffffffffffULL,
        0x000fffffffffffffULL,
        0x0000ffffffffffffULL,
        0x000003ffffffffffULL,
        0x0000007fffffffffULL,
    };

#pragma unroll
    for (u32 index = 0; index < 6; index++) {
        u64 candidate = address & masks[index];
        key.page = candidate & ~(u64)APP_DWARF_PAGE_MASK;
        struct app_dwarf_unwind_page_t *page =
            bpf_map_lookup_elem(&app_dwarf_unwind_pages, &key);
        if (page != NULL) {
            *normalized = candidate;
            return page;
        }
    }
    return NULL;
}

static __always_inline int app_dwarf_read_delta(u32 logical_index,
                                                u16 *address_low,
                                                u16 *unwind_info) {
    u32 pair_key = (logical_index >> 1) & (APP_DWARF_MAX_DELTA_PAIRS - 1);
    struct app_dwarf_stack_delta_pair_t *pair =
        bpf_map_lookup_elem(&app_dwarf_unwind_deltas, &pair_key);
    if (pair == NULL)
        return -1;
    if (logical_index & 1) {
        *address_low = pair->deltas[1].address_low;
        *unwind_info = pair->deltas[1].unwind_info;
    } else {
        *address_low = pair->deltas[0].address_low;
        *unwind_info = pair->deltas[0].unwind_info;
    }
    return 0;
}

static __always_inline struct app_dwarf_unwind_info_t *
app_dwarf_find_unwind_info(struct app_dwarf_unwind_state_t *state,
                           u64 address, u64 *normalized) {
    struct app_dwarf_unwind_page_t *page =
        app_dwarf_find_page(state->pid, address, normalized);
    if (page == NULL)
        return NULL;

    u32 count = page->count;
    u32 safe_count = count & (APP_DWARF_MAX_PAGE_DELTAS - 1);
    /*
     * These equality checks make both values explicitly bounded scalars for
     * older verifiers. Userspace rejects a page with 2048 transitions and a
     * delta array which reaches the fixed backing-array capacity.
     */
    if (count != safe_count || safe_count == 0)
        return NULL;
    u32 start = page->delta_start;
    u32 safe_start = start & (APP_DWARF_MAX_TOTAL_DELTAS - 1);
    if (start != safe_start ||
        safe_start > APP_DWARF_MAX_TOTAL_DELTAS - safe_count)
        return NULL;
    u16 page_offset = *normalized & APP_DWARF_PAGE_MASK;
    u32 bucket_index = (page_offset >> 8) & 15;
    u32 bucket_low = page->buckets[bucket_index];
    u32 bucket_high = page->buckets[bucket_index + 1];
    u32 low = bucket_low & (APP_DWARF_MAX_PAGE_DELTAS - 1);
    u32 high = bucket_high & (APP_DWARF_MAX_PAGE_DELTAS - 1);
    /* Keep these as explicitly bounded scalars on older Android verifiers. */
    if (bucket_low != low || bucket_high != high || low > high ||
        high > safe_count)
        return NULL;
    /*
     * A bucket can start before its first transition or contain no transition
     * at all. Include the last transition from the preceding bucket so the
     * upper-bound search still returns the rule active at page_offset.
     * There are at most 256 distinct byte offsets in a bucket, plus this
     * predecessor, so nine binary-search steps are sufficient.
     */
    if (low > 0)
        low = (low - 1) & (APP_DWARF_MAX_PAGE_DELTAS - 1);
#pragma unroll
    for (u32 iteration = 0; iteration < 9; iteration++) {
        /*
         * Android's older verifier can forget the scalar bounds after the
         * two binary-search branches merge. The compiler can otherwise prove
         * these masks redundant from C semantics and remove them, while the
         * verifier still needs to observe the narrowing instructions. The
         * barriers preserve those instructions without changing runtime data.
         */
        barrier_var(low);
        barrier_var(high);
        low &= APP_DWARF_MAX_PAGE_DELTAS - 1;
        high &= APP_DWARF_MAX_PAGE_DELTAS - 1;
        if (low < high) {
            u32 pivot = ((low + high) >> 1) &
                        (APP_DWARF_MAX_PAGE_DELTAS - 1);
            u32 logical_index =
                (safe_start + (pivot & (APP_DWARF_MAX_PAGE_DELTAS - 1))) &
                (APP_DWARF_MAX_TOTAL_DELTAS - 1);
            u16 delta_address = 0;
            u16 delta_unwind = 0;
            if (app_dwarf_read_delta(logical_index, &delta_address,
                                     &delta_unwind) != 0)
                return NULL;
            if (page_offset >= delta_address) {
                low = (pivot + 1) & (APP_DWARF_MAX_PAGE_DELTAS - 1);
            } else {
                high = pivot & (APP_DWARF_MAX_PAGE_DELTAS - 1);
            }
        }
    }
    if (low == 0)
        return NULL;
    u32 logical_index =
        (safe_start + ((low - 1) & (APP_DWARF_MAX_PAGE_DELTAS - 1))) &
        (APP_DWARF_MAX_TOTAL_DELTAS - 1);
    u16 delta_address = 0;
    u16 delta_unwind = APP_DWARF_MAX_UNWIND_INFOS;
    if (app_dwarf_read_delta(logical_index, &delta_address, &delta_unwind) != 0)
        return NULL;
    /* BPF array keys are four bytes even though the packed rule index is u16. */
    u32 unwind_index = delta_unwind;
    if (unwind_index >= APP_DWARF_MAX_UNWIND_INFOS)
        return NULL;
    return bpf_map_lookup_elem(&app_dwarf_unwind_infos, &unwind_index);
}

static __always_inline int app_dwarf_unwind_frame_pointer(
    struct app_dwarf_unwind_state_t *state) {
    u64 frame[2] = {};
    if (state->fp == 0 ||
        bpf_probe_read_user(frame, sizeof(frame), (void *)state->fp) != 0)
        return APP_DWARF_STATUS_MEMORY_FAULT;
    state->sp = state->fp + sizeof(frame);
    state->fp = frame[0];
    state->pc = frame[1];
    state->lr_valid = 0;
    state->return_address = 1;
    return 0;
}

static __always_inline int app_dwarf_unwind_one(
    struct app_dwarf_unwind_state_t *state) {
    u64 lookup_address = state->pc;
    if (state->return_address && lookup_address != 0)
        lookup_address--;
    u64 normalized = 0;
    struct app_dwarf_unwind_info_t *info =
        app_dwarf_find_unwind_info(state, lookup_address, &normalized);
    if (info == NULL)
        return APP_DWARF_STATUS_RULE_MISSING;

    if ((info->flags & APP_DWARF_UNWIND_FLAG_COMMAND) != 0) {
        switch (info->param) {
        case APP_DWARF_UNWIND_COMMAND_STOP:
            return 1;
        case APP_DWARF_UNWIND_COMMAND_FRAME_POINTER:
            return app_dwarf_unwind_frame_pointer(state);
        case APP_DWARF_UNWIND_COMMAND_INVALID:
        case APP_DWARF_UNWIND_COMMAND_SIGNAL:
        default:
            return APP_DWARF_STATUS_INVALID_RULE;
        }
    }
    if ((info->flags & APP_DWARF_UNWIND_FLAG_LEAF_ONLY) != 0 &&
        !state->lr_valid)
        return APP_DWARF_STATUS_INVALID_RULE;
    if (info->base_reg != APP_DWARF_UNWIND_REG_SP &&
        info->base_reg != APP_DWARF_UNWIND_REG_FP)
        return APP_DWARF_STATUS_INVALID_RULE;

    u64 cfa = app_dwarf_register_value(state, info->base_reg) + info->param;
    if (cfa == 0)
        return APP_DWARF_STATUS_INVALID_RULE;

    u64 return_address = 0;
    if (info->aux_base_reg == APP_DWARF_UNWIND_REG_LR) {
        if (!state->lr_valid)
            return APP_DWARF_STATUS_INVALID_RULE;
        return_address = state->lr + info->aux_param;
    } else if (info->aux_base_reg == APP_DWARF_UNWIND_REG_CFA) {
        u64 address = cfa + info->aux_param;
        if ((info->flags & APP_DWARF_UNWIND_FLAG_FRAME) != 0) {
            u64 frame[2] = {};
            if (bpf_probe_read_user(frame, sizeof(frame),
                                    (void *)(address - sizeof(u64))) != 0)
                return APP_DWARF_STATUS_MEMORY_FAULT;
            state->fp = frame[0];
            return_address = frame[1];
        } else if (bpf_probe_read_user(&return_address,
                                       sizeof(return_address),
                                       (void *)address) != 0) {
            return APP_DWARF_STATUS_MEMORY_FAULT;
        }
    } else {
        return APP_DWARF_STATUS_INVALID_RULE;
    }

    /*
     * Normalize a signed return address before exposing it in the event. The
     * same page-table membership check also prevents blindly stripping bits
     * on 48-bit Linux processes. If the caller has no CFI page (for example
     * JIT code), retain the raw address and terminate safely on the next step.
     */
    u64 normalized_return = 0;
    u64 return_lookup = return_address;
    if (return_lookup != 0)
        return_lookup--;
    if (app_dwarf_find_page(state->pid, return_lookup,
                            &normalized_return) != NULL)
        state->pc = normalized_return + (return_address != 0);
    else
        state->pc = return_address;
    state->sp = cfa;
    state->lr_valid = 0;
    state->return_address = 1;
    return 0;
}

static __always_inline int app_collect_dwarf_stack(
    struct pt_regs *ctx, struct app_data_event_t *event) {
#if defined(bpf_target_arm64)
    struct app_dwarf_unwind_state_t state = {
        .pc = (u64)PT_REGS_IP(ctx),
        .sp = (u64)PT_REGS_SP(ctx),
        .fp = (u64)PT_REGS_FP(ctx),
        .lr = (u64)PT_REGS_RET(ctx),
        .pid = event->pid,
        .lr_valid = 1,
    };
    int status = 0;
#pragma unroll
    for (u32 depth = 0; depth < APP_DATA_MAX_STACK_DEPTH; depth++) {
        if (state.pc == 0)
            break;
        event->user_stack[depth] =
            state.pc & 0x00ffffffffffffffULL;
        event->user_stack_depth = depth + 1;
        if (depth + 1 == APP_DATA_MAX_STACK_DEPTH)
            break;
        status = app_dwarf_unwind_one(&state);
        if (status != 0)
            break;
    }
    if (status < 0)
        return status;
    return event->user_stack_depth * sizeof(u64);
#else
    return APP_DWARF_STATUS_UNSUPPORTED;
#endif
}

static __always_inline u64 app_hook_argument(struct pt_regs *ctx, u32 index) {
    /*
     * Keep every pt_regs access at a compile-time constant offset. Without
     * volatile temporaries, LLVM can fold this switch into ctx + index * 8,
     * which the verifier rejects as a dynamic context-pointer dereference.
     */
    volatile u64 argument1 = (u64)PT_REGS_PARM1(ctx);
    volatile u64 argument2 = (u64)PT_REGS_PARM2(ctx);
    volatile u64 argument3 = (u64)PT_REGS_PARM3(ctx);
    volatile u64 argument4 = (u64)PT_REGS_PARM4(ctx);
    volatile u64 argument5 = (u64)PT_REGS_PARM5(ctx);
    volatile u64 argument6 = (u64)PT_REGS_PARM6(ctx);
    switch (index) {
    case 1:
        return argument1;
    case 2:
        return argument2;
    case 3:
        return argument3;
    case 4:
        return argument4;
    case 5:
        return argument5;
    case 6:
        return argument6;
#if defined(bpf_target_arm64)
    case 7:
        return (u64)PT_REGS_PARM7(ctx);
    case 8:
        return (u64)PT_REGS_PARM8(ctx);
    case 9: {
        u64 value = 0;
        bpf_probe_read_user(&value, sizeof(value), (void *)((u64)PT_REGS_SP(ctx)));
        return value;
    }
    case 10: {
        u64 value = 0;
        bpf_probe_read_user(&value, sizeof(value), (void *)((u64)PT_REGS_SP(ctx) + 8));
        return value;
    }
    case 11: {
        u64 value = 0;
        bpf_probe_read_user(&value, sizeof(value), (void *)((u64)PT_REGS_SP(ctx) + 16));
        return value;
    }
    case 12: {
        u64 value = 0;
        bpf_probe_read_user(&value, sizeof(value), (void *)((u64)PT_REGS_SP(ctx) + 24));
        return value;
    }
#elif defined(bpf_target_x86)
    /*
     * SysV amd64 puts a return address at entry SP, followed by arguments
     * seven and later. Keep each user-memory offset compile-time constant.
     */
    case 7: {
        u64 value = 0;
        bpf_probe_read_user(&value, sizeof(value), (void *)((u64)PT_REGS_SP(ctx) + 8));
        return value;
    }
    case 8: {
        u64 value = 0;
        bpf_probe_read_user(&value, sizeof(value), (void *)((u64)PT_REGS_SP(ctx) + 16));
        return value;
    }
    case 9: {
        u64 value = 0;
        bpf_probe_read_user(&value, sizeof(value), (void *)((u64)PT_REGS_SP(ctx) + 24));
        return value;
    }
    case 10: {
        u64 value = 0;
        bpf_probe_read_user(&value, sizeof(value), (void *)((u64)PT_REGS_SP(ctx) + 32));
        return value;
    }
    case 11: {
        u64 value = 0;
        bpf_probe_read_user(&value, sizeof(value), (void *)((u64)PT_REGS_SP(ctx) + 40));
        return value;
    }
    case 12: {
        u64 value = 0;
        bpf_probe_read_user(&value, sizeof(value), (void *)((u64)PT_REGS_SP(ctx) + 48));
        return value;
    }
#endif
    default:
        return 0;
    }
}

/*
 * Android arm64 permits tagged user pointers through Top Byte Ignore (TBI).
 * Native allocators used by Chromium/Cronet commonly return addresses such as
 * 0xb4xx..., while bpf_probe_read_user() expects the canonical user address.
 * Keep scalar arguments unchanged and normalize only values used as memory
 * addresses so lengths, stream IDs, and flags retain their full bit width.
 */
static __always_inline u64 app_hook_user_address(u64 address) {
#if defined(bpf_target_arm64)
    return address & 0x00ffffffffffffffULL;
#else
    return address;
#endif
}

static __always_inline u64 app_hook_deferred_length_address(
    struct pt_regs *ctx, struct app_hook_config_t *config) {
    u64 length_base = app_hook_user_address(
        app_hook_argument(ctx, config->length_arg));
    if (length_base == 0)
        return 0;
    if ((config->flags & APP_DATA_FLAG_LENGTH_INDIRECT) != 0) {
        u64 indirect = 0;
        if (bpf_probe_read_user(&indirect, sizeof(indirect),
                                (void *)(length_base + config->length_offset)) != 0)
            return 0;
        return app_hook_user_address(indirect);
    }
    return length_base + config->length_offset;
}

static __always_inline s64 app_hook_read_signed_length(u64 address, u32 size) {
    address = app_hook_user_address(address);
    if (address == 0)
        return 0;
    switch (size) {
    case 1: {
        s8 value = 0;
        if (bpf_probe_read_user(&value, sizeof(value), (void *)address) == 0)
            return value;
        break;
    }
    case 2: {
        s16 value = 0;
        if (bpf_probe_read_user(&value, sizeof(value), (void *)address) == 0)
            return value;
        break;
    }
    case 4: {
        s32 value = 0;
        if (bpf_probe_read_user(&value, sizeof(value), (void *)address) == 0)
            return value;
        break;
    }
    case 8: {
        s64 value = 0;
        if (bpf_probe_read_user(&value, sizeof(value), (void *)address) == 0)
            return value;
        break;
    }
    }
    return 0;
}

static __always_inline u64 app_hook_read_length(u64 address, u32 size) {
    address = app_hook_user_address(address);
    u64 length = 0;
    switch (size) {
    case 1: {
        u8 value = 0;
        if (bpf_probe_read_user(&value, sizeof(value), (void *)address) == 0)
            length = value;
        break;
    }
    case 2: {
        u16 value = 0;
        if (bpf_probe_read_user(&value, sizeof(value), (void *)address) == 0)
            length = value;
        break;
    }
    case 4: {
        u32 value = 0;
        if (bpf_probe_read_user(&value, sizeof(value), (void *)address) == 0)
            length = value;
        break;
    }
    case 8:
        bpf_probe_read_user(&length, sizeof(length), (void *)address);
        break;
    }
    return length;
}

static __always_inline int app_hook_read_scalar(u64 address, u32 size,
                                                u64 *result) {
    address = app_hook_user_address(address);
    if (result == NULL)
        return -1;
    *result = 0;
    switch (size) {
    case 1: {
        u8 value = 0;
        if (bpf_probe_read_user(&value, sizeof(value), (void *)address) != 0)
            return -1;
        *result = value;
        return 0;
    }
    case 2: {
        u16 value = 0;
        if (bpf_probe_read_user(&value, sizeof(value), (void *)address) != 0)
            return -1;
        *result = value;
        return 0;
    }
    case 4: {
        u32 value = 0;
        if (bpf_probe_read_user(&value, sizeof(value), (void *)address) != 0)
            return -1;
        *result = value;
        return 0;
    }
    case 8:
        return bpf_probe_read_user(result, sizeof(*result), (void *)address);
    default:
        return -1;
    }
}

static __always_inline int app_hook_scalar(struct pt_regs *ctx, u32 argument,
                                           u64 offset, u32 size,
                                           u64 *result) {
    if (argument == 0 || result == NULL)
        return -1;
    u64 value = app_hook_argument(ctx, argument);
    if (size == 0) {
        *result = value;
        return 0;
    }
    if (value == 0)
        return -1;
    return app_hook_read_scalar(app_hook_user_address(value) + offset,
                                size, result);
}

static __always_inline u64 app_hook_identity(struct pt_regs *ctx, u32 argument,
                                             u64 offset, u32 size) {
    u64 value = 0;
    if (app_hook_scalar(ctx, argument, offset, size, &value) != 0)
        return 0;
    return value;
}

static __always_inline int app_hook_resolve(struct pt_regs *ctx, struct app_hook_config_t *config,
                                            u64 *buffer, u64 *length) {
    u64 buffer_base = app_hook_user_address(
        app_hook_argument(ctx, config->buffer_arg));
    if (buffer_base == 0)
        return -1;
    u64 buffer_object = buffer_base + config->buffer_offset;
    if ((config->flags & APP_DATA_FLAG_BUFFER_INDIRECT) != 0) {
        if (bpf_probe_read_user(&buffer_object, sizeof(buffer_object),
                                (void *)buffer_object) != 0)
            return -1;
        buffer_object = app_hook_user_address(buffer_object);
    }
    if (buffer_object == 0)
        return -1;

    /*
     * Android Chromium uses libc++'s alternate std::string layout. The final
     * byte stores the short-string length, or has its high bit set for a long
     * string whose pointer and length live at offsets 0 and 8.
     */
    if ((config->flags & APP_DATA_FLAG_BUFFER_LIBCXX_STRING) != 0) {
        u8 marker = 0;
        if (bpf_probe_read_user(&marker, sizeof(marker), (void *)(buffer_object + 23)) != 0)
            return -1;
        if ((marker & 0x80) != 0) {
            if (bpf_probe_read_user(buffer, sizeof(*buffer), (void *)buffer_object) != 0)
                return -1;
            *buffer = app_hook_user_address(*buffer);
            if (bpf_probe_read_user(length, sizeof(*length), (void *)(buffer_object + 8)) != 0)
                return -1;
        } else {
            *buffer = buffer_object;
            *length = marker;
        }
        return *buffer == 0 || *length == 0 ? -1 : 0;
    }

    *buffer = buffer_object;
    if ((config->flags & APP_DATA_FLAG_LENGTH_FIXED) != 0) {
        *length = config->length_arg;
        return *length == 0 ? -1 : 0;
    }
    if ((config->flags & APP_DATA_FLAG_LENGTH_RETURN) != 0) {
        *length = 0;
        return 0;
    }
    u64 length_base = app_hook_argument(ctx, config->length_arg);
    if ((config->flags & APP_DATA_FLAG_LENGTH_MEMORY) == 0) {
        *length = length_base;
        return *length == 0 ? -1 : 0;
    }
    if (length_base == 0)
        length_base = buffer_base;
    length_base = app_hook_user_address(length_base);
    if ((config->flags & APP_DATA_FLAG_LENGTH_INDIRECT) != 0) {
        u64 indirect = 0;
        if (bpf_probe_read_user(&indirect, sizeof(indirect),
                                (void *)(length_base + config->length_offset)) != 0)
            return -1;
        length_base = indirect;
        length_base = app_hook_user_address(length_base);
        if (length_base == 0)
            return -1;
        *length = app_hook_read_length(length_base, config->length_size);
    } else {
        *length = app_hook_read_length(length_base + config->length_offset,
                                       config->length_size);
    }
    return *length == 0 ? -1 : 0;
}

#define APP_DATA_EMIT_SEG(ctx, event, base, total, max_chunk, seg_idx)                                \
    do {                                                                                              \
        const u32 _off = (u32)(seg_idx) * (max_chunk);                                                \
        if (_off < (total)) {                                                                         \
            u32 _remaining = (total) - _off;                                                          \
            u32 _chunk = _remaining < (max_chunk) ? (_remaining & ((max_chunk)-1)) : (max_chunk);     \
            if (_chunk > 0) {                                                                         \
                (event)->data_len = _chunk;                                                           \
                (event)->chunk_offset = _off;                                                         \
                if (bpf_probe_read_user(&(event)->data, _chunk,                                       \
                                        (void *)((base) + (u64)_off)) == 0) {                          \
                    bpf_perf_event_output(ctx, &app_data_events, BPF_F_CURRENT_CPU, event,             \
                                          APP_DATA_EVENT_HEADER_SIZE + _chunk);                        \
                }                                                                                     \
            }                                                                                         \
        }                                                                                             \
    } while (0)

static __always_inline int app_hook_emit(struct pt_regs *ctx, u32 slot,
                                         struct app_hook_config_t *config,
                                         u64 buffer, u64 length,
                                         u64 context_id, u64 stream_id,
                                         u64 stream_byte_offset,
                                         u32 stream_flags) {
    const bool fin_only =
        length == 0 &&
        (stream_flags & APP_DATA_STREAM_FIN_VALID) != 0 &&
        (stream_flags & APP_DATA_STREAM_FIN) != 0;
    if (!fin_only && (buffer == 0 || length == 0))
        return 0;
    struct app_data_event_t *event =
        bpf_map_lookup_elem(&app_data_buffer_heap, &slot);
    if (event == NULL)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->buffer_addr = buffer;
    event->context_id = context_id;
    event->stream_id = stream_id;
    event->stream_byte_offset = stream_byte_offset;
    event->stream_flags = stream_flags;
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid;
    event->hook_id = slot;
    event->direction = config->direction;
    event->flags = 0;
    event->original_len = length > 0xffffffffULL ? 0xffffffffU : (u32)length;

    u32 maximum = MAX_DATA_SIZE_OPENSSL * APP_DATA_MAX_SEGMENTS;
    if (config->max_bytes != 0 && config->max_bytes < maximum)
        maximum = config->max_bytes;
    u32 captured = event->original_len;
    if (captured > maximum) {
        captured = maximum;
        event->flags |= APP_DATA_EVENT_TRUNCATED;
    }
    event->captured_len = captured;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->user_stack_status = 0;
    event->user_stack_depth = 0;
    event->uid = bpf_get_current_uid_gid();
    event->reserved = 0;
    event->cgroup_id = bpf_get_current_cgroup_id();
    __builtin_memset(event->user_stack, 0, sizeof(event->user_stack));
    if ((config->flags & APP_DATA_FLAG_USER_STACK) != 0) {
        s32 stack_bytes;
        if ((config->flags & APP_DATA_FLAG_DWARF_STACK) != 0)
            stack_bytes = app_collect_dwarf_stack(ctx, event);
        else
            stack_bytes = bpf_get_stack(
                ctx, event->user_stack, sizeof(event->user_stack), BPF_F_USER_STACK);
        event->user_stack_status = stack_bytes;
        if (stack_bytes > 0)
            event->user_stack_depth = (u32)stack_bytes / sizeof(u64);
    }

    /*
     * A QUIC FIN is permitted without stream data. Preserve that transport
     * transition as a metadata-only event; otherwise short responses whose
     * final offset arrives in a zero-length STREAM frame never become
     * complete in the userspace sequencer.
     */
    if (fin_only) {
        event->data_len = 0;
        event->chunk_offset = 0;
        bpf_perf_event_output(ctx, &app_data_events, BPF_F_CURRENT_CPU, event,
                              APP_DATA_EVENT_HEADER_SIZE);
        return 0;
    }

    const u32 chunk = MAX_DATA_SIZE_OPENSSL;
    APP_DATA_EMIT_SEG(ctx, event, buffer, captured, chunk, 0);
    APP_DATA_EMIT_SEG(ctx, event, buffer, captured, chunk, 1);
    APP_DATA_EMIT_SEG(ctx, event, buffer, captured, chunk, 2);
    APP_DATA_EMIT_SEG(ctx, event, buffer, captured, chunk, 3);
    APP_DATA_EMIT_SEG(ctx, event, buffer, captured, chunk, 4);
    APP_DATA_EMIT_SEG(ctx, event, buffer, captured, chunk, 5);
    APP_DATA_EMIT_SEG(ctx, event, buffer, captured, chunk, 6);
    APP_DATA_EMIT_SEG(ctx, event, buffer, captured, chunk, 7);
    return 0;
}

static __noinline int app_hook_read_vector(struct app_iovec_state_t *state,
                                           u32 index,
                                           struct app_iovec_t *vector) {
    if (state == NULL || vector == NULL || state->vector_stride == 0 ||
        index >= state->vector_count || index >= APP_DATA_MAX_IOVECS)
        return -1;

    u64 address = app_hook_user_address(state->iovec_address) +
                  (u64)index * (u64)state->vector_stride;
    if (bpf_probe_read_user(&vector->base, sizeof(vector->base),
                            (void *)(address + state->vector_base_offset)) != 0)
        return -1;
    vector->base = app_hook_user_address(vector->base);

    switch (state->vector_length_size) {
    case 1: {
        u8 value = 0;
        if (bpf_probe_read_user(
                &value, sizeof(value),
                (void *)(address + state->vector_length_offset)) != 0)
            return -1;
        vector->length = value;
        break;
    }
    case 2: {
        u16 value = 0;
        if (bpf_probe_read_user(
                &value, sizeof(value),
                (void *)(address + state->vector_length_offset)) != 0)
            return -1;
        vector->length = value;
        break;
    }
    case 4: {
        u32 value = 0;
        if (bpf_probe_read_user(
                &value, sizeof(value),
                (void *)(address + state->vector_length_offset)) != 0)
            return -1;
        vector->length = value;
        break;
    }
    case 8:
        if (bpf_probe_read_user(
                &vector->length, sizeof(vector->length),
                (void *)(address + state->vector_length_offset)) != 0)
            return -1;
        break;
    default:
        return -1;
    }
    return 0;
}

static __noinline void app_hook_measure_iovec(struct app_iovec_state_t *state,
                                              u32 index) {
    if (state == NULL || state->measurement_failed != 0 ||
        index >= state->vector_count || index >= APP_DATA_MAX_IOVECS)
        return;

    struct app_iovec_t vector = {};
    if (app_hook_read_vector(state, index, &vector) != 0) {
        state->measurement_failed = 1;
        state->flags |= APP_DATA_EVENT_TRUNCATED;
        return;
    }

    u64 available = vector.length;
    if (state->uses_return_len != 0) {
        if (state->measured_len >= state->return_len)
            return;
        u64 remaining = state->return_len - state->measured_len;
        if (available > remaining)
            available = remaining;
    }
    if (~0ULL - state->measured_len < available)
        state->measured_len = ~0ULL;
    else
        state->measured_len += available;
}

#define APP_IOVEC_MEASURE(state, index) app_hook_measure_iovec(state, index)

#define APP_IOVEC_EMIT_CHUNK(ctx, event, state, vector, vector_offset)                    \
    do {                                                                                 \
        if ((state)->measurement_failed == 0 &&                                          \
            (state)->segment_count < APP_DATA_MAX_IOVEC_SEGMENTS &&                      \
            (state)->emitted_len < (state)->captured_len &&                              \
            (vector_offset) < (vector).length) {                                         \
            u64 _vector_remaining = (vector).length - (vector_offset);                   \
            u32 _capture_remaining = (state)->captured_len - (state)->emitted_len;        \
            u32 _chunk = _capture_remaining;                                              \
            if ((u64)_chunk > _vector_remaining)                                          \
                _chunk = (u32)_vector_remaining;                                          \
            if (_chunk > MAX_DATA_SIZE_OPENSSL)                                           \
                _chunk = MAX_DATA_SIZE_OPENSSL;                                           \
            if (_chunk > 0) {                                                             \
                (event)->data_len = _chunk;                                                \
                (event)->chunk_offset = (state)->emitted_len;                              \
                if (bpf_probe_read_user(&(event)->data, _chunk,                            \
                                        (void *)((vector).base + (vector_offset))) == 0) { \
                    bpf_perf_event_output(ctx, &app_data_events, BPF_F_CURRENT_CPU, event, \
                                          APP_DATA_EVENT_HEADER_SIZE + _chunk);            \
                    (vector_offset) += _chunk;                                             \
                    (state)->emitted_len += _chunk;                                        \
                    (state)->segment_count++;                                              \
                } else {                                                                   \
                    /*                                                                     \
                     * Never advance the logical stream past bytes that were not read.     \
                     * Continuing with a later vector would assign it the failed range's   \
                     * offset and manufacture a corrupt, apparently contiguous call.       \
                     */                                                                    \
                    (state)->measurement_failed = 1;                                       \
                    (state)->flags |= APP_DATA_EVENT_TRUNCATED;                            \
                    (event)->flags |= APP_DATA_EVENT_TRUNCATED;                            \
                }                                                                          \
            }                                                                             \
        }                                                                                 \
    } while (0)

static __noinline void app_hook_emit_iovec_vector(struct pt_regs *ctx,
                                                  struct app_data_event_t *event,
                                                  struct app_iovec_state_t *state,
                                                  u32 index) {
    if (state == NULL || event == NULL || index >= state->vector_count ||
        index >= APP_DATA_MAX_IOVECS || state->emitted_len >= state->captured_len)
        return;

    struct app_iovec_t vector = {};
    if (app_hook_read_vector(state, index, &vector) != 0)
        return;

    if (state->uses_return_len != 0) {
        if (state->emit_consumed >= state->return_len)
            return;
        u64 remaining = state->return_len - state->emit_consumed;
        if (vector.length > remaining)
            vector.length = remaining;
    }
    if (~0ULL - state->emit_consumed < vector.length)
        state->emit_consumed = ~0ULL;
    else
        state->emit_consumed += vector.length;
    if (vector.base == 0 || vector.length == 0)
        return;

    u64 vector_offset = 0;
    APP_IOVEC_EMIT_CHUNK(ctx, event, state, vector, vector_offset);
    APP_IOVEC_EMIT_CHUNK(ctx, event, state, vector, vector_offset);
    APP_IOVEC_EMIT_CHUNK(ctx, event, state, vector, vector_offset);
    APP_IOVEC_EMIT_CHUNK(ctx, event, state, vector, vector_offset);
    APP_IOVEC_EMIT_CHUNK(ctx, event, state, vector, vector_offset);
    APP_IOVEC_EMIT_CHUNK(ctx, event, state, vector, vector_offset);
    APP_IOVEC_EMIT_CHUNK(ctx, event, state, vector, vector_offset);
    APP_IOVEC_EMIT_CHUNK(ctx, event, state, vector, vector_offset);
}

#define APP_IOVEC_EMIT_VECTOR(ctx, event, state, index) \
    app_hook_emit_iovec_vector(ctx, event, state, index)

static __noinline int
app_hook_measure_iovec_state(struct app_iovec_state_t *state) {
    if (state == NULL)
        return -1;

    if (state->vector_stride == 0 || state->vector_stride > 256 ||
        state->vector_base_offset + sizeof(u64) > state->vector_stride ||
        state->vector_length_offset + state->vector_length_size >
            state->vector_stride)
        return -1;

    APP_IOVEC_MEASURE(state, 0);
    APP_IOVEC_MEASURE(state, 1);
    APP_IOVEC_MEASURE(state, 2);
    APP_IOVEC_MEASURE(state, 3);
    APP_IOVEC_MEASURE(state, 4);
    APP_IOVEC_MEASURE(state, 5);
    APP_IOVEC_MEASURE(state, 6);
    APP_IOVEC_MEASURE(state, 7);
    APP_IOVEC_MEASURE(state, 8);
    APP_IOVEC_MEASURE(state, 9);
    APP_IOVEC_MEASURE(state, 10);
    APP_IOVEC_MEASURE(state, 11);
    APP_IOVEC_MEASURE(state, 12);
    APP_IOVEC_MEASURE(state, 13);
    APP_IOVEC_MEASURE(state, 14);
    APP_IOVEC_MEASURE(state, 15);

    u64 original = state->measured_len;
    if (state->uses_return_len != 0) {
        original = state->return_len;
        if (state->measured_len < state->return_len)
            state->flags |= APP_DATA_EVENT_TRUNCATED;
    } else if (state->vector_count > APP_DATA_MAX_IOVECS) {
        original = 0xffffffffULL;
        state->flags |= APP_DATA_EVENT_TRUNCATED;
    }
    if (original > 0xffffffffULL) {
        original = 0xffffffffULL;
        state->flags |= APP_DATA_EVENT_TRUNCATED;
    }

    u64 captured = state->measured_len;
    if (state->uses_return_len != 0 && captured > state->return_len)
        captured = state->return_len;
    if (captured > state->maximum)
        captured = state->maximum;
    if (captured > original)
        captured = original;
    state->captured_len = (u32)captured;
    state->original_len = (u32)original;
    if (original > captured)
        state->flags |= APP_DATA_EVENT_TRUNCATED;
    return state->captured_len != 0;
}

static __noinline int
app_hook_emit_iovec_state(struct pt_regs *ctx,
                          struct app_iovec_state_t *state,
                          struct app_data_event_t *event) {
    if (state == NULL || event == NULL ||
        (state->captured_len == 0 && state->fin_only == 0))
        return 0;

    event->timestamp_ns = state->timestamp_ns;
    event->buffer_addr = state->fin_only != 0 ? 0 : state->iovec_address;
    event->context_id = state->context_id;
    event->stream_id = state->stream_id;
    event->stream_byte_offset = state->stream_byte_offset;
    event->stream_flags = state->stream_flags;
    event->hook_id = state->hook_id;
    event->direction = state->direction;
    event->flags = state->flags;
    event->original_len = state->original_len;
    event->captured_len = state->captured_len;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->uid = bpf_get_current_uid_gid();
    event->reserved = 0;
    event->cgroup_id = bpf_get_current_cgroup_id();
    if (state->fin_only != 0) {
        event->chunk_offset = 0;
        event->data_len = 0;
        bpf_perf_event_output(ctx, &app_data_events, BPF_F_CURRENT_CPU, event,
                              APP_DATA_EVENT_HEADER_SIZE);
        return 0;
    }

    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 0);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 1);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 2);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 3);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 4);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 5);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 6);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 7);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 8);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 9);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 10);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 11);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 12);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 13);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 14);
    APP_IOVEC_EMIT_VECTOR(ctx, event, state, 15);
    return 0;
}

static __always_inline int app_hook_emit_iovec(struct pt_regs *ctx, u32 slot,
                                               struct app_hook_config_t *config,
                                               u64 iovec_address, u64 vector_count,
                                               u64 return_len, bool uses_return_len,
                                               u64 context_id, u64 stream_id,
                                               u64 stream_byte_offset,
                                               u32 stream_flags) {
    const bool has_fin =
        (stream_flags & APP_DATA_STREAM_FIN_VALID) != 0 &&
        (stream_flags & APP_DATA_STREAM_FIN) != 0;
    const bool no_data = iovec_address == 0 || vector_count == 0 ||
                         (uses_return_len && return_len == 0);
    if (no_data && !has_fin)
        return 0;

    struct app_iovec_state_t *state =
        bpf_map_lookup_elem(&app_iovec_state_heap, &slot);
    struct app_data_event_t *event =
        bpf_map_lookup_elem(&app_data_buffer_heap, &slot);
    if (state == NULL || event == NULL)
        return 0;

    __builtin_memset(state, 0, sizeof(*state));
    state->iovec_address = app_hook_user_address(iovec_address);
    state->return_len = return_len;
    state->vector_count =
        vector_count > 0xffffffffULL ? 0xffffffffU : (u32)vector_count;
    state->uses_return_len = uses_return_len ? 1 : 0;
    state->vector_stride = config->vector_stride;
    state->vector_base_offset = config->vector_base_offset;
    state->vector_length_offset = config->vector_length_offset;
    state->vector_length_size = config->vector_length_size;
    state->maximum = MAX_DATA_SIZE_OPENSSL * APP_DATA_MAX_IOVEC_SEGMENTS;
    if (config->max_bytes != 0 && config->max_bytes < state->maximum)
        state->maximum = config->max_bytes;
    state->context_id = context_id;
    state->stream_id = stream_id;
    state->stream_byte_offset = stream_byte_offset;
    state->stream_flags = stream_flags;
    state->hook_id = slot;
    state->direction = config->direction;
    state->fin_only = no_data ? 1 : 0;
    if (state->fin_only == 0) {
        int measurement = app_hook_measure_iovec_state(state);
        if (measurement < 0 || (measurement == 0 && !has_fin))
            return 0;
        if (measurement == 0)
            state->fin_only = 1;
    }

    state->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid();
    event->user_stack_status = 0;
    event->user_stack_depth = 0;
    __builtin_memset(event->user_stack, 0, sizeof(event->user_stack));
    if ((config->flags & APP_DATA_FLAG_USER_STACK) != 0) {
        s32 stack_bytes;
        if ((config->flags & APP_DATA_FLAG_DWARF_STACK) != 0)
            stack_bytes = app_collect_dwarf_stack(ctx, event);
        else
            stack_bytes = bpf_get_stack(
                ctx, event->user_stack, sizeof(event->user_stack), BPF_F_USER_STACK);
        event->user_stack_status = stack_bytes;
        if (stack_bytes > 0)
            event->user_stack_depth = (u32)stack_bytes / sizeof(u64);
    }
    return app_hook_emit_iovec_state(ctx, state, event);
}

static __always_inline int app_hook_entry(struct pt_regs *ctx, u32 slot) {
    if (!passes_filter(ctx))
        return 0;
    struct app_hook_config_t *config = bpf_map_lookup_elem(&app_hook_configs, &slot);
    if (config == NULL || config->buffer_arg == 0)
        return 0;
    u64 buffer = 0;
    u64 length = 0;
    u64 context_id = app_hook_identity(
        ctx, config->context_arg, config->context_offset, config->context_size);
    u64 stream_id = app_hook_identity(
        ctx, config->stream_arg, config->stream_offset, config->stream_size);
    u64 stream_byte_offset = 0;
    u32 stream_flags = 0;
    if (config->stream_byte_offset_arg != 0 &&
        app_hook_scalar(ctx, config->stream_byte_offset_arg,
                        config->stream_byte_offset_offset,
                        config->stream_byte_offset_size,
                        &stream_byte_offset) == 0)
        stream_flags |= APP_DATA_STREAM_OFFSET_VALID;
    if (config->fin_arg != 0) {
        u64 fin = 0;
        if (app_hook_scalar(ctx, config->fin_arg, config->fin_offset,
                            config->fin_size, &fin) == 0) {
            stream_flags |= APP_DATA_STREAM_FIN_VALID;
            if (fin != 0)
                stream_flags |= APP_DATA_STREAM_FIN;
        }
    }
    if ((config->flags &
         (APP_DATA_FLAG_BUFFER_IOVEC | APP_DATA_FLAG_BUFFER_MSGHDR)) != 0) {
        u64 iovec_address = app_hook_user_address(
            app_hook_argument(ctx, config->buffer_arg));
        u64 vector_count = app_hook_argument(ctx, config->vector_count_arg);
        if ((config->flags & APP_DATA_FLAG_BUFFER_MSGHDR) != 0) {
            u64 message_header = app_hook_user_address(iovec_address);
            if (message_header == 0 ||
                bpf_probe_read_user(&iovec_address, sizeof(iovec_address),
                                    (void *)(message_header + config->buffer_offset)) != 0)
                return 0;
            iovec_address = app_hook_user_address(iovec_address);
            vector_count = app_hook_read_length(
                message_header + config->length_offset, config->length_size);
        }
        if ((config->flags & APP_DATA_FLAG_CAPTURE_RETURN) == 0)
            return app_hook_emit_iovec(ctx, slot, config, iovec_address,
                                      vector_count, 0, false,
                                      context_id, stream_id,
                                      stream_byte_offset, stream_flags);
        const bool has_fin =
            (stream_flags & APP_DATA_STREAM_FIN_VALID) != 0 &&
            (stream_flags & APP_DATA_STREAM_FIN) != 0;
        if ((iovec_address == 0 || vector_count == 0) && !has_fin)
            return 0;
        struct app_hook_key_t key = {
            .pid_tgid = bpf_get_current_pid_tgid(),
            .slot = slot,
        };
        struct active_app_hook_t active = {
            .buffer = iovec_address,
            .length = vector_count,
            .context_id = context_id,
            .stream_id = stream_id,
            .stream_byte_offset = stream_byte_offset,
            .stream_flags = stream_flags,
            .result_length_address =
                (config->flags & APP_DATA_FLAG_LENGTH_MEMORY) != 0
                    ? app_hook_deferred_length_address(ctx, config)
                    : 0,
        };
        bpf_map_update_elem(&active_app_hooks, &key, &active, BPF_ANY);
        return 0;
    }
    if (app_hook_resolve(ctx, config, &buffer, &length) != 0) {
        if ((stream_flags & APP_DATA_STREAM_FIN_VALID) != 0 &&
            (stream_flags & APP_DATA_STREAM_FIN) != 0)
            return app_hook_emit(ctx, slot, config, buffer, 0,
                                 context_id, stream_id,
                                 stream_byte_offset, stream_flags);
        return 0;
    }
    if ((config->flags & (APP_DATA_FLAG_STATE_SAVE | APP_DATA_FLAG_STATE_LOAD)) != 0) {
        u64 state_value = app_hook_argument(ctx, config->state_key_arg);
        if (state_value == 0 || config->state_id == 0)
            return 0;
        struct app_hook_state_key_t state_key = {
            .tgid = bpf_get_current_pid_tgid() >> 32,
            .value = state_value,
            .state_id = config->state_id,
        };
        if ((config->flags & APP_DATA_FLAG_STATE_SAVE) != 0) {
            struct app_hook_state_t state = {
                .buffer = buffer,
                .maximum_length = length,
            };
            bpf_map_update_elem(&app_hook_states, &state_key, &state, BPF_ANY);
            return 0;
        }
        struct app_hook_state_t *state = bpf_map_lookup_elem(&app_hook_states, &state_key);
        if (state == NULL)
            return 0;
        buffer = state->buffer;
        if (length > state->maximum_length)
            length = state->maximum_length;
        bpf_map_delete_elem(&app_hook_states, &state_key);
    }
    if ((config->flags & APP_DATA_FLAG_CAPTURE_RETURN) == 0)
        return app_hook_emit(ctx, slot, config, buffer, length,
                             context_id, stream_id,
                             stream_byte_offset, stream_flags);

    struct app_hook_key_t key = {
        .pid_tgid = bpf_get_current_pid_tgid(),
        .slot = slot,
    };
    struct active_app_hook_t active = {
        .buffer = buffer,
        .length = length,
        .context_id = context_id,
        .stream_id = stream_id,
        .stream_byte_offset = stream_byte_offset,
        .stream_flags = stream_flags,
    };
    bpf_map_update_elem(&active_app_hooks, &key, &active, BPF_ANY);
    return 0;
}

static __always_inline s64 app_hook_signed_return(struct pt_regs *ctx,
                                                  struct app_hook_config_t *config) {
    u64 raw = (u64)PT_REGS_RC(ctx);
    if (config != NULL && config->length_size == 4)
        return (s64)(s32)(u32)raw;
    return (s64)raw;
}

static __always_inline int app_hook_return(struct pt_regs *ctx, u32 slot) {
    if (!passes_filter(ctx))
        return 0;
    struct app_hook_key_t key = {
        .pid_tgid = bpf_get_current_pid_tgid(),
        .slot = slot,
    };
    struct active_app_hook_t *active = bpf_map_lookup_elem(&active_app_hooks, &key);
    if (active == NULL)
        return 0;
    struct app_hook_config_t *config = bpf_map_lookup_elem(&app_hook_configs, &slot);
    if (config != NULL) {
        if ((config->flags &
             (APP_DATA_FLAG_BUFFER_IOVEC | APP_DATA_FLAG_BUFFER_MSGHDR)) != 0) {
            s64 result =
                (config->flags & APP_DATA_FLAG_LENGTH_MEMORY) != 0
                    ? app_hook_read_signed_length(active->result_length_address,
                                                  config->length_size)
                    : app_hook_signed_return(ctx, config);
            const bool has_fin =
                (active->stream_flags & APP_DATA_STREAM_FIN_VALID) != 0 &&
                (active->stream_flags & APP_DATA_STREAM_FIN) != 0;
            if (result > 0 || (result == 0 && has_fin))
                app_hook_emit_iovec(ctx, slot, config, active->buffer,
                                    active->length, (u64)result, true,
                                    active->context_id, active->stream_id,
                                    active->stream_byte_offset,
                                    active->stream_flags);
            bpf_map_delete_elem(&active_app_hooks, &key);
            return 0;
        }
        u64 length = active->length;
        if ((config->flags & APP_DATA_FLAG_LENGTH_RETURN) != 0) {
            s64 result = app_hook_signed_return(ctx, config);
            length = result > 0 ? (u64)result : 0;
        }
        app_hook_emit(ctx, slot, config, active->buffer, length,
                      active->context_id, active->stream_id,
                      active->stream_byte_offset, active->stream_flags);
    }
    bpf_map_delete_elem(&active_app_hooks, &key);
    return 0;
}

#define APP_HOOK_PROGRAMS(slot)                                                                    \
    SEC("uprobe/app_data_" #slot)                                                                  \
    int probe_entry_app_data_##slot(struct pt_regs *ctx) { return app_hook_entry(ctx, slot); }      \
    SEC("uretprobe/app_data_" #slot)                                                               \
    int probe_ret_app_data_##slot(struct pt_regs *ctx) { return app_hook_return(ctx, slot); }

APP_HOOK_PROGRAMS(0)
APP_HOOK_PROGRAMS(1)
APP_HOOK_PROGRAMS(2)
APP_HOOK_PROGRAMS(3)
APP_HOOK_PROGRAMS(4)
APP_HOOK_PROGRAMS(5)
APP_HOOK_PROGRAMS(6)
APP_HOOK_PROGRAMS(7)

#endif
