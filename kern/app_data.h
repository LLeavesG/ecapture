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
#define APP_DATA_EVENT_TRUNCATED 0x01

struct app_hook_config_t {
    u32 buffer_arg;
    u32 length_arg;
    u32 direction;
    u32 flags;
    u64 buffer_offset;
    u64 length_offset;
    u32 length_size;
    u32 max_bytes;
};

struct active_app_hook_t {
    u64 buffer;
    u64 length;
};

struct app_hook_key_t {
    u64 pid_tgid;
    u32 slot;
    u32 pad;
};

struct app_data_event_t {
    u64 timestamp_ns;
    u64 buffer_addr;
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
    char data[MAX_DATA_SIZE_OPENSSL];
};

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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct app_data_event_t);
    __uint(max_entries, 1);
} app_data_buffer_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} app_data_events SEC(".maps");

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
    default:
        return 0;
    }
}

static __always_inline u64 app_hook_read_length(u64 address, u32 size) {
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

static __always_inline int app_hook_resolve(struct pt_regs *ctx, struct app_hook_config_t *config,
                                            u64 *buffer, u64 *length) {
    u64 buffer_base = app_hook_argument(ctx, config->buffer_arg);
    if (buffer_base == 0)
        return -1;
    if ((config->flags & APP_DATA_FLAG_BUFFER_INDIRECT) != 0) {
        if (bpf_probe_read_user(buffer, sizeof(*buffer),
                                (void *)(buffer_base + config->buffer_offset)) != 0)
            return -1;
    } else {
        *buffer = buffer_base + config->buffer_offset;
    }
    if (*buffer == 0)
        return -1;

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
    if ((config->flags & APP_DATA_FLAG_LENGTH_INDIRECT) != 0) {
        u64 indirect = 0;
        if (bpf_probe_read_user(&indirect, sizeof(indirect),
                                (void *)(length_base + config->length_offset)) != 0)
            return -1;
        length_base = indirect;
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
                                          sizeof(struct app_data_event_t));                            \
                }                                                                                     \
            }                                                                                         \
        }                                                                                             \
    } while (0)

static __always_inline int app_hook_emit(struct pt_regs *ctx, u32 slot,
                                         struct app_hook_config_t *config,
                                         u64 buffer, u64 length) {
    if (buffer == 0 || length == 0)
        return 0;
    u32 zero = 0;
    struct app_data_event_t *event = bpf_map_lookup_elem(&app_data_buffer_heap, &zero);
    if (event == NULL)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->buffer_addr = buffer;
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

static __always_inline int app_hook_entry(struct pt_regs *ctx, u32 slot) {
    if (!passes_filter(ctx))
        return 0;
    struct app_hook_config_t *config = bpf_map_lookup_elem(&app_hook_configs, &slot);
    if (config == NULL || config->buffer_arg == 0)
        return 0;
    u64 buffer = 0;
    u64 length = 0;
    if (app_hook_resolve(ctx, config, &buffer, &length) != 0)
        return 0;
    if ((config->flags & APP_DATA_FLAG_CAPTURE_RETURN) == 0)
        return app_hook_emit(ctx, slot, config, buffer, length);

    struct app_hook_key_t key = {
        .pid_tgid = bpf_get_current_pid_tgid(),
        .slot = slot,
    };
    struct active_app_hook_t active = {
        .buffer = buffer,
        .length = length,
    };
    bpf_map_update_elem(&active_app_hooks, &key, &active, BPF_ANY);
    return 0;
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
        u64 length = active->length;
        if ((config->flags & APP_DATA_FLAG_LENGTH_RETURN) != 0) {
            s64 result = (s64)PT_REGS_RC(ctx);
            length = result > 0 ? (u64)result : 0;
        }
        app_hook_emit(ctx, slot, config, active->buffer, length);
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
