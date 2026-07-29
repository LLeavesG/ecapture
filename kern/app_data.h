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
#define APP_DATA_EVENT_TRUNCATED 0x01
#define APP_DATA_MAX_IOVECS 16
#define APP_DATA_MAX_IOVEC_SEGMENTS 8

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
};

struct active_app_hook_t {
    u64 buffer;
    u64 length;
    u64 context_id;
    u64 stream_id;
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
    u32 vector_count;
    u32 maximum;
    u32 captured_len;
    u32 emitted_len;
    u32 segment_count;
    u32 flags;
    u32 uses_return_len;
    u32 measurement_failed;
};

struct app_data_event_t {
    u64 timestamp_ns;
    u64 buffer_addr;
    u64 context_id;
    u64 stream_id;
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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct app_data_event_t);
    __uint(max_entries, 1);
} app_data_buffer_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct app_iovec_state_t);
    __uint(max_entries, 1);
} app_iovec_state_heap SEC(".maps");

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
    u64 buffer_object = buffer_base + config->buffer_offset;
    if ((config->flags & APP_DATA_FLAG_BUFFER_INDIRECT) != 0) {
        if (bpf_probe_read_user(&buffer_object, sizeof(buffer_object),
                                (void *)buffer_object) != 0)
            return -1;
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
                                         u64 buffer, u64 length,
                                         u64 context_id, u64 stream_id) {
    if (buffer == 0 || length == 0)
        return 0;
    u32 zero = 0;
    struct app_data_event_t *event = bpf_map_lookup_elem(&app_data_buffer_heap, &zero);
    if (event == NULL)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->buffer_addr = buffer;
    event->context_id = context_id;
    event->stream_id = stream_id;
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

static __noinline void app_hook_measure_iovec(struct app_iovec_state_t *state,
                                              u32 index) {
    if (state == NULL || state->measurement_failed != 0 ||
        index >= state->vector_count || index >= APP_DATA_MAX_IOVECS)
        return;

    struct app_iovec_t vector = {};
    u64 address = state->iovec_address + (u64)index * sizeof(vector);
    if (bpf_probe_read_user(&vector, sizeof(vector), (void *)address) != 0) {
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
        if ((state)->segment_count < APP_DATA_MAX_IOVEC_SEGMENTS &&                      \
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
                                        (void *)((vector).base + (vector_offset))) == 0)   \
                    bpf_perf_event_output(ctx, &app_data_events, BPF_F_CURRENT_CPU, event, \
                                          sizeof(struct app_data_event_t));                \
                (vector_offset) += _chunk;                                                 \
                (state)->emitted_len += _chunk;                                            \
                (state)->segment_count++;                                                  \
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
    u64 address = state->iovec_address + (u64)index * sizeof(vector);
    if (bpf_probe_read_user(&vector, sizeof(vector), (void *)address) != 0)
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

static __always_inline int app_hook_emit_iovec(struct pt_regs *ctx, u32 slot,
                                               struct app_hook_config_t *config,
                                               u64 iovec_address, u64 vector_count,
                                               u64 return_len, bool uses_return_len,
                                               u64 context_id, u64 stream_id) {
    if (iovec_address == 0 || vector_count == 0 ||
        (uses_return_len && return_len == 0))
        return 0;

    u32 zero = 0;
    struct app_iovec_state_t *state = bpf_map_lookup_elem(&app_iovec_state_heap, &zero);
    struct app_data_event_t *event = bpf_map_lookup_elem(&app_data_buffer_heap, &zero);
    if (state == NULL || event == NULL)
        return 0;

    __builtin_memset(state, 0, sizeof(*state));
    state->iovec_address = iovec_address;
    state->return_len = return_len;
    state->vector_count =
        vector_count > 0xffffffffULL ? 0xffffffffU : (u32)vector_count;
    state->uses_return_len = uses_return_len ? 1 : 0;
    state->maximum = MAX_DATA_SIZE_OPENSSL * APP_DATA_MAX_IOVEC_SEGMENTS;
    if (config->max_bytes != 0 && config->max_bytes < state->maximum)
        state->maximum = config->max_bytes;

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
    if (uses_return_len) {
        original = return_len;
        if (state->measured_len < return_len)
            state->flags |= APP_DATA_EVENT_TRUNCATED;
    } else if (vector_count > APP_DATA_MAX_IOVECS) {
        original = 0xffffffffULL;
        state->flags |= APP_DATA_EVENT_TRUNCATED;
    }
    if (original > 0xffffffffULL) {
        original = 0xffffffffULL;
        state->flags |= APP_DATA_EVENT_TRUNCATED;
    }

    u64 captured = state->measured_len;
    if (uses_return_len && captured > return_len)
        captured = return_len;
    if (captured > state->maximum)
        captured = state->maximum;
    if (captured > original)
        captured = original;
    state->captured_len = (u32)captured;
    if (original > captured)
        state->flags |= APP_DATA_EVENT_TRUNCATED;
    if (state->captured_len == 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    state->timestamp_ns = bpf_ktime_get_ns();
    event->timestamp_ns = state->timestamp_ns;
    event->buffer_addr = iovec_address;
    event->context_id = context_id;
    event->stream_id = stream_id;
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid;
    event->hook_id = slot;
    event->direction = config->direction;
    event->flags = state->flags;
    event->original_len = (u32)original;
    event->captured_len = state->captured_len;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

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

static __always_inline int app_hook_entry(struct pt_regs *ctx, u32 slot) {
    if (!passes_filter(ctx))
        return 0;
    struct app_hook_config_t *config = bpf_map_lookup_elem(&app_hook_configs, &slot);
    if (config == NULL || config->buffer_arg == 0)
        return 0;
    u64 buffer = 0;
    u64 length = 0;
    u64 context_id = app_hook_argument(ctx, config->context_arg);
    u64 stream_id = app_hook_argument(ctx, config->stream_arg);
    if ((config->flags &
         (APP_DATA_FLAG_BUFFER_IOVEC | APP_DATA_FLAG_BUFFER_MSGHDR)) != 0) {
        u64 iovec_address = app_hook_argument(ctx, config->buffer_arg);
        u64 vector_count = app_hook_argument(ctx, config->vector_count_arg);
        if ((config->flags & APP_DATA_FLAG_BUFFER_MSGHDR) != 0) {
            u64 message_header = iovec_address;
            if (message_header == 0 ||
                bpf_probe_read_user(&iovec_address, sizeof(iovec_address),
                                    (void *)(message_header + config->buffer_offset)) != 0)
                return 0;
            vector_count = app_hook_read_length(
                message_header + config->length_offset, config->length_size);
        }
        if ((config->flags & APP_DATA_FLAG_CAPTURE_RETURN) == 0)
            return app_hook_emit_iovec(ctx, slot, config, iovec_address,
                                      vector_count, 0, false,
                                      context_id, stream_id);
        if (iovec_address == 0 || vector_count == 0)
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
        };
        bpf_map_update_elem(&active_app_hooks, &key, &active, BPF_ANY);
        return 0;
    }
    if (app_hook_resolve(ctx, config, &buffer, &length) != 0)
        return 0;
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
        return app_hook_emit(ctx, slot, config, buffer, length, context_id, stream_id);

    struct app_hook_key_t key = {
        .pid_tgid = bpf_get_current_pid_tgid(),
        .slot = slot,
    };
    struct active_app_hook_t active = {
        .buffer = buffer,
        .length = length,
        .context_id = context_id,
        .stream_id = stream_id,
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
        if ((config->flags &
             (APP_DATA_FLAG_BUFFER_IOVEC | APP_DATA_FLAG_BUFFER_MSGHDR)) != 0) {
            s64 result = (s64)PT_REGS_RC(ctx);
            if (result > 0)
                app_hook_emit_iovec(ctx, slot, config, active->buffer,
                                    active->length, (u64)result, true,
                                    active->context_id, active->stream_id);
            bpf_map_delete_elem(&active_app_hooks, &key);
            return 0;
        }
        u64 length = active->length;
        if ((config->flags & APP_DATA_FLAG_LENGTH_RETURN) != 0) {
            s64 result = (s64)PT_REGS_RC(ctx);
            length = result > 0 ? (u64)result : 0;
        }
        app_hook_emit(ctx, slot, config, active->buffer, length,
                      active->context_id, active->stream_id);
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
