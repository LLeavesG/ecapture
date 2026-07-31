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

#ifndef ECAPTURE_JNI_CONVERSION_H
#define ECAPTURE_JNI_CONVERSION_H

#define JNI_CONVERSION_MAX_SEGMENTS 8
#define JNI_CONVERSION_STATE_TTL_NS 5000000000ULL

#define JNI_CONVERSION_FLAG_HAS_BUFFER 0x01
#define JNI_CONVERSION_FLAG_HAS_LENGTH 0x02
#define JNI_CONVERSION_FLAG_HAS_DATA 0x04
#define JNI_CONVERSION_FLAG_TRUNCATED 0x08
#define JNI_CONVERSION_FLAG_JOINED 0x10
#define JNI_CONVERSION_FLAG_LENGTH_LOWER_BOUND 0x20
#define JNI_CONVERSION_FLAG_LENGTH_IS_ELEMENTS 0x40

enum jni_conversion_role {
    kJNIGetStringLength = 1,
    kJNIGetStringChars = 2,
    kJNIReleaseStringChars = 3,
    kJNIGetStringUTFLength = 4,
    kJNIGetStringUTFChars = 5,
    kJNIReleaseStringUTFChars = 6,
    kJNIGetArrayLength = 7,
    kJNIGetByteArrayElements = 8,
    kJNIReleaseByteArrayElements = 9,
    kJNIGetByteArrayRegion = 10,
    kJNISetByteArrayRegion = 11,
    kJNIGetPrimitiveArrayCritical = 12,
    kJNIReleasePrimitiveArrayCritical = 13,
    kJNIGetStringCritical = 14,
    kJNIReleaseStringCritical = 15,
    kJNIGetDirectBufferAddress = 16,
    kJNIGetDirectBufferCapacity = 17,
};

enum jni_conversion_phase {
    kJNIPhaseAcquire = 1,
    kJNIPhaseRelease = 2,
    kJNIPhaseRegion = 3,
    kJNIPhaseLength = 4,
};

struct jni_conversion_active_key_t {
    u64 pid_tgid;
    u32 role;
    u32 pad;
};

struct jni_conversion_caller_key_t {
    u32 pid;
    u32 role;
    u64 caller_addr;
};

struct jni_conversion_active_t {
    u64 env;
    u64 object;
    u64 buffer;
    u64 byte_length;
    u64 element_count;
    u64 region_start;
    u64 caller_addr;
};

struct jni_object_key_t {
    u64 pid_tgid;
    u64 env;
    u64 object;
};

struct jni_object_state_t {
    u64 buffer;
    u64 byte_length;
    u64 element_count;
    u64 caller_addr;
    u64 timestamp_ns;
    u32 buffer_role;
    u32 element_width;
};

struct jni_conversion_event_t {
    u64 timestamp_ns;
    u64 env;
    u64 object;
    u64 buffer_addr;
    u64 caller_addr;
    u64 byte_length;
    u64 element_count;
    u64 region_start;
    u32 pid;
    u32 tid;
    u32 role;
    u32 phase;
    u32 flags;
    u32 captured_len;
    u32 chunk_offset;
    u32 data_len;
    char comm[TASK_COMM_LEN];
    char data[MAX_DATA_SIZE_OPENSSL];
};

#define JNI_CONVERSION_HEADER_SIZE                                           \
    (sizeof(struct jni_conversion_event_t) - MAX_DATA_SIZE_OPENSSL)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct jni_conversion_active_key_t);
    __type(value, struct jni_conversion_active_t);
    __uint(max_entries, 1024);
} active_jni_conversions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct jni_object_key_t);
    __type(value, struct jni_object_state_t);
    __uint(max_entries, 4096);
} jni_object_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct jni_conversion_event_t);
    __uint(max_entries, 1);
} jni_conversion_buffer_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} jni_conversion_events SEC(".maps");

// Caller rules are populated in userspace after translating module-relative
// profile offsets through /proc/PID/maps. A PID is absent from
// jni_conversion_filter_pids during its short bootstrap window; once all
// configured modules resolve, only exact (PID, role, caller) entries pass.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct jni_conversion_caller_key_t);
    __type(value, u8);
    __uint(max_entries, 32768);
} jni_conversion_allowed_callers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, u8);
    __uint(max_entries, 1024);
} jni_conversion_filter_pids SEC(".maps");

static __always_inline u64 jni_conversion_caller(struct pt_regs *ctx) {
#if defined(bpf_target_arm64)
    // Strip the arm64 top-byte tag/PAC storage bits so userspace can rebuild
    // the same address deterministically from the executable mapping.
    return (u64)PT_REGS_RET(ctx) & 0x00ffffffffffffffULL;
#elif defined(bpf_target_x86)
    u64 caller = 0;
    bpf_probe_read_user(
        &caller, sizeof(caller), (void *)((u64)PT_REGS_SP(ctx)));
    return caller;
#else
    return 0;
#endif
}

static __always_inline int jni_conversion_caller_allowed(
    u32 role, u64 caller_addr) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *enabled =
        bpf_map_lookup_elem(&jni_conversion_filter_pids, &pid);
    if (enabled == NULL || *enabled == 0)
        return 1;
    struct jni_conversion_caller_key_t key = {
        .pid = pid,
        .role = role,
        .caller_addr = caller_addr,
    };
    return bpf_map_lookup_elem(
               &jni_conversion_allowed_callers, &key) != NULL;
}

static __always_inline struct jni_object_state_t *jni_object_state(
    struct jni_object_key_t *key, u64 timestamp_ns) {
    struct jni_object_state_t *state =
        bpf_map_lookup_elem(&jni_object_states, key);
    if (state == NULL) {
        struct jni_object_state_t initial = {
            .timestamp_ns = timestamp_ns,
        };
        bpf_map_update_elem(&jni_object_states, key, &initial, BPF_ANY);
        state = bpf_map_lookup_elem(&jni_object_states, key);
    } else if (timestamp_ns > state->timestamp_ns &&
               timestamp_ns - state->timestamp_ns >
                   JNI_CONVERSION_STATE_TTL_NS) {
        state->buffer = 0;
        state->byte_length = 0;
        state->element_count = 0;
        state->caller_addr = 0;
        state->buffer_role = 0;
        state->element_width = 0;
        state->timestamp_ns = timestamp_ns;
    }
    return state;
}

static __always_inline struct jni_conversion_event_t *jni_conversion_event(
    struct jni_conversion_active_t *active, u32 role, u32 phase) {
    u32 zero = 0;
    struct jni_conversion_event_t *event =
        bpf_map_lookup_elem(&jni_conversion_buffer_heap, &zero);
    if (event == NULL)
        return NULL;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->env = active->env;
    event->object = active->object;
    event->buffer_addr = active->buffer;
    event->caller_addr = active->caller_addr;
    event->byte_length = active->byte_length;
    event->element_count = active->element_count;
    event->region_start = active->region_start;
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid;
    event->role = role;
    event->phase = phase;
    event->flags = 0;
    if (active->buffer != 0)
        event->flags |= JNI_CONVERSION_FLAG_HAS_BUFFER;
    if (active->byte_length != 0 || active->element_count != 0)
        event->flags |= JNI_CONVERSION_FLAG_HAS_LENGTH;
    event->captured_len = 0;
    event->chunk_offset = 0;
    event->data_len = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    return event;
}

static __always_inline void jni_emit_metadata(
    struct pt_regs *ctx, struct jni_conversion_active_t *active, u32 role,
    u32 phase, u32 flags) {
    struct jni_conversion_event_t *event =
        jni_conversion_event(active, role, phase);
    if (event == NULL)
        return;
    event->flags |= flags;
    bpf_perf_event_output(
        ctx, &jni_conversion_events, BPF_F_CURRENT_CPU, event,
        JNI_CONVERSION_HEADER_SIZE);
}

#define JNI_CONVERSION_EMIT_SEG(ctx, event, base, total, seg_idx)             \
    do {                                                                       \
        const u32 _off = (u32)(seg_idx) * MAX_DATA_SIZE_OPENSSL;              \
        if (_off < (total)) {                                                  \
            u32 _remaining = (total) - _off;                                  \
            u32 _chunk = _remaining < MAX_DATA_SIZE_OPENSSL                   \
                             ? (_remaining & (MAX_DATA_SIZE_OPENSSL - 1))      \
                             : MAX_DATA_SIZE_OPENSSL;                          \
            if (_chunk > 0) {                                                  \
                (event)->data_len = _chunk;                                   \
                (event)->chunk_offset = _off;                                 \
                if (bpf_probe_read_user(                                      \
                        &(event)->data, _chunk,                               \
                        (void *)((base) + (u64)_off)) == 0)                   \
                    bpf_perf_event_output(                                    \
                        ctx, &jni_conversion_events, BPF_F_CURRENT_CPU,        \
                        event, sizeof(struct jni_conversion_event_t));         \
            }                                                                  \
        }                                                                      \
    } while (0)

static __always_inline void jni_emit_data(
    struct pt_regs *ctx, struct jni_conversion_active_t *active, u32 role,
    u32 phase, u32 extra_flags) {
    if (active->buffer == 0 || active->byte_length == 0) {
        return;
    }
    struct jni_conversion_event_t *event =
        jni_conversion_event(active, role, phase);
    if (event == NULL)
        return;
    event->flags |=
        extra_flags | JNI_CONVERSION_FLAG_HAS_DATA |
        JNI_CONVERSION_FLAG_HAS_BUFFER | JNI_CONVERSION_FLAG_HAS_LENGTH;
    u64 maximum =
        (u64)MAX_DATA_SIZE_OPENSSL * JNI_CONVERSION_MAX_SEGMENTS;
    u64 bounded = active->byte_length;
    if (bounded > maximum) {
        bounded = maximum;
        event->flags |= JNI_CONVERSION_FLAG_TRUNCATED;
    }
    u32 captured = (u32)bounded;
    event->captured_len = captured;
    JNI_CONVERSION_EMIT_SEG(ctx, event, active->buffer, captured, 0);
    JNI_CONVERSION_EMIT_SEG(ctx, event, active->buffer, captured, 1);
    JNI_CONVERSION_EMIT_SEG(ctx, event, active->buffer, captured, 2);
    JNI_CONVERSION_EMIT_SEG(ctx, event, active->buffer, captured, 3);
    JNI_CONVERSION_EMIT_SEG(ctx, event, active->buffer, captured, 4);
    JNI_CONVERSION_EMIT_SEG(ctx, event, active->buffer, captured, 5);
    JNI_CONVERSION_EMIT_SEG(ctx, event, active->buffer, captured, 6);
    JNI_CONVERSION_EMIT_SEG(ctx, event, active->buffer, captured, 7);
}

static __always_inline void jni_emit_utf_string(
    struct pt_regs *ctx, struct jni_conversion_active_t *active, u32 role) {
    if (active->buffer == 0) {
        return;
    }
    struct jni_conversion_event_t *event =
        jni_conversion_event(active, role, kJNIPhaseAcquire);
    if (event == NULL)
        return;
    int length = bpf_probe_read_user_str(
        &event->data, sizeof(event->data), (void *)active->buffer);
    if (length <= 1) {
        return;
    }
    u32 data_length = (u32)length - 1;
    event->byte_length = data_length;
    event->captured_len = data_length;
    event->data_len = data_length;
    event->flags |= JNI_CONVERSION_FLAG_HAS_BUFFER |
                    JNI_CONVERSION_FLAG_HAS_LENGTH |
                    JNI_CONVERSION_FLAG_HAS_DATA;
    if (length == sizeof(event->data)) {
        event->flags |= JNI_CONVERSION_FLAG_TRUNCATED |
                        JNI_CONVERSION_FLAG_LENGTH_LOWER_BOUND;
    }
    bpf_perf_event_output(
        ctx, &jni_conversion_events, BPF_F_CURRENT_CPU, event,
        sizeof(struct jni_conversion_event_t));
}

static __always_inline int jni_conversion_begin(
    struct pt_regs *ctx, u32 role) {
    if (!passes_filter(ctx))
        return 0;
    u64 caller_addr = jni_conversion_caller(ctx);
    if (!jni_conversion_caller_allowed(role, caller_addr))
        return 0;
    struct jni_conversion_active_key_t key = {
        .pid_tgid = bpf_get_current_pid_tgid(),
        .role = role,
    };
    struct jni_conversion_active_t active = {
        .env = (u64)PT_REGS_PARM1(ctx),
        .object = (u64)PT_REGS_PARM2(ctx),
        .caller_addr = caller_addr,
    };
    if (active.env == 0 || active.object == 0)
        return 0;
    bpf_map_update_elem(&active_jni_conversions, &key, &active, BPF_ANY);
    return 0;
}

static __always_inline int jni_conversion_length_return(
    struct pt_regs *ctx, u32 role) {
    if (!passes_filter(ctx))
        return 0;
    struct jni_conversion_active_key_t active_key = {
        .pid_tgid = bpf_get_current_pid_tgid(),
        .role = role,
    };
    struct jni_conversion_active_t *active =
        bpf_map_lookup_elem(&active_jni_conversions, &active_key);
    if (active == NULL)
        return 0;
    s64 signed_length = (s64)PT_REGS_RC(ctx);
    if (signed_length < 0) {
        bpf_map_delete_elem(&active_jni_conversions, &active_key);
        return 0;
    }
    u64 length = (u64)signed_length;
    u64 now = bpf_ktime_get_ns();
    struct jni_object_key_t object_key = {
        .pid_tgid = active_key.pid_tgid,
        .env = active->env,
        .object = active->object,
    };
    struct jni_object_state_t *state =
        jni_object_state(&object_key, now);
    if (role == kJNIGetStringLength) {
        active->element_count = length;
        active->byte_length =
            length > (~0ULL / 2) ? ~0ULL : length * 2;
    } else if (role == kJNIGetArrayLength) {
        active->element_count = length;
    } else {
        active->byte_length = length;
    }
    if (state != NULL) {
        state->timestamp_ns = now;
        if (role == kJNIGetStringLength) {
            state->element_count = active->element_count;
            state->byte_length = active->byte_length;
        } else if (role == kJNIGetArrayLength) {
            state->element_count = length;
            if (state->buffer_role == kJNIGetByteArrayElements)
                state->byte_length = length;
        } else {
            state->byte_length = length;
        }
        if (state->buffer != 0) {
            active->buffer = state->buffer;
            active->caller_addr = state->caller_addr;
            active->byte_length = state->byte_length;
            active->element_count = state->element_count;
            if (state->buffer_role == kJNIGetPrimitiveArrayCritical) {
                jni_emit_metadata(
                    ctx, active, state->buffer_role, kJNIPhaseAcquire,
                    JNI_CONVERSION_FLAG_JOINED |
                        JNI_CONVERSION_FLAG_LENGTH_IS_ELEMENTS);
            } else {
                jni_emit_data(
                    ctx, active, state->buffer_role, kJNIPhaseAcquire,
                    JNI_CONVERSION_FLAG_JOINED);
            }
            bpf_map_delete_elem(&active_jni_conversions, &active_key);
            return 0;
        }
    }
    bpf_map_delete_elem(&active_jni_conversions, &active_key);
    return 0;
}

static __always_inline u32 jni_conversion_element_width(u32 role) {
    if (role == kJNIGetStringChars || role == kJNIGetStringCritical)
        return 2;
    if (role == kJNIGetStringUTFChars ||
        role == kJNIGetByteArrayElements ||
        role == kJNIGetDirectBufferAddress)
        return 1;
    return 0;
}

static __always_inline int jni_conversion_pointer_return(
    struct pt_regs *ctx, u32 role) {
    if (!passes_filter(ctx))
        return 0;
    struct jni_conversion_active_key_t active_key = {
        .pid_tgid = bpf_get_current_pid_tgid(),
        .role = role,
    };
    struct jni_conversion_active_t *active =
        bpf_map_lookup_elem(&active_jni_conversions, &active_key);
    if (active == NULL)
        return 0;
    active->buffer = (u64)PT_REGS_RC(ctx);
    if (active->buffer == 0) {
        bpf_map_delete_elem(&active_jni_conversions, &active_key);
        return 0;
    }
    u64 now = bpf_ktime_get_ns();
    struct jni_object_key_t object_key = {
        .pid_tgid = active_key.pid_tgid,
        .env = active->env,
        .object = active->object,
    };
    struct jni_object_state_t *state =
        jni_object_state(&object_key, now);
    u32 width = jni_conversion_element_width(role);
    if (state != NULL) {
        state->buffer = active->buffer;
        state->caller_addr = active->caller_addr;
        state->buffer_role = role;
        state->element_width = width;
        state->timestamp_ns = now;
        if (state->byte_length == 0 && state->element_count != 0 &&
            width != 0) {
            state->byte_length =
                state->element_count > (~0ULL / width)
                    ? ~0ULL
                    : state->element_count * width;
        }
        active->byte_length = state->byte_length;
        active->element_count = state->element_count;
    }
    if (role == kJNIGetStringUTFChars && active->byte_length == 0)
        jni_emit_utf_string(ctx, active, role);
    else if (active->byte_length != 0 && width != 0)
        jni_emit_data(
            ctx, active, role, kJNIPhaseAcquire,
            JNI_CONVERSION_FLAG_JOINED);
    bpf_map_delete_elem(&active_jni_conversions, &active_key);
    return 0;
}

static __always_inline int jni_conversion_release(
    struct pt_regs *ctx, u32 role, u32 acquire_role) {
    if (!passes_filter(ctx))
        return 0;
    u64 caller_addr = jni_conversion_caller(ctx);
    if (!jni_conversion_caller_allowed(role, caller_addr))
        return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct jni_conversion_active_t active = {
        .env = (u64)PT_REGS_PARM1(ctx),
        .object = (u64)PT_REGS_PARM2(ctx),
        .buffer = (u64)PT_REGS_PARM3(ctx),
        .caller_addr = caller_addr,
    };
    if (active.env == 0 || active.object == 0)
        return 0;
    struct jni_object_key_t object_key = {
        .pid_tgid = pid_tgid,
        .env = active.env,
        .object = active.object,
    };
    struct jni_object_state_t *state =
        bpf_map_lookup_elem(&jni_object_states, &object_key);
    if (state != NULL) {
        if (active.buffer == 0)
            active.buffer = state->buffer;
        active.byte_length = state->byte_length;
        active.element_count = state->element_count;
        if (acquire_role == kJNIGetPrimitiveArrayCritical &&
            active.element_count != 0) {
            jni_emit_metadata(
                ctx, &active, role, kJNIPhaseRelease,
                JNI_CONVERSION_FLAG_JOINED |
                    JNI_CONVERSION_FLAG_LENGTH_IS_ELEMENTS);
        } else if (active.byte_length != 0) {
            jni_emit_data(
                ctx, &active, role, kJNIPhaseRelease,
                JNI_CONVERSION_FLAG_JOINED);
        }
        bpf_map_delete_elem(&jni_object_states, &object_key);
        return 0;
    }
    return 0;
}

static __always_inline int jni_conversion_region_begin(
    struct pt_regs *ctx, u32 role) {
    if (!passes_filter(ctx))
        return 0;
    u64 caller_addr = jni_conversion_caller(ctx);
    if (!jni_conversion_caller_allowed(role, caller_addr))
        return 0;
    s64 signed_length = (s64)PT_REGS_PARM4(ctx);
    if (signed_length < 0)
        return 0;
    struct jni_conversion_active_key_t key = {
        .pid_tgid = bpf_get_current_pid_tgid(),
        .role = role,
    };
    struct jni_conversion_active_t active = {
        .env = (u64)PT_REGS_PARM1(ctx),
        .object = (u64)PT_REGS_PARM2(ctx),
        .buffer = (u64)PT_REGS_PARM5(ctx),
        .byte_length = (u64)signed_length,
        .element_count = (u64)signed_length,
        .region_start = (u64)PT_REGS_PARM3(ctx),
        .caller_addr = caller_addr,
    };
    if (active.env == 0 || active.object == 0 || active.buffer == 0)
        return 0;
    if (role == kJNISetByteArrayRegion) {
        jni_emit_data(ctx, &active, role, kJNIPhaseRegion, 0);
        return 0;
    }
    bpf_map_update_elem(&active_jni_conversions, &key, &active, BPF_ANY);
    return 0;
}

static __always_inline int jni_conversion_region_return(
    struct pt_regs *ctx, u32 role) {
    if (!passes_filter(ctx))
        return 0;
    struct jni_conversion_active_key_t key = {
        .pid_tgid = bpf_get_current_pid_tgid(),
        .role = role,
    };
    struct jni_conversion_active_t *active =
        bpf_map_lookup_elem(&active_jni_conversions, &key);
    if (active != NULL) {
        jni_emit_data(ctx, active, role, kJNIPhaseRegion, 0);
        bpf_map_delete_elem(&active_jni_conversions, &key);
    }
    return 0;
}

#define JNI_LENGTH_PROGRAM(name, role)                                        \
    SEC("uprobe/jni_" #name "_entry")                                        \
    int probe_entry_jni_##name(struct pt_regs *ctx) {                         \
        return jni_conversion_begin(ctx, role);                               \
    }                                                                         \
    SEC("uretprobe/jni_" #name "_return")                                    \
    int probe_return_jni_##name(struct pt_regs *ctx) {                        \
        return jni_conversion_length_return(ctx, role);                       \
    }

#define JNI_POINTER_PROGRAM(name, role)                                       \
    SEC("uprobe/jni_" #name "_entry")                                        \
    int probe_entry_jni_##name(struct pt_regs *ctx) {                         \
        return jni_conversion_begin(ctx, role);                               \
    }                                                                         \
    SEC("uretprobe/jni_" #name "_return")                                    \
    int probe_return_jni_##name(struct pt_regs *ctx) {                        \
        return jni_conversion_pointer_return(ctx, role);                      \
    }

#define JNI_RELEASE_PROGRAM(name, role, acquire_role)                         \
    SEC("uprobe/jni_" #name)                                                 \
    int probe_jni_##name(struct pt_regs *ctx) {                               \
        return jni_conversion_release(ctx, role, acquire_role);               \
    }

JNI_LENGTH_PROGRAM(get_string_length, kJNIGetStringLength)
JNI_POINTER_PROGRAM(get_string_chars, kJNIGetStringChars)
JNI_RELEASE_PROGRAM(
    release_string_chars, kJNIReleaseStringChars, kJNIGetStringChars)
JNI_LENGTH_PROGRAM(get_string_utf_length, kJNIGetStringUTFLength)
JNI_POINTER_PROGRAM(get_string_utf_chars, kJNIGetStringUTFChars)
JNI_RELEASE_PROGRAM(
    release_string_utf_chars, kJNIReleaseStringUTFChars,
    kJNIGetStringUTFChars)
JNI_LENGTH_PROGRAM(get_array_length, kJNIGetArrayLength)
JNI_POINTER_PROGRAM(get_byte_array_elements, kJNIGetByteArrayElements)
JNI_RELEASE_PROGRAM(
    release_byte_array_elements, kJNIReleaseByteArrayElements,
    kJNIGetByteArrayElements)
JNI_POINTER_PROGRAM(
    get_primitive_array_critical, kJNIGetPrimitiveArrayCritical)
JNI_RELEASE_PROGRAM(
    release_primitive_array_critical, kJNIReleasePrimitiveArrayCritical,
    kJNIGetPrimitiveArrayCritical)
JNI_POINTER_PROGRAM(get_string_critical, kJNIGetStringCritical)
JNI_RELEASE_PROGRAM(
    release_string_critical, kJNIReleaseStringCritical,
    kJNIGetStringCritical)
JNI_POINTER_PROGRAM(
    get_direct_buffer_address, kJNIGetDirectBufferAddress)
JNI_LENGTH_PROGRAM(
    get_direct_buffer_capacity, kJNIGetDirectBufferCapacity)

SEC("uprobe/jni_get_byte_array_region_entry")
int probe_entry_jni_get_byte_array_region(struct pt_regs *ctx) {
    return jni_conversion_region_begin(ctx, kJNIGetByteArrayRegion);
}

SEC("uretprobe/jni_get_byte_array_region_return")
int probe_return_jni_get_byte_array_region(struct pt_regs *ctx) {
    return jni_conversion_region_return(ctx, kJNIGetByteArrayRegion);
}

SEC("uprobe/jni_set_byte_array_region")
int probe_jni_set_byte_array_region(struct pt_regs *ctx) {
    return jni_conversion_region_begin(ctx, kJNISetByteArrayRegion);
}

#undef JNI_LENGTH_PROGRAM
#undef JNI_POINTER_PROGRAM
#undef JNI_RELEASE_PROGRAM
#undef JNI_CONVERSION_EMIT_SEG

#endif
