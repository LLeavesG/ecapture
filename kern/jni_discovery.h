// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ECAPTURE_JNI_DISCOVERY_H
#define ECAPTURE_JNI_DISCOVERY_H

#define JNI_DISCOVERY_SEGMENTS 16
#define JNI_DISCOVERY_METHODS_PER_SEGMENT 16
#define JNI_DISCOVERY_MAX_METHODS \
    (JNI_DISCOVERY_SEGMENTS * JNI_DISCOVERY_METHODS_PER_SEGMENT)
#define JNI_METHOD_NAME_SIZE 96
#define JNI_METHOD_SIGNATURE_SIZE 160
#define JNI_EVENT_NAME_TRUNCATED 0x01
#define JNI_EVENT_SIGNATURE_TRUNCATED 0x02

struct jni_native_method_t {
    u64 name;
    u64 signature;
    u64 function;
};

struct jni_register_event_t {
    u64 timestamp_ns;
    u64 register_natives_addr;
    u64 methods_addr;
    u64 function_addr;
    u32 pid;
    u32 tid;
    u32 method_count;
    u32 method_index;
    u32 hook_id;
    u32 flags;
    char comm[TASK_COMM_LEN];
    char name[JNI_METHOD_NAME_SIZE];
    char signature[JNI_METHOD_SIGNATURE_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} jni_register_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct jni_register_event_t);
    __uint(max_entries, 1);
} jni_register_buffer_heap SEC(".maps");

static __always_inline void emit_jni_registered_method(
    struct pt_regs *ctx, struct jni_register_event_t *event, u64 methods_addr,
    u32 method_count, u32 method_index) {
    if (method_index >= method_count)
        return;

    struct jni_native_method_t method = {};
    u64 method_addr =
        methods_addr + (u64)method_index * sizeof(struct jni_native_method_t);
    if (bpf_probe_read_user(
            &method, sizeof(method), (void *)method_addr) != 0)
        return;
    if (method.name == 0 || method.signature == 0 || method.function == 0)
        return;

    event->name[0] = '\0';
    event->signature[0] = '\0';
    int name_length = bpf_probe_read_user_str(
        event->name, sizeof(event->name), (void *)method.name);
    if (name_length <= 1)
        return;
    int signature_length = bpf_probe_read_user_str(
        event->signature, sizeof(event->signature), (void *)method.signature);
    if (signature_length <= 1)
        return;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->register_natives_addr = (u64)PT_REGS_IP(ctx);
    event->methods_addr = methods_addr;
    event->function_addr = method.function;
    event->pid = pid_tgid >> 32;
    event->tid = pid_tgid;
    event->method_count = method_count;
    event->method_index = method_index;
    // The same segment program is attached to every configured
    // RegisterNatives implementation. User space derives the hook ID from
    // register_natives_addr and the build-ID-pinned profile offsets.
    event->hook_id = 0;
    event->flags = 0;
    if (name_length == sizeof(event->name))
        event->flags |= JNI_EVENT_NAME_TRUNCATED;
    if (signature_length == sizeof(event->signature))
        event->flags |= JNI_EVENT_SIGNATURE_TRUNCATED;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_perf_event_output(
        ctx, &jni_register_events, BPF_F_CURRENT_CPU, event,
        sizeof(struct jni_register_event_t));
}

static __always_inline int trace_jni_register_natives(
    struct pt_regs *ctx, u32 segment) {
    if (!passes_filter(ctx))
        return 0;

    u64 methods_addr = (u64)PT_REGS_PARM3(ctx);
    s64 signed_count = (s64)PT_REGS_PARM4(ctx);
    if (methods_addr == 0 || signed_count <= 0 || signed_count > 65535)
        return 0;

    u32 zero = 0;
    struct jni_register_event_t *event =
        bpf_map_lookup_elem(&jni_register_buffer_heap, &zero);
    if (event == NULL)
        return 0;

    u32 method_count = (u32)signed_count;
    u32 first = segment * JNI_DISCOVERY_METHODS_PER_SEGMENT;
    if (first >= method_count)
        return 0;

#define JNI_EMIT_LOCAL(local_index)                                              \
    emit_jni_registered_method(                                                 \
        ctx, event, methods_addr, method_count, first + local_index)

    // Keep this list explicit. Some Android kernels reject the bounded loop
    // clang otherwise retains for segment zero during verification/JIT.
    JNI_EMIT_LOCAL(0);
    JNI_EMIT_LOCAL(1);
    JNI_EMIT_LOCAL(2);
    JNI_EMIT_LOCAL(3);
    JNI_EMIT_LOCAL(4);
    JNI_EMIT_LOCAL(5);
    JNI_EMIT_LOCAL(6);
    JNI_EMIT_LOCAL(7);
    JNI_EMIT_LOCAL(8);
    JNI_EMIT_LOCAL(9);
    JNI_EMIT_LOCAL(10);
    JNI_EMIT_LOCAL(11);
    JNI_EMIT_LOCAL(12);
    JNI_EMIT_LOCAL(13);
    JNI_EMIT_LOCAL(14);
    JNI_EMIT_LOCAL(15);

#undef JNI_EMIT_LOCAL
    return 0;
}

#define JNI_REGISTER_PROGRAM(segment)                                            \
    SEC("uprobe/jni_register_natives_" #segment)                                 \
    int probe_jni_register_natives_##segment(struct pt_regs *ctx) {              \
        return trace_jni_register_natives(ctx, segment);                         \
    }

JNI_REGISTER_PROGRAM(0)
JNI_REGISTER_PROGRAM(1)
JNI_REGISTER_PROGRAM(2)
JNI_REGISTER_PROGRAM(3)
JNI_REGISTER_PROGRAM(4)
JNI_REGISTER_PROGRAM(5)
JNI_REGISTER_PROGRAM(6)
JNI_REGISTER_PROGRAM(7)
JNI_REGISTER_PROGRAM(8)
JNI_REGISTER_PROGRAM(9)
JNI_REGISTER_PROGRAM(10)
JNI_REGISTER_PROGRAM(11)
JNI_REGISTER_PROGRAM(12)
JNI_REGISTER_PROGRAM(13)
JNI_REGISTER_PROGRAM(14)
JNI_REGISTER_PROGRAM(15)

#endif
