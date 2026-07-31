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

// if vmlinux.h not defined
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#define TC_PACKET_META_SIZE 64
#define SOCKET_ALLOW 1
#define TC_UNKNOWN_INCLUDE 0
#define TC_UNKNOWN_MARK 1
#define TC_UNKNOWN_DROP 2
#define TC_EVENT_ATTRIBUTED 0x01
#define TC_EVENT_UID_FROM_SOCKET 0x02
#define TC_EVENT_UNKNOWN_FLOW 0x04
#define TC_EVENT_RAW_IP 0x08
#define TC_EVENT_VLAN 0x10

const volatile u64 tc_unknown_flow_policy = TC_UNKNOWN_INCLUDE;
const volatile u64 tc_strict_attribution = 0;

#define READ_KERN(ptr)                                                  \
    ({                                                                  \
        typeof(ptr) _val;                                               \
        __builtin_memset((void *)&_val, 0, sizeof(_val));               \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);               \
        _val;                                                           \
    })

struct skb_data_event_t {
    uint64_t ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    // Keep the first 36 bytes stable for existing readers.
    u32 len;
    u32 ifindex;
    u32 uid;
    u32 flags;
    u32 direction;
    u64 socket_cookie;
    u64 cgroup_id;
};

struct net_id_t {
    u32 protocol;
    u32 src_port;
    u32 src_ip4;
    u32 dst_port;
    u32 dst_ip4;
    u32 src_ip6[4];
    u32 dst_ip6[4];
};

struct net_ctx_t {
    u32 pid;
    u32 uid;
    u64 cgroup_id;
    char comm[TASK_COMM_LEN];
//    u8 cmdline[PATH_MAX_LEN];
};

////////////////////// ebpf maps //////////////////////
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 10240);
} skb_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct skb_data_event_t);
    __uint(max_entries, 1);
} skb_data_buffer_heap SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct net_id_t);
    __type(value, struct net_ctx_t);
    __uint(max_entries, 10240);
} network_map SEC(".maps");

////////////////////// General helper functions //////////////////////

static __always_inline void get_proc_cmdline(struct task_struct *task, char *cmdline, int size)
{
    struct mm_struct *mm = READ_KERN(task->mm);
    long unsigned int args_start = READ_KERN(mm->arg_start);
    long unsigned int args_end = READ_KERN(mm->arg_end);
    int len = (args_end - args_start);
    if (len >= size)
        len = size - 1;
    bpf_probe_read(cmdline, len & (size - 1), (const void *)args_start);
}

static __always_inline struct skb_data_event_t *make_skb_data_event() {
    u32 zero = 0;
    struct skb_data_event_t *event =
        bpf_map_lookup_elem(&skb_data_buffer_heap, &zero);
    if (event == NULL) {
        return NULL;
    }
    return event;
}

static __always_inline bool skb_revalidate_data(struct __sk_buff *skb,
                                                uint8_t **head, uint8_t **tail,
                                                const u32 offset) {
    if (*head + offset > *tail) {
        if (bpf_skb_pull_data(skb, offset) < 0) {
            return false;
        }

        *head = (uint8_t *)(long)skb->data;
        *tail = (uint8_t *)(long)skb->data_end;

        if (*head + offset > *tail) {
            return false;
        }
    }

    return true;
}

// filter_pcap_ebpf_l2 is a stub to inject pcap-filter.
static __noinline bool filter_pcap_ebpf_l2(void *_skb, void *__skb,
                                           void *___skb, void *data,
                                           void* data_end) {
    return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool filter_pcap_l2(struct __sk_buff *skb, void *data,
                                           void *data_end) {
    return filter_pcap_ebpf_l2((void *) skb, (void *) skb, (void *) skb, data,
                               data_end);
}

static __always_inline struct net_ctx_t *lookup_network_context(struct net_id_t *conn_id) {
    struct net_ctx_t *net_ctx = bpf_map_lookup_elem(&network_map, conn_id);
    if (net_ctx != NULL) {
        return net_ctx;
    }

    u32 tmp_ip4 = conn_id->src_ip4;
    conn_id->src_ip4 = conn_id->dst_ip4;
    conn_id->dst_ip4 = tmp_ip4;

    u32 tmp_ip6[4];
    __builtin_memcpy(tmp_ip6, conn_id->src_ip6, sizeof(tmp_ip6));
    __builtin_memcpy(conn_id->src_ip6, conn_id->dst_ip6, sizeof(conn_id->src_ip6));
    __builtin_memcpy(conn_id->dst_ip6, tmp_ip6, sizeof(conn_id->dst_ip6));

    u32 tmp_port = conn_id->src_port;
    conn_id->src_port = conn_id->dst_port;
    conn_id->dst_port = tmp_port;
    return bpf_map_lookup_elem(&network_map, conn_id);
}

///////////////////// ebpf functions //////////////////////
static __always_inline int capture_packets(struct __sk_buff *skb, bool is_ingress) {
    unsigned char *data_start = (void *)(long)skb->data;
    unsigned char *data_end = (void *)(long)skb->data_end;

    // Capture every non-empty frame. Protocol parsing below is best-effort and
    // is used only for process attribution; it must not decide raw coverage.
    if (data_start + 1 > data_end) {
        return TC_ACT_OK;
    }
    if (less52 != 1) {
        if (!filter_pcap_l2(skb, data_start, data_end))
            return TC_ACT_OK;
    }

    struct net_id_t conn_id = {0};
    struct net_ctx_t *net_ctx = NULL;
    u32 event_flags = 0;
    u32 l3_hdr_off = 0;
    u16 l3_protocol = 0;

    struct ethhdr eth = {};
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) == 0) {
        l3_protocol = bpf_ntohs(eth.h_proto);
        l3_hdr_off = sizeof(struct ethhdr);

        // Parse up to two VLAN tags. Packets with deeper tag stacks are still
        // emitted, but tuple attribution remains unknown.
#pragma unroll
        for (int vlan_index = 0; vlan_index < 2; vlan_index++) {
            if (l3_protocol != ETH_P_8021Q && l3_protocol != ETH_P_8021AD) {
                break;
            }
            event_flags |= TC_EVENT_VLAN;
            u16 encapsulated_protocol = 0;
            if (bpf_skb_load_bytes(skb, l3_hdr_off + 2, &encapsulated_protocol,
                                   sizeof(encapsulated_protocol)) != 0) {
                l3_protocol = 0;
                break;
            }
            l3_protocol = bpf_ntohs(encapsulated_protocol);
            l3_hdr_off += 4;
        }
    }

    // TUN and other ARPHRD_NONE devices expose an IP packet without Ethernet.
    u8 first_byte = 0;
    bpf_skb_load_bytes(skb, 0, &first_byte, sizeof(first_byte));
    u8 first_nibble = first_byte >> 4;
    if (l3_protocol != ETH_P_IP && l3_protocol != ETH_P_IPV6 && (first_nibble == 4 || first_nibble == 6)) {
        l3_hdr_off = 0;
        l3_protocol = first_nibble == 4 ? ETH_P_IP : ETH_P_IPV6;
        event_flags |= TC_EVENT_RAW_IP;
    }

    if (l3_protocol == ETH_P_IPV6) {
        u32 l4_hdr_off = l3_hdr_off + sizeof(struct ipv6hdr);
        struct ipv6hdr iph = {};
        if (bpf_skb_load_bytes(skb, l3_hdr_off, &iph, sizeof(iph)) == 0) {
            conn_id.protocol = iph.nexthdr;
            __builtin_memcpy(conn_id.src_ip6, &iph.saddr, sizeof(iph.saddr));
            __builtin_memcpy(conn_id.dst_ip6, &iph.daddr, sizeof(iph.daddr));

            // Extension headers make the transport offset variable. Emit the
            // packet regardless, and attribute direct TCP/UDP packets here.
            if (iph.nexthdr == IPPROTO_TCP || iph.nexthdr == IPPROTO_UDP) {
                u16 ports[2] = {};
                if (bpf_skb_load_bytes(skb, l4_hdr_off, ports, sizeof(ports)) == 0) {
                    conn_id.src_port = bpf_ntohs(ports[0]);
                    conn_id.dst_port = bpf_ntohs(ports[1]);
                    net_ctx = lookup_network_context(&conn_id);
                }
            }
        }
    } else if (l3_protocol == ETH_P_IP) {
        struct iphdr iph = {};
        if (bpf_skb_load_bytes(skb, l3_hdr_off, &iph, sizeof(iph)) == 0) {
            u32 ip_header_len = (u32)iph.ihl * 4;
            conn_id.protocol = iph.protocol;
            conn_id.src_ip4 = iph.saddr;
            conn_id.dst_ip4 = iph.daddr;

            if (ip_header_len >= sizeof(struct iphdr) && ip_header_len <= 60 &&
                (bpf_ntohs(iph.frag_off) & 0x1fff) == 0) {
                u32 l4_hdr_off = l3_hdr_off + ip_header_len;
                if (iph.protocol == IPPROTO_TCP || iph.protocol == IPPROTO_UDP) {
                    u16 ports[2] = {};
                    if (bpf_skb_load_bytes(skb, l4_hdr_off, ports, sizeof(ports)) == 0) {
                        conn_id.src_port = bpf_ntohs(ports[0]);
                        conn_id.dst_port = bpf_ntohs(ports[1]);
                        net_ctx = lookup_network_context(&conn_id);
                    }
                }
            }
        }
    }

    struct skb_data_event_t event = {0};
    u32 socket_uid = bpf_get_socket_uid(skb);
    bool socket_uid_known = socket_uid != (u32)-1 && socket_uid != 65534;
    bool identity_unknown = false;
    if (net_ctx != NULL) {
        if (filter_rejects_base(net_ctx->pid, net_ctx->uid)) {
            return TC_ACT_OK;
        }
        if (target_cgroup_id != 0 && net_ctx->cgroup_id != target_cgroup_id) {
            return TC_ACT_OK;
        }
        event.pid = net_ctx->pid;
        event.uid = net_ctx->uid;
        event.cgroup_id = net_ctx->cgroup_id;
        event_flags |= TC_EVENT_ATTRIBUTED;
        __builtin_memcpy(event.comm, net_ctx->comm, TASK_COMM_LEN);
    } else {
        if (socket_uid_known) {
            event.uid = socket_uid;
            event_flags |= TC_EVENT_UID_FROM_SOCKET;
        }
        if (target_uid != 0) {
            if (!socket_uid_known) {
                identity_unknown = true;
            } else if (!target_uid_matches(socket_uid)) {
                return TC_ACT_OK;
            }
        }
        if (target_pid != 0 || target_cgroup_id != 0) {
            identity_unknown = true;
        }
    }

    if (net_ctx == NULL) {
        event_flags |= TC_EVENT_UNKNOWN_FLOW;
        if (identity_unknown && tc_strict_attribution != 0) {
            return TC_ACT_OK;
        }
        if (tc_unknown_flow_policy == TC_UNKNOWN_DROP) {
            return TC_ACT_OK;
        }
    }

    event.ts = bpf_ktime_get_ns();
    event.len = skb->len;
    event.ifindex = skb->ifindex;
    event.flags = event_flags;
    event.direction = is_ingress ? 0 : 1;
    event.socket_cookie = bpf_get_socket_cookie(skb);

    u32 capture_len = skb->len;
    if (capture_len > SKB_MAX_DATA_SIZE)
        capture_len = SKB_MAX_DATA_SIZE;

    u64 flags = BPF_F_CURRENT_CPU;
    flags |= (u64)capture_len << 32;

    size_t pkt_size = TC_PACKET_META_SIZE;
    bpf_perf_event_output(skb, &skb_events, flags, &event, pkt_size);
    return TC_ACT_OK;
}

// egress_cls_func is called for packets that are going out of the network
SEC("classifier")
int egress_cls_func(struct __sk_buff *skb) {
    return capture_packets(skb, false);
};

// ingress_cls_func is called for packets that are coming into the network
SEC("classifier")
int ingress_cls_func(struct __sk_buff *skb) {
    return capture_packets(skb, true);
};

// Shared helper for tcp_sendmsg / udp_sendmsg kprobes.
// Extracts the 5-tuple from the socket and stores the PID/UID context in
// network_map so that TC classifier can correlate packets to processes.
static __always_inline int trace_sendmsg(struct pt_regs *ctx, u32 protocol) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;
    if (filter_rejects_base(pid, uid)) {
        return 0;
    }
    u64 cgroup_id = bpf_get_current_cgroup_id();
    if (target_cgroup_id != 0 && cgroup_id != target_cgroup_id) {
        return 0;
    }
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (sk == NULL) {
        return 0;
    }

    u16 family, lport, dport;
    struct net_id_t conn_id = {0};
    bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);

    if (family == AF_INET6) {
        u32 src_ip6[4], dst_ip6[4];
        bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        bpf_probe_read(&src_ip6, sizeof(src_ip6), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read(&dst_ip6, sizeof(dst_ip6), &sk->__sk_common.skc_v6_daddr);

        conn_id.protocol = protocol;
        conn_id.src_port = lport;
        conn_id.dst_port = bpf_ntohs(dport);
        __builtin_memcpy(conn_id.src_ip6, src_ip6, sizeof(src_ip6));
        __builtin_memcpy(conn_id.dst_ip6, dst_ip6, sizeof(dst_ip6));
    } else if (family == AF_INET) {
        u32 src_ip4, dst_ip4;
        bpf_probe_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);
        bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
        bpf_probe_read(&src_ip4, sizeof(src_ip4), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read(&dst_ip4, sizeof(dst_ip4), &sk->__sk_common.skc_daddr);

        conn_id.protocol = protocol;
        conn_id.src_port = lport;
        conn_id.src_ip4 = src_ip4;
        conn_id.dst_port = bpf_ntohs(dport);
        conn_id.dst_ip4 = dst_ip4;
    } else {
        return 0;
    }

    struct net_ctx_t net_ctx;
    net_ctx.pid = pid;
    net_ctx.uid = uid;
    net_ctx.cgroup_id = cgroup_id;
    bpf_get_current_comm(&net_ctx.comm, sizeof(net_ctx.comm));

    debug_bpf_printk("trace_sendmsg pid: %d, comm: %s\n", net_ctx.pid, net_ctx.comm);
    bpf_map_update_elem(&network_map, &conn_id, &net_ctx, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int tcp_sendmsg(struct pt_regs *ctx) {
    return trace_sendmsg(ctx, IPPROTO_TCP);
};

SEC("kprobe/udp_sendmsg")
int udp_sendmsg(struct pt_regs *ctx) {
    return trace_sendmsg(ctx, IPPROTO_UDP);
};
