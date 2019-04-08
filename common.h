
// cat /sys/kernel/debug/tracing/trace_pipe

#define KDEBUG
#define DOH_PORT 443
#define MAX_CONNS_ENTRIES       256U
#define MIN_PACKETS 10

/********************************************************************
* Description:
* Author: root <>
* Created at: Mon Apr  8 21:22:13 UTC 2019
* Computer: debianOne
* System: Linux 4.19.0-0.bpo.4-amd64 on x86_64
*
* Copyright (c) 2019 root  All rights reserved.
*
********************************************************************/

enum bpf_attach_type {
    BPF_CGROUP_INET_INGRESS,
    BPF_CGROUP_INET_EGRESS,
    BPF_CGROUP_INET_SOCK_CREATE,
    BPF_CGROUP_SOCK_OPS,
    BPF_SK_SKB_STREAM_PARSER,
    BPF_SK_SKB_STREAM_VERDICT,
    BPF_CGROUP_DEVICE,
    BPF_SK_MSG_VERDICT,
    BPF_CGROUP_INET4_BIND,
    BPF_CGROUP_INET6_BIND,
    BPF_CGROUP_INET4_CONNECT,
    BPF_CGROUP_INET6_CONNECT,
    BPF_CGROUP_INET4_POST_BIND,
    BPF_CGROUP_INET6_POST_BIND,
    BPF_CGROUP_UDP4_SENDMSG,
    BPF_CGROUP_UDP6_SENDMSG,
    BPF_LIRC_MODE2,
    __MAX_BPF_ATTACH_TYPE
};

/* ************************************************* */
struct mapk_s {
    uint16_t family;
    union {
        uint32_t v6[4];
        uint32_t v4;
    } saddr;
    union {
        uint32_t v6[4];
        uint32_t v4;
    } daddr;
    uint16_t sport;
    uint16_t dport;
};

struct mapv_s {
    /*
        npkts, totsize and totsq are needed for Welford’s method to
        calculate the connection packet size and stddev.
        Kernel space will update the counters, user space will do the
        harder math.
     */
    uint64_t npkts;
    uint64_t totsize;
    uint64_t totsq;
    /*
        These are needed to get the connection length, needed to
        understand if it's a simple TLS connection or some daemon trying
        to tunnel data over HTTPS.
    */
    uint64_t start;
    uint64_t last;
    uint64_t end;
};
