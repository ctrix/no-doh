
/*
    ip        link set dev ens33 xdp object knodoh.o verbose
    ip        link show dev ens33
    ip        link set dev ens33 xdp off
*/

#define __x86_64__

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "common.h"

#define SEC(NAME) __attribute__((section(NAME), used))

#if !defined(NULL)
#define NULL ((void*)0)
#endif

#ifdef KDEBUG
#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})
#else
#define bpf_printk(fmt, ...) while (0);
#endif

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
    unsigned int inner_map_idx;
    unsigned int numa_node;
};

static void *(*bpf_map_lookup_elem) (void *map, void *key) = (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem) (void *map, void *key, void *value, unsigned long long flags) = (void *) BPF_FUNC_map_update_elem;
static int (*bpf_trace_printk) (const char *fmt, int fmt_size, ...) = (void *) BPF_FUNC_trace_printk;
static unsigned long long (*bpf_ktime_get_ns) (void) = (void *) BPF_FUNC_ktime_get_ns;

/* ********************************************** */

struct bpf_map_def SEC("maps") conns = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct mapk_s),
    .value_size = sizeof(struct mapv_s),
    .max_entries = MAX_CONNS_ENTRIES,
};

/* ********************************************** */

static inline uint16_t get_dport(void *trans_data, void *data_end, uint8_t protocol) {
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *) trans_data;
            if ((void *) (th + 1) > data_end) {
                return -1;
            }
            return __constant_ntohs(th->dest);
        case IPPROTO_UDP:
            uh = (struct udphdr *) trans_data;
            if ((void *) (uh + 1) > data_end) {
                return -1;
            }
            return __constant_ntohs(uh->dest);
        default:
            return 0;
    }
}

static inline uint16_t get_sport(void *trans_data, void *data_end, uint8_t protocol) {
    struct tcphdr *th;
    struct udphdr *uh;

    switch (protocol) {
        case IPPROTO_TCP:
            th = (struct tcphdr *) trans_data;
            if ((void *) (th + 1) > data_end) {
                return -1;
            }
            return __constant_ntohs(th->source);
        case IPPROTO_UDP:
            uh = (struct udphdr *) trans_data;
            if ((void *) (uh + 1) > data_end) {
                return -1;
            }
            return __constant_ntohs(uh->source);
        default:
            return 0;
    }
}

static inline int handle_ipv4(struct xdp_md *xdp) {
    void *data_end = (void *) (long) xdp->data_end;
    void *data = (void *) (long) xdp->data;
    struct iphdr *iph = data + sizeof(struct ethhdr);
    long pktsize = data_end - data - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct tcphdr);

    if ((void *) (iph + 1) > data_end) {
        return XDP_DROP;
    }

    /* We're interested only in TCP connectionx */
    if (iph->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    long sport = get_sport(iph + 1, data_end, iph->protocol);
    if (sport == -1) {
        return XDP_DROP;
    }

    long dport = get_dport(iph + 1, data_end, iph->protocol);
    if (dport == -1) {
        return XDP_DROP;
    }

    /* If it doesn't involve port DOH_PORT, let it go. */
    if (sport != DOH_PORT && dport != DOH_PORT) {
        return XDP_PASS;
    }

    /*
       If it's a syn packet, then we should create a map entry
     */
    struct tcphdr *th;

    th = (struct tcphdr *) (iph + 1);
    if ((void *) (th + 1) > data_end) {
        return 0;
    }

    /*
       If it's a syn packet then it's the beginning of a new
       connection. Add it to the map.
       Note that we only get incoming packets, so we're analyzing a
       response packet from the server.

       Else, pick the data from the map.
     */
    struct mapk_s mapk = { 0 };
    struct mapv_s mapv = { 0 }, *mapvp;

    mapk.family = AF_INET;;
    mapk.saddr.v4 = iph->saddr;
    mapk.daddr.v4 = iph->daddr;
    mapk.sport = sport;
    mapk.dport = dport;
    //__builtin_memcpy((void *) &mapk.saddr.v4, (void *) &iph->saddr, sizeof(mapk.saddr.v4));
    //__builtin_memcpy((void *) &mapk.daddr.v4, (void *) &iph->daddr, sizeof(mapk.daddr.v4));

    if (th->syn && th->ack) {
        bpf_printk("new: (%d -> %d) - %d\n", mapk.sport, mapk.dport, pktsize);
        __builtin_memset(&mapv, 0, sizeof(struct mapv_s));
        mapv.start = bpf_ktime_get_ns();
        mapv.last = bpf_ktime_get_ns();
        mapv.end = 0;
        bpf_map_update_elem(&conns, &mapk, &mapv, BPF_ANY);
        return XDP_PASS;
    }
    else if (th->rst || th->fin) {
        mapvp = bpf_map_lookup_elem(&conns, &mapk);
        if (mapvp) {
            mapvp->last = bpf_ktime_get_ns();
            mapvp->end = bpf_ktime_get_ns();
            bpf_printk("end %d\n", mapvp->npkts);
            return XDP_PASS;
        }
    } else {
        mapvp = bpf_map_lookup_elem(&conns, &mapk);
        if (mapvp) {
            __sync_fetch_and_add(&mapvp->npkts, 1);
            if ( mapvp->npkts >= MIN_PACKETS ) {
                __sync_fetch_and_add(&mapvp->totsize, pktsize);
                __sync_fetch_and_add(&mapvp->totsq, pktsize * pktsize);
                bpf_printk("upd %d %d **\n", mapvp->npkts, pktsize);
            }
            else {
                bpf_printk("upd %d %d\n", mapvp->npkts, pktsize);
            }
            mapvp->last = bpf_ktime_get_ns();

            return XDP_PASS;
        }
    }

    bpf_printk("Unknown connection ...\n");
    return XDP_PASS;
}

static inline int handle_ipv6(struct xdp_md *xdp) {
    void *data_end = (void *) (uintptr_t) xdp->data_end;
    void *data = (void *) (uintptr_t) xdp->data;
    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);

    if ((void *) (ip6h + 1) > data_end) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("prog")
int xdp_nodoh(struct xdp_md *xdp) {
    void *data_end = (void *) (long) xdp->data_end;
    void *data = (void *) (long) xdp->data;
    struct ethhdr *eth = data;
    uint16_t h_proto;

    if ((void *) (eth + 1) > data_end) {
        return XDP_DROP;
    }

    h_proto = __constant_ntohs(eth->h_proto);

    if (h_proto == ETH_P_IP) {
        return handle_ipv4(xdp);
    } else if (h_proto == ETH_P_IPV6) {
        return handle_ipv6(xdp);
    } else {
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
