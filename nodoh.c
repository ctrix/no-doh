
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>          // inet_ntop
#include <errno.h>              // ENOENT

#include <stdint.h>
#include "common.h"

//#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static int ifindex = -1;

static void int_exit(int sig) {
    printf("Exiting...\n");
    if (ifindex != -1) {
        bpf_set_link_xdp_fd(ifindex, -1, 0);
    }
    exit(0);
}

static void show(int fd) {
    struct mapk_s key = { 0 }, next_key;
    struct mapv_s mapv;

    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        char sip[64], dip[64];
        const char *sp, *dp;

        if ( bpf_map_lookup_elem(fd, &next_key, &mapv) != ENOENT ) {
            sp = inet_ntop(next_key.family, &next_key.saddr.v4, sip, sizeof(sip));
            dp = inet_ntop(next_key.family, &next_key.daddr.v4, dip, sizeof(dip));
            printf(">> %s:%d * %s:%d\n", sp, next_key.sport, dp, next_key.dport);
            printf("   %ld pkts  %ld %.3f %s\n", mapv.npkts, mapv.start / 1000000000, ((double) mapv.last - mapv.start) / 1000000000, (mapv.end > 0) ? "**" : "" );

            if ( mapv.end > 0 ) {
                bpf_map_delete_elem(fd, &next_key);
            }

        }
        else {
            printf("Lookup -> ENOENT\n");
        }
        key = next_key;
    }

    return;
}

int main(int argc, char *argv[]) {
    struct rlimit limit = { RLIM_INFINITY, RLIM_INFINITY };
    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .file = "knodoh.o",
    };
    struct bpf_object *obj;
    int fd;

    if (argc != 2) {
        printf("usage: %s <iface>\n", argv[0]);
        return 0;
    }

    if (setrlimit(RLIMIT_MEMLOCK, &limit) < 0) {
        perror("Unable to lift memlock rlimit");
    }

    ifindex = if_nametoindex(argv[optind]);
    if (!ifindex) {
        perror("if_nametoindex");
    }

    if (bpf_prog_load_xattr(&prog_load_attr, &obj, &fd))
        return 1;

    if (!fd) {
        perror("load bpf file");
        return 1;
    }

    if (bpf_set_link_xdp_fd(ifindex, fd, 0) < 0) {
        perror("link set xdp fd failed\n");
        return 1;
    }

    close(fd);

    struct bpf_map *map;

    map = bpf_map__next(NULL, obj);
    if (!map) {
        perror("finding a map\n");
        return 1;
    }
    fd = bpf_map__fd(map);

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    while (1) {
        sleep(1);
        show(fd);
    }

    int_exit(0);

    return 0;
}
