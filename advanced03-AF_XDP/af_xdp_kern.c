/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

// #ifdef DEBUG
#define s__(n)   # n
#define s_(n)    s__(n)
#define x_(fmt)  __FILE__ ":" s_(__LINE__) ": " fmt "\n"
#define DEBUG_PRINT_(fmt, ...) do { \
    const char fmt__[] = fmt; \
    bpf_trace_printk(fmt__, sizeof(fmt), ## __VA_ARGS__); } while(0)
#define DEBUG_PRINT(fmt, ...)   DEBUG_PRINT_ (x_(fmt), ## __VA_ARGS__)
// #else   /* DEBUG */
// #define DEBUG_PRINT(fmt, ...)
// #endif  /* DEBUG */

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(int),
	.value_size  = sizeof(__u32),
	.max_entries = 64,
};

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;
    // __u32 *pkt_count;

    // pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &index);
    // if (pkt_count) {

    //     /* We pass every other packet */
    //     if ((*pkt_count)++ & 1)
    //         return XDP_PASS;
    // }

    /* A set entry here means that the correspnding queue_id
     * has an active AF_XDP socket bound to it. */
    if (bpf_map_lookup_elem(&xsks_map, &index))
    {
        DEBUG_PRINT("going to socket %d", index);
        return bpf_redirect_map(&xsks_map, index, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
