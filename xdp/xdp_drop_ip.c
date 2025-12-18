#include <linux/bpf.h>          // Core eBPF definitions
#include <bpf/bpf_helpers.h>    // eBPF helper macros and functions
#include <linux/if_ether.h>     // Ethernet header definitions
#include <linux/ip.h>           // IPv4 header definitions

/* Required license for eBPF programs */
char LICENSE[] SEC("license") = "GPL";

/*
 * ARRAY map used to receive the IP address from userspace
 * key = 0
 * value = IPv4 address (network byte order)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} blocked_ip SEC(".maps");

/*
 * Ring buffer map to send events back to userspace
 * Used to notify when a packet is dropped
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Structure of event sent to userspace */
struct event {
    __u32 src_ip;   // Source IP of dropped packet
};

/*
 * XDP program entry point
 * Runs for every packet arriving on the interface
 */
SEC("xdp")
int xdp_drop_by_ip(struct xdp_md *ctx)
{
    /* Pointers to packet data boundaries */
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;

    /* Bounds check: required for eBPF verifier */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only handle IPv4 packets */
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IP header */
    struct iphdr *ip = (void *)(eth + 1);

    /* Bounds check for IP header */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Lookup blocked IP from map */
    __u32 key = 0;
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ip, &key);

    /* If userspace hasn't set IP yet */
    if (!blocked)
        return XDP_PASS;

    /* Compare packet source IP with blocked IP */
    if (ip->saddr == *blocked) {

        /* Reserve space in ring buffer for event */
        struct event *e =
            bpf_ringbuf_reserve(&events, sizeof(*e), 0);

        /* If reservation succeeded, fill and submit */
        if (e) {
            e->src_ip = ip->saddr;
            bpf_ringbuf_submit(e, 0);
        }

        /* Drop the packet */
        return XDP_DROP;
    }

    /* Otherwise let packet pass */
    return XDP_PASS;
}
