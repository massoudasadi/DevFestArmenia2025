#include <stdio.h>          // printf
#include <arpa/inet.h>     // inet_pton, inet_ntoa
#include <bpf/libbpf.h>    // libbpf API
#include <unistd.h>        // sleep
#include <net/if.h>        // if_nametoindex

/* Event structure must match kernel definition */
struct event {
    __u32 src_ip;
};

/*
 * Callback executed when kernel sends an event
 * via ring buffer
 */
static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;

    /* Convert IP from network to printable format */
    struct in_addr ip = { .s_addr = e->src_ip };

    printf("🔥 Packet dropped from IP: %s\n",
           inet_ntoa(ip));

    return 0;
}

int main(int argc, char **argv)
{
    /* Expect: interface name + IP address */
    if (argc != 3) {
        printf("Usage: %s <iface> <ip>\n", argv[0]);
        return 1;
    }

    const char *iface  = argv[1];
    const char *ip_str = argv[2];

    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    struct ring_buffer *rb;

    int ifindex, map_fd;
    __u32 key = 0;
    __u32 ip;

    /* Convert IP string to network byte order */
    inet_pton(AF_INET, ip_str, &ip);

    /* Open compiled eBPF object file */
    obj = bpf_object__open_file("xdp_drop_ip.o", NULL);

    /* Load eBPF program into kernel */
    bpf_object__load(obj);

    /* Find XDP program by name */
    prog = bpf_object__find_program_by_name(
        obj, "xdp_drop_by_ip");

    /* Get interface index */
    ifindex = if_nametoindex(iface);

    /* Attach XDP program to interface */
    bpf_program__attach_xdp(prog, ifindex);

    /* Find map that stores blocked IP */
    map = bpf_object__find_map_by_name(obj, "blocked_ip");
    map_fd = bpf_map__fd(map);

    /* Send IP from userspace to kernel */
    bpf_map__update_elem(map, &key, sizeof(key), &ip, sizeof(ip), BPF_ANY);

    /* Find ring buffer map */
    map = bpf_object__find_map_by_name(obj, "events");

    /* Create ring buffer reader */
    rb = ring_buffer__new(
        bpf_map__fd(map),
        handle_event,
        NULL,
        NULL
    );

    printf("🚫 Blocking IP %s on interface %s\n",
           ip_str, iface);

    /* Poll for kernel events forever */
    while (1) {
        ring_buffer__poll(rb, 100);
    }
}
