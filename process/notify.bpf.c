#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* Define the structure of the data we want to send to userspace.
 * This must match the struct definition in your userspace C code. */
struct event {
    int pid;
    char comm[16]; // TASK_COMM_LEN is 16 in the kernel
};

/* Define a Ring Buffer map. 
 * Ring buffers are the modern way to move data to userspace efficiently. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB buffer size
} rb SEC(".maps");

/* Custom string comparison because standard strcmp() is unavailable in BPF.
 * We use __always_inline because BPF programs prefer inlined functions. */
static __always_inline bool is_firefox(char *comm) {
    char target[] = "firefox";
    // Check first 7 characters: 'f','i','r','e','f','o','x'
    for (int i = 0; i < 7; i++) {
        if (comm[i] != target[i]) return false;
    }
    return true;
}

/* Attach to the 'execve' tracepoint. 
 * This triggers when any process tries to execute a new binary. */
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    char comm[16];

    /* Helper: Get the name of the process currently triggering the syscall. */
    bpf_get_current_comm(&comm, sizeof(comm));

    /* KERNEL-SIDE FILTERING: 
     * If it's not firefox, we exit immediately. This is high performance 
     * because we don't waste time allocating memory in the ring buffer. */
    if (!is_firefox(comm)) {
        return 0;
    }

    /* Reserve space in the ring buffer for our event struct. */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0; // If buffer is full, drop the event

    /* PID/TGID helper returns a 64-bit value: 
     * High 32 bits = PID, Low 32 bits = Thread ID. */
    e->pid = bpf_get_current_pid_tgid() >> 32;
    
    /* Copy the process name into our event struct. */
    __builtin_memcpy(e->comm, comm, sizeof(comm));

    /* Submit the data. This triggers the 'poll' in your userspace program. */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";