#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>

char LICENSE[] SEC("license") = "GPL";

// Map for target process name
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, char[16]);
} config SEC(".maps");

// Perf event array for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} events SEC(".maps");

// Event struct to send
struct event {
    char comm[16];
    char syscall[8];
};

// Helper function for string compare
static __inline int strncmp(char *s1, char *s2, int n) {
    int i;
#pragma unroll
    for (i = 0; i < n; i++) {
        if (s1[i] != s2[i])
            return 1; // not equal
        if (s1[i] == '\0')
            break;
    }
    return 0; // equal
}

static void send_event(void *ctx, char *comm, const char *syscall) {
    struct event e = {};
    __builtin_memcpy(e.comm, comm, sizeof(e.comm));
    __builtin_memcpy(e.syscall, syscall, sizeof(e.syscall));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
}

SEC("kprobe/sys_read")
int bpf_prog_read(struct pt_regs *ctx)
{
    uint32_t key = 0;
    char *target_comm = bpf_map_lookup_elem(&config, &key);
    if (!target_comm)
        return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (strncmp(comm, target_comm, 16) == 0) {
        send_event(ctx, comm, "read");
    }

    return 0;
}

SEC("kprobe/sys_write")
int bpf_prog_write(struct pt_regs *ctx)
{
    uint32_t key = 0;
    char *target_comm = bpf_map_lookup_elem(&config, &key);
    if (!target_comm)
        return 0;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (strncmp(comm, target_comm, 16) == 0) {
        send_event(ctx, comm, "write");
    }

    return 0;
}

