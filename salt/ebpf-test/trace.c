#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_read")
int bpf_prog_read(struct pt_regs *ctx) {
    bpf_printk("sys_read was called!\n");
    return 0;
}

SEC("kprobe/sys_write")
int bpf_prog_write(struct pt_regs *ctx) {
    bpf_printk("sys_write was called!\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
