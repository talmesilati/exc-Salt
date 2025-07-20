package main

import (
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

func main() {
    spec, err := ebpf.LoadCollectionSpec("trace.o")
    if err != nil {
        log.Fatalf("failed to load eBPF spec: %v", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("failed to load eBPF collection: %v", err)
    }
    defer coll.Close()

    log.Println("eBPF program loaded successfully!")

    progRead := coll.Programs["bpf_prog_read"]
    progWrite := coll.Programs["bpf_prog_write"]

    if progRead == nil || progWrite == nil {
        log.Fatalf("could not find kprobe programs in collection")
    }

    kprobeRead, err := link.Kprobe("sys_read", progRead, nil)
    if err != nil {
        log.Fatalf("failed to attach kprobe to sys_read: %v", err)
    }
    defer kprobeRead.Close()

    kprobeWrite, err := link.Kprobe("sys_write", progWrite, nil)
    if err != nil {
        log.Fatalf("failed to attach kprobe to sys_write: %v", err)
    }
    defer kprobeWrite.Close()

    log.Println("kprobes attached. Listening...")

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    <-sig

    log.Println("Exiting...")
}
