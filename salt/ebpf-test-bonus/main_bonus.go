package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
)

type event struct {
    Comm    [16]byte
    Syscall [8]byte
}

func main() {
    if len(os.Args) < 2 {
        log.Fatalf("Usage: %s <binary_name>", os.Args[0])
    }

    targetComm := os.Args[1]
    fmt.Printf("Target process name to monitor: %s\n", targetComm)

    // Load eBPF program
    coll, err := ebpf.LoadCollection("trace_bonus.o")
    if err != nil {
        log.Fatalf("failed to load eBPF object: %v", err)
    }
    defer coll.Close()

    programRead := coll.Programs["bpf_prog_read"]
    programWrite := coll.Programs["bpf_prog_write"]
    configMap := coll.Maps["config"]
    perfMap := coll.Maps["events"]

    // Insert target process name into config map
    key := uint32(0)
    value := make([]byte, 16)
    copy(value, []byte(targetComm))
    if err := configMap.Put(key, value); err != nil {
        log.Fatalf("failed to insert target comm: %v", err)
    }
    fmt.Printf("Inserted target process \"%s\" into eBPF map\n", targetComm)

    // Attach kprobes
    kprobeRead, err := link.Kprobe("sys_read", programRead, nil)
    if err != nil {
        log.Fatalf("failed to attach kprobe to sys_read: %v", err)
    }
    defer kprobeRead.Close()

    kprobeWrite, err := link.Kprobe("sys_write", programWrite, nil)
    if err != nil {
        log.Fatalf("failed to attach kprobe to sys_write: %v", err)
    }
    defer kprobeWrite.Close()

    // Open perf buffer
    reader, err := perf.NewReader(perfMap, os.Getpagesize())
    if err != nil {
        log.Fatalf("failed to open perf buffer: %v", err)
    }
    defer reader.Close()

    fmt.Println("eBPF programs loaded and kprobes attached.")
    fmt.Println("Listening for events... Press Ctrl+C to exit.")

    var matchCount int
    sigs := make(chan os.Signal, 1)
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        for {
            record, err := reader.Read()
            if err != nil {
                if err == perf.ErrClosed {
                    return
                }
                log.Fatalf("perf buffer read failed: %v", err)
            }

            var e event
            err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e)
            if err != nil {
                log.Printf("failed to parse event: %v", err)
                continue
            }

            fmt.Printf("Matched syscall: %s by process %s\n",
                bytes.Trim(e.Syscall[:], "\x00"),
                bytes.Trim(e.Comm[:], "\x00"))

            matchCount++
        }
    }()

    <-sigs
    fmt.Printf("\nDetected %d matching syscalls before exit\n", matchCount)
}

