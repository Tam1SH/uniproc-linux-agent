#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

static __always_inline bool is_loopback_v4(__u32 addr) {
    return (addr & 0x000000FF) == 0x7F;
}

static __always_inline bool is_loopback_v6(struct in6_addr *addr) {
    __u32 a[4];
    bpf_probe_read_kernel(a, sizeof(a), addr->in6_u.u6_addr32);
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0x01000000;
}