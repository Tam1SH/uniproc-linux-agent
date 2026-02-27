#pragma once

#include "vmlinux.h"
#include "maps.h"
#include "constants.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MEM_UPDATE_INTERVAL_NS 1000000ULL

// Approximates si_mem_available() from kernel symbol addresses stored in
// ksym_addrs_map (populated by userspace on load):
//   [0] totalram_pages
//   [1] vm_zone_stat   (for NR_FREE_PAGES)
//   [2] vm_node_stat   (for file/anon/shmem/slab pages)
//   [3] totalreserve_pages
//
// Reference:
// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/mm/show_mem.c#L32
static __always_inline void update_mem_stats(struct machine_stats *mem) {
    __u32 key = 0;
    __u32 *shift_ptr = bpf_map_lookup_elem(&shift_map, &key);
    if (!shift_ptr || *shift_ptr == 0) return;
    __u32 shift = *shift_ptr;

    __u64 *a0 = bpf_map_lookup_elem(&ksym_addrs_map, &(__u32){0});
    __u64 *a1 = bpf_map_lookup_elem(&ksym_addrs_map, &(__u32){1});
    __u64 *a2 = bpf_map_lookup_elem(&ksym_addrs_map, &(__u32){2});
    __u64 *a3 = bpf_map_lookup_elem(&ksym_addrs_map, &(__u32){3});
    if (!a0 || !a1 || !a2 || !a3 || !*a0 || !*a1 || !*a2 || !*a3) return;

    __u64 atomic_size = sizeof(atomic_long_t);

    // 1. Total RAM
    __u64 total_pages = 0;
    bpf_probe_read_kernel(&total_pages, sizeof(total_pages), (void *)*a0);
    mem->total_kb = total_pages << shift;

    // 2. Free pages (vm_zone_stat[NR_FREE_PAGES])
    atomic_long_t val = {};
    bpf_probe_read_kernel(&val, sizeof(val),
        (void *)(*a1 + NR_FREE_PAGES * atomic_size));
    __s64 free_pages = val.counter;
    mem->free_kb = free_pages > 0 ? ((__u64)free_pages << shift) : 0;

    // 3. Reclaimable pages (vm_node_stat)
    __s64 active_file = 0, inactive_file = 0, shmem = 0, slab_reclaimable = 0;
    bpf_probe_read_kernel(&val, sizeof(val), (void *)(*a2 + NR_ACTIVE_FILE        * atomic_size)); active_file       = val.counter;
    bpf_probe_read_kernel(&val, sizeof(val), (void *)(*a2 + NR_INACTIVE_FILE      * atomic_size)); inactive_file     = val.counter;
    bpf_probe_read_kernel(&val, sizeof(val), (void *)(*a2 + NR_SHMEM              * atomic_size)); shmem             = val.counter;
    bpf_probe_read_kernel(&val, sizeof(val), (void *)(*a2 + NR_SLAB_RECLAIMABLE_B * atomic_size)); slab_reclaimable  = val.counter;

    mem->cached_kb = ((__u64)(active_file + inactive_file + shmem)) << shift;

    // 4. Available memory
    __u64 reserve_pages = 0;
    bpf_probe_read_kernel(&reserve_pages, sizeof(reserve_pages), (void *)*a3);

    __s64 available     = free_pages - (__s64)reserve_pages;
    __s64 reclaimable   = active_file + inactive_file + slab_reclaimable;
    __s64 penalty       = (reclaimable >> 1) < (__s64)reserve_pages
                          ? (reclaimable >> 1)
                          : (__s64)reserve_pages;
    available += reclaimable - penalty;

    mem->available_kb = available > 0 ? ((__u64)available << shift) : 0;
    mem->used_kb      = mem->total_kb > mem->available_kb
                        ? mem->total_kb - mem->available_kb : 0;
}