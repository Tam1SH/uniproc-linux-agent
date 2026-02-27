#pragma once

#include "vmlinux.h"
#include "maps.h"
#include "common.h"
#include <bpf/bpf_core_read.h>
#include "constants.h"

static __always_inline bool is_regular_file(struct file *file_ptr) {
    if (!file_ptr) return false;
    struct inode *inode_ptr = BPF_CORE_READ(file_ptr, f_inode);
    if (!inode_ptr) return false;
    umode_t mode = BPF_CORE_READ(inode_ptr, i_mode);
    return (mode & S_IFMT) == S_IFREG;
}

static __always_inline void increment_disk_iops(__u32 pid, traffic_dir_t dir) {
    struct process_stats *s = bpf_map_lookup_elem(&process_stats_map, &pid);
    if (!s) return;
    if (dir == TRAFFIC_TX) s->disk_write_iops += 1;
    else                   s->disk_read_iops  += 1;
}