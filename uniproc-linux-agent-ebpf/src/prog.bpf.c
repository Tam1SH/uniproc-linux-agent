#include "vmlinux.h"
#include "constants.h"
#include "maps.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// ============================================================
// utils
// ============================================================

#define ERR_CODE -1337

static __always_inline __u32 get_pid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

// ============================================================
// http_detect
// ============================================================

#define PORT_80  0x5000
#define PORT_443 0xBB01

static __always_inline bool is_http_port(__u16 port_be) {
    return false;
}

// ============================================================
// sockets — traffic direction + update helpers
// ============================================================

typedef enum { TRAFFIC_TX, TRAFFIC_RX } traffic_dir_t;

#define GEN_UPDATE_FN(fn_name, tx_field, rx_field)                               \
static __always_inline void fn_name(__u32 pid, __u64 len, traffic_dir_t dir) {   \
    struct process_stats *s = bpf_map_lookup_elem(&process_stats_map, &pid);     \
    if (!s) return;                                                               \
    if (dir == TRAFFIC_TX) s->tx_field += len;                                   \
    else                   s->rx_field += len;                                   \
}

GEN_UPDATE_FN(update_p9_stats,         p9_tx_bytes,         p9_rx_bytes)
GEN_UPDATE_FN(update_vsock_stats,      vsock_tx_bytes,      vsock_rx_bytes)
GEN_UPDATE_FN(update_tcp_remote_stats, tcp_tx_remote_bytes, tcp_rx_remote_bytes)
GEN_UPDATE_FN(update_tcp_lo_stats,     tcp_tx_lo_bytes,     tcp_rx_lo_bytes)
GEN_UPDATE_FN(update_uds_stats,        uds_tx_bytes,        uds_rx_bytes)
GEN_UPDATE_FN(update_udp_remote_stats, udp_tx_remote_bytes, udp_rx_remote_bytes)
GEN_UPDATE_FN(update_udp_lo_stats,     udp_tx_lo_bytes,     udp_rx_lo_bytes)
GEN_UPDATE_FN(update_disk_stats,       disk_write_bytes,    disk_read_bytes)
GEN_UPDATE_FN(update_pipe_stats,       pipe_write_bytes,    pipe_read_bytes)

// ============================================================
// sockets — loopback helpers
// ============================================================

static __always_inline bool is_loopback_v6(struct in6_addr *addr) {
    __u32 a[4];
    bpf_probe_read_kernel(a, sizeof(a), addr->in6_u.u6_addr32);
    return a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0x01000000;
}

static __always_inline bool is_loopback_v4(__u32 addr) {
    return (addr & 0x000000FF) == 0x7F;
}

// ============================================================
// sockets — core logic
// ============================================================

static __always_inline int handle_socket_stats(struct socket *sock, __u64 size, traffic_dir_t dir, __u32 pid) {
    if (!sock) return ERR_CODE;

    __u16 family    = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
    __u16 sock_type = BPF_CORE_READ(sock, type);

    switch (family) {
        case AF_UNIX:
            update_uds_stats(pid, size, dir);
            break;
        case AF_VSOCK:
            update_vsock_stats(pid, size, dir);
            break;
        case AF_INET:
        case AF_INET6: {
            __u16 protocol = BPF_CORE_READ(sock, sk, sk_protocol);
            bool is_lo;
            if (family == AF_INET) {
                __u32 daddr = BPF_CORE_READ(sock, sk, __sk_common.skc_daddr);
                is_lo = is_loopback_v4(daddr);
            } else {
                struct in6_addr daddr6 = BPF_CORE_READ(sock, sk, __sk_common.skc_v6_daddr);
                is_lo = is_loopback_v6(&daddr6);
            }
            if (protocol == IPPROTO_TCP || sock_type == SOCK_STREAM) {
                if (is_lo) update_tcp_lo_stats(pid, size, dir);
                else       update_tcp_remote_stats(pid, size, dir);
            } else if (protocol == IPPROTO_UDP || sock_type == SOCK_DGRAM) {
                if (is_lo) update_udp_lo_stats(pid, size, dir);
                else       update_udp_remote_stats(pid, size, dir);
            }
            break;
        }
        default:
            return ERR_CODE;
    }
    return 0;
}

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/net.h#L259
SEC("fexit/sock_sendmsg")
int BPF_PROG(socket_tracing_enter, struct socket *sock, struct msghdr *msg, int ret) {
    if (ret <= 0 || !sock) return 0;
    handle_socket_stats(sock, (__u64)ret, TRAFFIC_TX, get_pid());
    return 0;
}

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/net.h#L260
SEC("fexit/sock_recvmsg")
int BPF_PROG(socket_tracing_exit, struct socket *sock, struct msghdr *msg, int flags, int ret) {
    if (ret <= 0 || !sock) return 0;
    handle_socket_stats(sock, (__u64)ret, TRAFFIC_RX, get_pid());
    return 0;
}

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/net/9p/client.c#L582
SEC("kretprobe/p9_client_rpc")
int BPF_KRETPROBE(p9_client_rpc_kretprobe, struct p9_req_t *req_ptr) {
    if (!req_ptr || (unsigned long)req_ptr > (unsigned long)(-4096L)) return 0;
    __u32 pid = get_pid();
    __u64 tx_size = BPF_CORE_READ(req_ptr, tc.size);
    __u64 rx_size = BPF_CORE_READ(req_ptr, rc.size);
    if (tx_size > 0) update_p9_stats(pid, tx_size, TRAFFIC_TX);
    if (rx_size > 0) update_p9_stats(pid, rx_size, TRAFFIC_RX);
    return 0;
}

// ============================================================
// disk
// ============================================================

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

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/fs.h#L2026
SEC("fexit/vfs_read")
int BPF_PROG(vfs_read_exit, struct file *file, char *buf, size_t count, loff_t *pos, ssize_t ret) {
    if (ret <= 0) return 0;
    __u32 pid = get_pid();
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    umode_t mode = BPF_CORE_READ(inode, i_mode);
    switch (mode & S_IFMT) {
        case S_IFREG:
            update_disk_stats(pid, (__u64)ret, TRAFFIC_RX);
            increment_disk_iops(pid, TRAFFIC_RX);
            break;
        case S_IFIFO:
            update_pipe_stats(pid, (__u64)ret, TRAFFIC_RX);
            break;
    }
    return 0;
}

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/fs.h#L2027
SEC("fexit/vfs_write")
int BPF_PROG(vfs_write_exit, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret) {
    if (ret <= 0) return 0;
    __u32 pid = get_pid();
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    umode_t mode = BPF_CORE_READ(inode, i_mode);
    switch (mode & S_IFMT) {
        case S_IFREG:
            update_disk_stats(pid, (__u64)ret, TRAFFIC_TX);
            increment_disk_iops(pid, TRAFFIC_TX);
            break;
        case S_IFIFO:
            update_pipe_stats(pid, (__u64)ret, TRAFFIC_TX);
            break;
    }
    return 0;
}

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/fs.h#L2985
SEC("fexit/vfs_iter_read")
int BPF_PROG(vfs_iter_read_exit, struct file *file, struct iov_iter *iter, loff_t *ppos, __u32 flags, ssize_t ret) {
    if (ret <= 0) return 0;
    if (is_regular_file(file))
        update_disk_stats(get_pid(), (__u64)ret, TRAFFIC_RX);
    return 0;
}

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/fs.h#L2987
SEC("fexit/vfs_iter_write")
int BPF_PROG(vfs_iter_write_exit, struct file *file, struct iov_iter *iter, loff_t *ppos, __u32 flags, ssize_t ret) {
    if (ret <= 0) return 0;
    if (is_regular_file(file))
        update_disk_stats(get_pid(), (__u64)ret, TRAFFIC_TX);
    return 0;
}

// ============================================================
// processes
// ============================================================

#define MM_FILEPAGES  0
#define MM_ANONPAGES  1
#define MM_SHMEMPAGES 3

static __always_inline int get_local_tgid(struct task_struct *task, __u32 *out) {
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    struct pid *pid_ptr        = BPF_CORE_READ(leader, thread_pid);
    int level                  = BPF_CORE_READ(pid_ptr, level);

    struct upid target = {};
    bpf_probe_read_kernel(&target, sizeof(target), &pid_ptr->numbers[level]);
    __u32 nr = target.nr;

    if (nr == 0)
        nr = (__u32)BPF_CORE_READ(leader, tgid);

    *out = nr;
    return nr == 0 ? ERR_CODE : 0;
}

static __always_inline void update_process_metrics(__u32 pid, __u64 runtime) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u32 flags = BPF_CORE_READ(task, flags);
    if (flags & 0x00200000) return; // kernel thread

    __u32 local_pid = 0;
    if (get_local_tgid(task, &local_pid) < 0 || local_pid == 0) return;

    struct process_stats *stats = bpf_map_lookup_elem(&process_stats_map, &local_pid);
    if (!stats) return;

    stats->cpu_runtime_ns += runtime;

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) return;

    __u32 key = 0;
    __u32 *shift_ptr = bpf_map_lookup_elem(&shift_map, &key);
    if (!shift_ptr) return;
    __u32 shift = *shift_ptr;

    __s64 pages = 0;
    int rss_idxs[3] = { MM_FILEPAGES, MM_ANONPAGES, MM_SHMEMPAGES };
    for (int i = 0; i < 3; i++) {
        __s64 count = 0;
        bpf_probe_read_kernel(&count, sizeof(count),
            &mm->rss_stat[rss_idxs[i]].count);
        if (count > 0) pages += count;
    }

    stats->rss_kb = pages > 0 ? ((__u64)pages << shift) : 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_proc_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);

    __u32 local_pid = 0;
    if (get_local_tgid(task, &local_pid) < 0 || local_pid == 0) return -1;

    struct process_stats new_stats = { .global_pid = tgid, .local_pid = local_pid };
    bpf_map_update_elem(&process_stats_map, &local_pid, &new_stats, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid);
    __u32 tgid = (__u32)(pid_tgid >> 32);

    __u32 local_pid = 0;
    if (get_local_tgid(task, &local_pid) < 0 || local_pid == 0) return -1;

    if (pid == tgid)
        bpf_map_delete_elem(&process_stats_map, &local_pid);

    return 0;
}

// ============================================================
// globals
// ============================================================

#define MEM_UPDATE_INTERVAL_NS 1000000ULL

static __always_inline void update_mem_stats(struct mem_stats *mem) {
    __u32 key = 0;
    __u32 *shift_ptr = bpf_map_lookup_elem(&shift_map, &key);
    if (!shift_ptr || *shift_ptr == 0) return;
    __u32 shift = *shift_ptr;

    __u64 *a0 = bpf_map_lookup_elem(&ksym_addrs_map, &(__u32){0});
    __u64 *a1 = bpf_map_lookup_elem(&ksym_addrs_map, &(__u32){1});
    __u64 *a2 = bpf_map_lookup_elem(&ksym_addrs_map, &(__u32){2});
    __u64 *a3 = bpf_map_lookup_elem(&ksym_addrs_map, &(__u32){3});
    if (!a0 || !a1 || !a2 || !a3 || !*a0 || !*a1 || !*a2 || !*a3) return;

    __u64 totalram_addr      = *a0;
    __u64 vm_zone_stat_addr  = *a1;
    __u64 vm_node_stat_addr  = *a2;
    __u64 total_reserve_addr = *a3;

    __u64 atomic_size = sizeof(atomic_long_t);

    // 1. Total RAM
    __u64 total_pages = 0;
    bpf_probe_read_kernel(&total_pages, sizeof(total_pages), (void *)totalram_addr);
    mem->total_kb = total_pages << shift;

    // 2. Free pages
    atomic_long_t val = {};
    bpf_probe_read_kernel(&val, sizeof(val), (void *)(vm_zone_stat_addr + NR_FREE_PAGES * atomic_size));
    __s64 free_pages = val.counter;
    mem->free_kb = free_pages > 0 ? ((__u64)free_pages << shift) : 0;

    // 3. Node stats
    __s64 active_file = 0, inactive_file = 0, shmem = 0, slab_reclaimable = 0;
    bpf_probe_read_kernel(&val, sizeof(val), (void *)(vm_node_stat_addr + NR_ACTIVE_FILE        * atomic_size)); active_file       = val.counter;
    bpf_probe_read_kernel(&val, sizeof(val), (void *)(vm_node_stat_addr + NR_INACTIVE_FILE      * atomic_size)); inactive_file     = val.counter;
    bpf_probe_read_kernel(&val, sizeof(val), (void *)(vm_node_stat_addr + NR_SHMEM              * atomic_size)); shmem             = val.counter;
    bpf_probe_read_kernel(&val, sizeof(val), (void *)(vm_node_stat_addr + NR_SLAB_RECLAIMABLE_B * atomic_size)); slab_reclaimable  = val.counter;

    mem->cached_kb = ((__u64)(active_file + inactive_file + shmem)) << shift;

    // 4. Available (si_mem_available approximation)
    // https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/mm/show_mem.c#L32
    __u64 reserve_pages = 0;
    bpf_probe_read_kernel(&reserve_pages, sizeof(reserve_pages), (void *)total_reserve_addr);

    __s64 available  = free_pages - (__s64)reserve_pages;
    __s64 reclaimable = active_file + inactive_file + slab_reclaimable;
    __s64 half_reclaimable = reclaimable >> 1;
    __s64 penalty = (half_reclaimable < (__s64)reserve_pages) ? half_reclaimable : (__s64)reserve_pages;
    available += reclaimable - penalty;

    mem->available_kb = available > 0 ? ((__u64)available << shift) : 0;
    mem->used_kb = mem->total_kb > mem->available_kb ? mem->total_kb - mem->available_kb : 0;
}

SEC("tracepoint/sched/sched_stat_runtime")
int global_cpu_monitor(struct trace_event_raw_sched_stat_runtime *ctx) {
    __u64 runtime  = ctx->runtime;
    __u32 tgid     = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 now      = bpf_ktime_get_ns();
    __u32 key      = 0;

    update_process_metrics(tgid, runtime);

    struct cpu_stats *cpu = bpf_map_lookup_elem(&cpu_stats_map, &key);
    if (cpu) {
        cpu->busy_ns  += runtime;
        cpu->last_tsc  = now;
    }

    __u64 *last_update = bpf_map_lookup_elem(&last_mem_update_map, &key);
    if (last_update && (now - *last_update >= MEM_UPDATE_INTERVAL_NS)) {
        struct mem_stats *mem = bpf_map_lookup_elem(&mem_stats_map, &key);
        if (mem) {
            update_mem_stats(mem);
            *last_update = now;
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";