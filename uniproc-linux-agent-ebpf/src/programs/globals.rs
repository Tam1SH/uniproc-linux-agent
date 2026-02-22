use aya_ebpf::{macros::{map, perf_event}, maps::PerCpuArray, programs::PerfEventContext, helpers::bpf_get_current_pid_tgid, EbpfContext};
use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_buf};
use aya_ebpf::macros::tracepoint;
use aya_ebpf::maps::Array;
use aya_ebpf::programs::TracePointContext;
use aya_log_ebpf::info;
use uniproc_linux_agent_common::{CpuStats, MemStats, INDEX_IDLE_TICKS, INDEX_TOTAL_TICKS};
use crate::programs::processes::update_process_metrics;
use crate::utils::get_pid;
use crate::vmlinux::{atomic_long_t, node_stat_item, trace_event_raw_sched_stat_runtime, trace_event_raw_sched_switch, zone_stat_item};

#[map]
static CPU_STATS: PerCpuArray<CpuStats> = PerCpuArray::with_max_entries(1, 0);

#[map]
static MEM_STATS: Array<MemStats> = Array::with_max_entries(1, 0);

#[map]
static LAST_MEM_UPDATE: Array<u64> = Array::with_max_entries(1, 0);

#[map]
pub static SHIFT: Array<u32> = Array::with_max_entries(1, 0);

const MEM_UPDATE_INTERVAL_NS: u64 = 1_000_000;

#[map]
static KSYM_ADDRS: Array<u64> = Array::with_max_entries(4, 0);

#[tracepoint(name = "sched_stat_runtime", category = "sched")]
pub fn global_cpu_monitor(ctx: TracePointContext) -> i32 { unsafe {

    let args = &*(ctx.as_ptr() as *const trace_event_raw_sched_stat_runtime);

    let runtime = args.runtime;

    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    update_process_metrics(tgid, args.runtime);

    let now = bpf_ktime_get_ns();

    if let Some(stats) = CPU_STATS.get_ptr_mut(0) {
        (*stats).busy_ns += runtime;
        (*stats).last_tsc = now;
    }

    if let Some(last_update) = LAST_MEM_UPDATE.get_ptr_mut(0) {
        if now - *last_update >= MEM_UPDATE_INTERVAL_NS {
            if let Some(mem) = MEM_STATS.get_ptr_mut(0) {
                update_mem_stats(mem);
                *last_update = now;
            }
        }
    }

    0
}}

// Approximate implementation of si_mem_available()
// https://elixir.bootlin.com/linux/v6.19.2/source/mm/show_mem.c#L32
#[inline(always)]
unsafe fn update_mem_stats(mem: *mut MemStats) {
    let shift = SHIFT.get(0).copied().unwrap_or(0);
    if shift == 0 {
        return;
    }

    let totalram_addr = KSYM_ADDRS.get(0).copied().unwrap_or(0);
    let vm_zone_stat_addr = KSYM_ADDRS.get(1).copied().unwrap_or(0);
    let vm_node_stat_addr = KSYM_ADDRS.get(2).copied().unwrap_or(0);
    let total_reserve_addr = KSYM_ADDRS.get(3).copied().unwrap_or(0);

    if totalram_addr == 0 || vm_zone_stat_addr == 0 || vm_node_stat_addr == 0 || total_reserve_addr == 0 {
        return;
    }

    let atomic_size = size_of::<atomic_long_t>() as u64;

    // 1. Total RAM
    if let Ok(pages) = bpf_probe_read_kernel(totalram_addr as *const u64) {
        (*mem).total_kb = pages << shift;
    }

    // 2. Free Pages
    let mut free_pages: i64 = 0;
    let free_idx = zone_stat_item::NR_FREE_PAGES as u64;
    if let Ok(val) = bpf_probe_read_kernel((vm_zone_stat_addr + (free_idx * atomic_size)) as *const atomic_long_t) {
        free_pages = val.counter;
        (*mem).free_kb = if free_pages > 0 { (free_pages as u64) << shift } else { 0 };
    }

    // 3. Cached (Active + Inactive File)
    let mut active_file: i64 = 0;
    let mut inactive_file: i64 = 0;
    let mut shmem: i64 = 0;
    let mut slab_reclaimable: i64 = 0;

    let act_f_idx = node_stat_item::NR_ACTIVE_FILE as u64;
    let inact_f_idx = node_stat_item::NR_INACTIVE_FILE as u64;
    let shmem_idx = node_stat_item::NR_SHMEM as u64;
    let slab_re_idx = node_stat_item::NR_SLAB_RECLAIMABLE_B as u64;

    if let Ok(v) = bpf_probe_read_kernel((vm_node_stat_addr + (act_f_idx * atomic_size)) as *const atomic_long_t) { active_file = v.counter; }
    if let Ok(v) = bpf_probe_read_kernel((vm_node_stat_addr + (inact_f_idx * atomic_size)) as *const atomic_long_t) { inactive_file = v.counter; }
    if let Ok(v) = bpf_probe_read_kernel((vm_node_stat_addr + (shmem_idx * atomic_size)) as *const atomic_long_t) { shmem = v.counter; }
    if let Ok(v) = bpf_probe_read_kernel((vm_node_stat_addr + (slab_re_idx * atomic_size)) as *const atomic_long_t) { slab_reclaimable = v.counter; }

    let cached = (active_file + inactive_file + shmem) as u64;
    (*mem).cached_kb = cached << shift;


    let mut reserve_pages: u64 = 0;
    if let Ok(r) = bpf_probe_read_kernel(total_reserve_addr as *const u64) { reserve_pages = r; }

    let mut available = free_pages - (reserve_pages as i64);

    let reclaimable = (active_file + inactive_file + slab_reclaimable) as i64;
    let clearing_penalty = if reclaimable / 2 < reserve_pages as i64 { reclaimable / 2 } else { reserve_pages as i64 };
    available += reclaimable - clearing_penalty;

    let avail_final = if available > 0 { (available as u64) << shift } else { 0 };
    (*mem).available_kb = avail_final;

    let total_kb = (*mem).total_kb;
    if total_kb > avail_final {
        (*mem).used_kb = total_kb - avail_final;
    } else {
        (*mem).used_kb = 0;
    }


}

