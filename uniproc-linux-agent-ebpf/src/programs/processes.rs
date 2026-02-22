use core::ptr::null;
use aya_ebpf::bindings::bpf_pidns_info;
use aya_ebpf::EbpfContext;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_ns_current_pid_tgid, bpf_probe_read_kernel};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::TracePointContext;
use uniproc_linux_agent_common::ProcessStats;
use crate::programs::globals::SHIFT;
use crate::vmlinux::{task_struct, trace_event_raw_sched_process_fork, upid};

#[map]
static PROCESS_STATS: LruHashMap<u32, ProcessStats> = LruHashMap::with_max_entries(4096, 0);

//https://elixir.bootlin.com/linux/v6.12.6/source/include/linux/mm_types_task.h
pub const MM_FILEPAGES:  usize = 0;
pub const MM_ANONPAGES:  usize = 1;
pub const MM_SWAPENTS:   usize = 2;
pub const MM_SHMEMPAGES: usize = 3;

const RSS_COUNTERS: [usize; 3] = [MM_FILEPAGES, MM_ANONPAGES, MM_SHMEMPAGES];

#[inline(always)]
unsafe fn get_local_tgid(task: *const task_struct) -> u32 {

    let leader = match bpf_probe_read_kernel(&(*task).group_leader) {
        Ok(l) => l,
        Err(_) => task,
    };

    let pid_ptr = match bpf_probe_read_kernel(&(*leader).thread_pid) {
        Ok(p) if !p.is_null() => p,
        _ => return bpf_probe_read_kernel(&(*leader).tgid).unwrap_or(0) as u32,
    };

    let level = match bpf_probe_read_kernel(&(*pid_ptr).level) {
        Ok(l) => l,
        Err(_) => return 0,
    };

    if level == 0 {
        return bpf_probe_read_kernel(&(*leader).tgid).unwrap_or(0) as u32;
    }

    if level > 0 && level < 3 {

        let numbers_ptr = core::ptr::addr_of!((*pid_ptr).numbers) as *const u8;

        let upid_size = core::mem::size_of::<upid>();

        let target_nr_ptr = numbers_ptr.add(level as usize * upid_size) as *const i32;

        if bpf_probe_read_kernel(target_nr_ptr).is_ok() {
            if let Ok(val) = bpf_probe_read_kernel(target_nr_ptr) {
                return val as u32;
            }
        }
    }

    bpf_probe_read_kernel(&(*leader).tgid).unwrap_or(0) as u32
}


#[inline(always)]
pub unsafe fn update_process_metrics(pid: u32, runtime: u64) {

    let stats_ptr = match PROCESS_STATS.get_ptr_mut(&pid) {
        Some(ptr) => ptr,
        None => {
            let task = bpf_get_current_task() as *const task_struct;

            let local_pid = if !task.is_null() {
                get_local_tgid(task)
            } else {
                pid
            };

            let new_stats = ProcessStats {
                global_pid: pid,
                local_pid,
                cpu_runtime_ns: 0,
                rss_kb: 0
            };

            if PROCESS_STATS.insert(&pid, &new_stats, 0).is_err() {
                return;
            }
            match PROCESS_STATS.get_ptr_mut(&pid) {
                Some(ptr) => ptr,
                None => return,
            }
        }
    };

    (*stats_ptr).cpu_runtime_ns += runtime;


    let task = bpf_get_current_task() as *const task_struct;
    if task.is_null() { return; }


    let mm_ptr = match bpf_probe_read_kernel(&(*task).mm) {
        Ok(p) if !p.is_null() => p,
        _ => return,
    };

    let mut pages: i64 = 0;
    let Some(shift) = SHIFT.get(0).copied() else { return; };

    for &idx in RSS_COUNTERS.iter() {

        let counter_ptr = &(*mm_ptr).__bindgen_anon_1.rss_stat[idx];
        if let Ok(counter) = bpf_probe_read_kernel(counter_ptr) {
            if counter.count > 0 {
                pages += counter.count;
            }
        }
    }

    (*stats_ptr).rss_kb = if pages > 0 { (pages as u64) << shift } else { 0 };
}



#[tracepoint(name = "handle_exit", category = "sched")]
pub fn handle_exit(ctx: TracePointContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;

    if pid == tgid {
        let _ = PROCESS_STATS.remove(&tgid);
    }
    0
}


#[tracepoint(name = "handle_fork", category = "sched")]
pub fn handle_fork(ctx: TracePointContext) -> i32 {
    unsafe {

        let args = &*(ctx.as_ptr() as *const trace_event_raw_sched_process_fork);
        let child_pid = args.child_pid as u32;

        let _ = PROCESS_STATS.remove(&child_pid);
    }
    0
}
