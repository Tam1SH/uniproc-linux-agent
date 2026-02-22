use anyhow::anyhow;
use aya::Ebpf;
use aya::maps::{Array, HashMap, PerCpuArray};
use aya::programs::TracePoint;
use aya::util::kernel_symbols;
use log::{debug, warn};
use std::time::Duration;
use tokio::{signal, time::sleep};

use uniproc_linux_agent_common::{CpuStats, MachineStats, MemStats, ProcessStats};
mod globals;
mod process_metrics_state;

use crate::globals::{calculate_usage, fetch_cpu_snapshot};
use crate::process_metrics_state::ProcessMetricsState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    setup_rlimits()?;

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/uniproc-linux-agent"
    )))?;

    init_ebpf_logger(&mut ebpf)?;

    setup_mem_config(&mut ebpf)?;

    setup_kernel_symbols(&mut ebpf)?;

    attach_programs(&mut ebpf)?;

    println!("Agent is running. Press Ctrl-C to stop...");

    tokio::select! {
        _ = signal::ctrl_c() => println!("\nShutting down..."),
        _ = main_loop(ebpf) => println!("Main loop finished unexpectedly"),
    }

    Ok(())
}

fn setup_rlimits() -> anyhow::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed");
    }
    Ok(())
}

fn init_ebpf_logger(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    match aya_log::EbpfLogger::init(ebpf) {
        Ok(logger) => {
            let mut logger = tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
        Err(e) => warn!("failed to initialize eBPF logger: {e}"),
    }
    Ok(())
}


fn setup_mem_config(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut config: Array<_, u32> = Array::try_from(ebpf.map_mut("SHIFT").unwrap())?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
    let shift = page_size.trailing_zeros() - 10;
    config.set(0, &shift, 0)?;

    let mut last_upd_map: Array<_, u64> = Array::try_from(ebpf.map_mut("LAST_MEM_UPDATE").unwrap())?;
    last_upd_map.set(0, &1, 0)?;
    Ok(())
}

fn setup_kernel_symbols(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let syms = kernel_symbols()?;

    let find_sym = |name: &str| {
        syms.iter()
            .find(|(_, s)| *s == name)
            .map(|(addr, _)| *addr)
            .ok_or_else(|| anyhow!("Symbol {} not found", name))
    };

    let addrs = [
        find_sym("_totalram_pages")?,
        find_sym("vm_zone_stat")?,
        find_sym("vm_node_stat")?,
        find_sym("totalreserve_pages")?,
    ];

    let mut ksym_map: Array<_, u64> = Array::try_from(ebpf.map_mut("KSYM_ADDRS").unwrap())?;
    for (i, addr) in addrs.iter().enumerate() {
        ksym_map.set(i as u32, addr, 0)?;
    }

    Ok(())
}

fn attach_programs(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let switch: &mut TracePoint = ebpf.program_mut("uniproc_linux_agent").unwrap().try_into()?;
    switch.load()?;
    switch.attach("sched", "sched_switch")?;

    let monitor: &mut TracePoint = ebpf.program_mut("global_cpu_monitor").unwrap().try_into()?;
    monitor.load()?;
    monitor.attach("sched", "sched_stat_runtime")?;

    let exit_prog: &mut TracePoint = ebpf.program_mut("handle_exit").unwrap().try_into()?;
    exit_prog.load()?;
    exit_prog.attach("sched", "sched_process_exit")?;

    let fork_prog: &mut TracePoint = ebpf.program_mut("handle_fork").unwrap().try_into()?;
    fork_prog.load()?;
    fork_prog.attach("sched", "sched_process_fork")?;

    Ok(())
}


async fn main_loop(ebpf: Ebpf) {
    let proc_stats_map: HashMap<_, u32, ProcessStats> = ebpf
        .map("PROCESS_STATS")
        .unwrap()
        .try_into()
        .unwrap();

    let mut metrics_engine = ProcessMetricsState::new();

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let raw_stats: Vec<ProcessStats> = proc_stats_map
            .iter()
            .filter_map(|r| r.ok().map(|(_, v)| v))
            .collect();

        let mut reports = metrics_engine.normalize(raw_stats);

        reports.sort_by(|a, b| b.cpu_usage_perc.partial_cmp(&a.cpu_usage_perc).unwrap());

        print!("\x1B[2J\x1B[H");
        println!("{:<10} {:<10} {:>10} {:>12}", "G-PID", "L-PID", "CPU %", "RSS (MB)");
        println!("{}", "-".repeat(46));

        for rep in reports.iter().take(5) {
            println!(
                "{:<10} {:<10} {:>9.1}% {:>10.2} MB",
                rep.pid, rep.local_pid, rep.cpu_usage_perc, rep.rss_mb
            );
        }
    }
}
