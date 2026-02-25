use std::collections::HashMap;
use std::fs;
use std::mem::MaybeUninit;
use std::time::Duration;
use anyhow::anyhow;
use libbpf_rs::{MapCore, MapFlags};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use tokio::signal;
use uniproc_linux_agent_common::{CpuStats, MemStats, ProcessStats};


mod process_metrics_state;
mod proc_checker;

mod prog {
    include!(concat!(env!("OUT_DIR"), "/prog.skel.rs"));
}

use prog::ProgSkelBuilder;
use crate::proc_checker::{initialize_proc_map, ProcChecker};
use crate::process_metrics_state::ProcessReport;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_rlimits()?;

    let mut skel_builder = ProgSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    let mut skel = open_skel.load()?;

    setup_mem_config(&mut skel)?;
    setup_kernel_symbols(&mut skel)?;

    skel.attach()?;

    println!("Agent is running. Press Ctrl-C to stop...");

    tokio::select! {
        _ = signal::ctrl_c() => println!("\nShutting down..."),
        _ = main_loop(skel) => println!("Main loop finished unexpectedly"),
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
        eprintln!("warning: failed to remove memlock limit");
    }
    Ok(())
}

fn setup_mem_config(skel: &mut prog::ProgSkel) -> anyhow::Result<()> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
    let shift = (page_size.trailing_zeros() - 10) as u32;

    let shift_map = &skel.maps.shift_map;
    shift_map.update(&0u32.to_ne_bytes(), &shift.to_ne_bytes(), MapFlags::ANY)?;

    let last_mem = &skel.maps.last_mem_update_map;
    last_mem.update(&0u32.to_ne_bytes(), &1u64.to_ne_bytes(), MapFlags::ANY)?;

    Ok(())
}

fn setup_kernel_symbols(skel: &mut prog::ProgSkel) -> anyhow::Result<()> {
    let syms = read_kallsyms()?;

    let find_sym = |name: &str| {
        syms.get(name)
            .copied()
            .ok_or_else(|| anyhow!("Symbol {} not found", name))
    };

    let addrs = [
        find_sym("_totalram_pages")?,
        find_sym("vm_zone_stat")?,
        find_sym("vm_node_stat")?,
        find_sym("totalreserve_pages")?,
    ];

    let ksym_map = &skel.maps.ksym_addrs_map;
    for (i, addr) in addrs.iter().enumerate() {
        ksym_map.update(&(i as u32).to_ne_bytes(), &addr.to_ne_bytes(), MapFlags::ANY)?;
    }

    Ok(())
}

fn read_kallsyms() -> anyhow::Result<HashMap<String, u64>> {
    let content = fs::read_to_string("/proc/kallsyms")?;
    let mut map = HashMap::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let addr = u64::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let _typ = parts.next();
        if let Some(name) = parts.next() {
            map.insert(name.to_string(), addr);
        }
    }
    Ok(map)
}

async fn main_loop(skel: prog::ProgSkel<'_>) {
    let mut metrics_engine = process_metrics_state::ProcessMetricsState::new();
    let _ = initialize_proc_map(&skel.maps.process_stats_map);
    loop {
        tokio::time::sleep(Duration::from_millis(300)).await;

        let map = &skel.maps.process_stats_map;

        let raw_stats: Vec<ProcessStats> = map
            .keys()
            .filter_map(|k| {
                let val = map.lookup(&k, MapFlags::ANY).ok()??;
                if val.len() < std::mem::size_of::<ProcessStats>() { return None; }
                Some(unsafe { *(val.as_ptr() as *const ProcessStats) })
            })
            .collect();

        let mut reports = metrics_engine.normalize(raw_stats);
        reports.sort_by(|a, b| b.cpu_usage_perc.partial_cmp(&a.cpu_usage_perc).unwrap());

        let _ = ProcChecker.tick(&skel.maps.process_stats_map);

        print!("\x1B[2J\x1B[H");
        println!("{:<10} {:<10} {:>10} {:>12}", "G-PID", "L-PID", "CPU %", "RSS (MB)");
        println!("all process: {}, size: {}", reports.len(), reports.len() * size_of::<ProcessReport>());
        println!("{}", "-".repeat(46));

        for rep in reports.iter().take(5) {
            println!(
                "{:<10} {:<10} {:>9.1}% {:>10.2} MB {:>10.2} RX {:>10.2} TX",
                rep.pid, rep.local_pid, rep.cpu_usage_perc, rep.rss_mb, rep.vsock_rx_bytes, rep.vsock_tx_bytes
            );
        }


        println!("processes: {}, /proc count: {}", reports.len(), count_processes());
    }
}

fn count_processes() -> usize {
    fs::read_dir("/proc")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit()))
                .count()
        })
        .unwrap_or(0)
}