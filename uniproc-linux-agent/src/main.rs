use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};
use std::time::Duration;
use anyhow::anyhow;
use libbpf_rs::{MapCore, MapFlags};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use tokio::signal;
use uniproc_linux_agent_common::{ProcessStats};


mod process_metrics_state;
mod iter_gc;
mod seed;
mod batch_lookup;
mod name_cache;

mod prog {
    include!(concat!(env!("OUT_DIR"), "/prog.skel.rs"));
}

use prog::ProgSkelBuilder;
use crate::batch_lookup::BatchLookup;
use crate::iter_gc::IterGc;
use crate::name_cache::{CacheEntry, NameCache};
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
    let seed_prog_fd = skel.progs.seed_processes.as_fd().as_raw_fd();
    seed::seed_existing_processes(seed_prog_fd)?;

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

async fn main_loop(mut skel: prog::ProgSkel<'_>) {
    let mut metrics_engine = process_metrics_state::ProcessMetricsState::new();
    let iter_prog_fd = skel.progs.list_processes.as_fd().as_raw_fd();
    let iter_check_name_fd = skel.progs.task_names.as_fd().as_raw_fd();
    let mut gc = IterGc::new(10, iter_prog_fd);
    let mut cache = NameCache::new(iter_check_name_fd);
    let mut batch = BatchLookup::new();

    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;

        let map = &mut skel.maps.process_stats_map;
        let _ = gc.maybe_gc(map);

        let _ = cache.refresh(gc.live_pids());
        if let Ok(batch) = batch.lookup(&skel.maps.process_stats_map) {
            let reports = metrics_engine.normalize(
                batch.iter().copied()
            );
            #[cfg(debug_assertions)]
            debug_print(&reports, &cache);
        }

    }
}

#[cfg(debug_assertions)]
fn debug_print(reports: &[ProcessReport], cache: &NameCache) {
    let mut sorted = reports.to_vec();
    sorted.sort_by(|a, b| b.cpu_usage_perc.partial_cmp(&a.cpu_usage_perc).unwrap());

    print!("\x1B[2J\x1B[H");
    println!("{:<10} {:<10} {:>10} {:>12}", "G-PID", "L-PID", "CPU %", "RSS (MB)");
    println!("all process: {}, size: {}",
             sorted.len(), sorted.len() * std::mem::size_of::<ProcessReport>());
    println!("{}", "-".repeat(46));

    let names: HashMap<&u32, &CacheEntry> = cache.get_names().collect();

    for rep in sorted.iter().take(5) {
        let name = names
            .get(&rep.pid)
            .map(|e| String::from_utf8_lossy(&e.name))
            .unwrap_or_default();
        let name_col = format!("{:<20}", name.trim_end_matches('\0').chars().take(20).collect::<String>());

        println!(
            "{} {:<10} {:<10} {:>9.1}% {:>10.2} MB {:>10.2} RX {:>10.2} TX",
            name_col, rep.pid, rep.local_pid, rep.cpu_usage_perc, rep.rss_mb,
            rep.vsock_rx_bytes, rep.vsock_tx_bytes
        );
    }

    println!("processes: {}, /proc: {}", sorted.len(), count_processes());
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