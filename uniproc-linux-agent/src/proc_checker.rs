use std::fs;
use libbpf_rs::{Map, MapCore, MapFlags};
use uniproc_linux_agent_common::ProcessStats;

pub struct ProcChecker;

impl ProcChecker {
    pub fn tick(&mut self, proc_stats_map: &Map) -> anyhow::Result<()> {
        let to_remove: Vec<Vec<u8>> = proc_stats_map
            .keys()
            .filter_map(|k| {
                let val = proc_stats_map.lookup(&k, MapFlags::ANY).ok()??;
                if val.len() < std::mem::size_of::<ProcessStats>() { return None; }
                let stats = unsafe { *(val.as_ptr() as *const ProcessStats) };
                if stats.global_pid == 0 { Some(k) } else { None }
            })
            .collect();

        println!("to remove: {}", to_remove.len());
        for key in to_remove {
            let _ = proc_stats_map.delete(&key);
        }

        Ok(())
    }
}

pub fn initialize_proc_map(proc_stats_map: &Map) -> anyhow::Result<()> {
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let s_name = name.to_string_lossy();

        if !s_name.chars().all(|c| c.is_numeric()) { continue; }

        let pid: u32 = s_name.parse()?;

        let stat_content = fs::read_to_string(format!("/proc/{}/stat", pid)).ok();
        let cpu_runtime_ns = if let Some(content) = stat_content {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() > 14 {
                let utime: u64 = parts[13].parse().unwrap_or(0);
                let stime: u64 = parts[14].parse().unwrap_or(0);
                (utime + stime) * 10_000_000
            } else { 0 }
        } else { 0 };

        let mut rss_kb = 0u64;
        if let Some(content) = fs::read_to_string(format!("/proc/{}/status", pid)).ok() {
            for line in content.lines() {
                if line.starts_with("VmRSS:") {
                    rss_kb = line.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                }
            }
        }

        let stats = ProcessStats {
            global_pid: pid,
            local_pid: pid,
            cpu_runtime_ns,
            rss_kb,
            ..Default::default()
        };

        let val = unsafe {
            std::slice::from_raw_parts(&stats as *const _ as *const u8, std::mem::size_of::<ProcessStats>())
        };

        let _ = proc_stats_map.update(&pid.to_ne_bytes(), val, MapFlags::ANY);
    }

    Ok(())
}