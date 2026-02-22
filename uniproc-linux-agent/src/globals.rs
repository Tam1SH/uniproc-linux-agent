use aya::maps::{MapData, PerCpuArray};
use aya::Pod;
use uniproc_linux_agent_common::CpuStats;

pub struct CpuSnapshot {
    pub cores: Vec<CpuStats>,
}


pub fn fetch_cpu_snapshot(map: &PerCpuArray<&MapData, CpuStats>) -> anyhow::Result<CpuSnapshot> {

    let values = map.get(&0, 0)?;
    Ok(CpuSnapshot { cores: values.as_ref().to_vec() })
}

pub fn calculate_usage(prev: &CpuSnapshot, curr: &CpuSnapshot) -> f64 {
    let mut total_busy_delta = 0u64;
    let mut max_time_delta = 0u64;

    for (p, c) in prev.cores.iter().zip(curr.cores.iter()) {
        let busy_delta = c.busy_ns.saturating_sub(p.busy_ns);
        let time_delta = c.last_tsc.saturating_sub(p.last_tsc);

        total_busy_delta += busy_delta;

        if time_delta > max_time_delta {
            max_time_delta = time_delta;
        }
    }

    if max_time_delta == 0 {
        return 0.0;
    }

    let num_cpus = curr.cores.len() as u64;
    let total_capacity = max_time_delta * num_cpus;

    (total_busy_delta as f64 / total_capacity as f64) * 100.0
}
