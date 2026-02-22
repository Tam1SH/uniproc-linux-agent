use std::collections::HashMap;
use std::time::Instant;
use uniproc_linux_agent_common::ProcessStats;

#[derive(Debug, Clone)]
pub struct ProcessReport {
    pub pid: u32,
    pub local_pid: u32,
    pub cpu_usage_perc: f64,
    pub rss_mb: f64,
}

pub struct ProcessMetricsState {
    history: HashMap<u32, (u64, Instant)>,
}

impl ProcessMetricsState {
    pub fn new() -> Self {
        Self {
            history: HashMap::with_capacity(1024),
        }
    }

    pub fn normalize(&mut self, raw_data: Vec<ProcessStats>) -> Vec<ProcessReport> {
        let now = Instant::now();

        let mut reports: Vec<ProcessReport> = raw_data
            .into_iter()
            .map(|raw| {
                let (prev_runtime, prev_time) = self.history
                    .get(&raw.global_pid)
                    .copied()
                    .unwrap_or((raw.cpu_runtime_ns, now));

                let delta_ns = raw.cpu_runtime_ns.saturating_sub(prev_runtime);
                let duration = now.duration_since(prev_time).as_secs_f64();

                let cpu_usage = if duration > 0.0 {
                    (delta_ns as f64 / (duration * 1_000_000_000.0)) * 100.0
                } else {
                    0.0
                };

                self.history.insert(raw.global_pid, (raw.cpu_runtime_ns, now));

                ProcessReport {
                    pid: raw.global_pid,
                    local_pid: raw.local_pid,
                    cpu_usage_perc: cpu_usage,
                    rss_mb: raw.rss_kb as f64 / 1024.0,
                }
            })
            .collect();

        if self.history.len() > 4096 {
            let active_pids: HashMap<u32, ()> = reports.iter().map(|r| (r.pid, ())).collect();
            self.history.retain(|pid, _| active_pids.contains_key(pid));
        }

        reports
    }
}