use std::collections::HashMap;
use std::time::Instant;
use uniproc_linux_agent_common::ProcessStats;

#[derive(Debug, Clone)]
pub struct ProcessReport {
    pub pid: u32,
    pub local_pid: u32,
    pub cpu_usage_perc: f64,
    pub rss_mb: f64,
    
    pub vsock_rx_bytes: u64,
    pub vsock_tx_bytes: u64,
    
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

        let current_pids: std::collections::HashSet<u32> = raw_data
            .iter()
            .map(|raw| raw.global_pid)
            .collect();

        self.history.retain(|pid, _| current_pids.contains(pid));

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
                    vsock_rx_bytes: raw.vsock_tx_bytes,
                    vsock_tx_bytes: raw.vsock_rx_bytes,
                }
            })
            .collect();

        reports
    }
}