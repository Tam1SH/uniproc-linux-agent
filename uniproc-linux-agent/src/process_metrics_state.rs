use std::time::Instant;
use rustc_hash::{FxHashMap, FxHashSet};
use uniproc_linux_agent_common::ProcessStats;

#[derive(Debug, Clone)]
pub struct ProcessReport {
    pub pid:            u32,
    pub local_pid:      u32,
    pub cpu_usage_perc: f64,
    pub rss_mb:         f64,
    pub vsock_rx_bytes: u64,
    pub vsock_tx_bytes: u64,
}

struct ProcHistory {
    cpu_runtime_ns: u64,
    time:           Instant,
}

pub struct ProcessMetricsState {
    history:      FxHashMap<u32, ProcHistory>,
    current_pids: FxHashSet<u32>,
    raw_buf:      Vec<ProcessStats>,
}

impl ProcessMetricsState {
    pub fn new() -> Self {
        Self {
            history:      FxHashMap::default(),
            current_pids: FxHashSet::default(),
            raw_buf:      Vec::with_capacity(512),
        }
    }

    pub fn normalize(&mut self, raw_data: impl Iterator<Item = ProcessStats>) -> Vec<ProcessReport> {
        let now = Instant::now();

        self.raw_buf.clear();
        self.raw_buf.extend(raw_data);

        self.current_pids.clear();
        self.current_pids.extend(self.raw_buf.iter().map(|r| r.global_pid));

        self.history.retain(|pid, _| self.current_pids.contains(pid));

        self.raw_buf
            .iter()
            .map(|raw| {
                let cpu_usage = if let Some(h) = self.history.get(&raw.global_pid) {
                    let delta_ns = raw.cpu_runtime_ns.saturating_sub(h.cpu_runtime_ns);
                    let duration = now.duration_since(h.time).as_secs_f64();
                    if duration > 0.0 {
                        (delta_ns as f64 / (duration * 1_000_000_000.0)) * 100.0
                    } else {
                        0.0
                    }
                } else {
                    0.0
                };

                self.history.insert(raw.global_pid, ProcHistory {
                    cpu_runtime_ns: raw.cpu_runtime_ns,
                    time:           now,
                });

                ProcessReport {
                    pid:            raw.global_pid,
                    local_pid:      raw.local_pid,
                    cpu_usage_perc: cpu_usage,
                    rss_mb:         raw.rss_kb as f64 / 1024.0,
                    vsock_rx_bytes: raw.vsock_rx_bytes,
                    vsock_tx_bytes: raw.vsock_tx_bytes,
                }
            })
            .collect()
    }
}