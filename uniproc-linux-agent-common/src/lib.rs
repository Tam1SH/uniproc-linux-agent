#![no_std]


#[repr(C)]
#[derive(Clone)]
pub struct ProcessInfo {
    pub pid: u32,
}

#[repr(C)]
#[derive(Clone)]
pub struct MachineStats {
    pub cpu_usage_percent: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuStats {
    pub busy_ns: u64,
    pub last_tsc: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemStats {
    pub total_kb: u64,
    pub free_kb: u64,
    pub cached_kb: u64,
    pub available_kb: u64,
    pub used_kb: u64,
}


#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct ProcessStats {
    pub global_pid: u32,
    pub local_pid: u32,
    pub cpu_runtime_ns: u64,
    
    pub rss_kb: u64,
    
    pub last_active_ns: u64,
    
    pub vsock_rx_bytes: u64,
    pub vsock_tx_bytes: u64,

    pub p9_rx_bytes: u64,
    pub p9_tx_bytes: u64,

    pub tcp_tx_lo_bytes: u64,
    pub tcp_rx_lo_bytes: u64,

    pub tcp_tx_remote_bytes: u64,
    pub tcp_rx_remote_bytes: u64,

    pub udp_tx_lo_bytes: u64,
    pub udp_rx_lo_bytes: u64,

    pub udp_tx_remote_bytes: u64,
    pub udp_rx_remote_bytes: u64,

    pub uds_tx_bytes: u64,
    pub uds_rx_bytes: u64,

    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,

    pub disk_read_iops: u64,
    pub disk_write_iops: u64,

    pub pipe_read_bytes: u64,
    pub pipe_write_bytes: u64,

    pub sendfile_bytes: u64,
}

pub const INDEX_TOTAL_TICKS: u32 = 0;
pub const INDEX_IDLE_TICKS: u32 = 1;
