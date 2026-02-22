use aya_ebpf::macros::map;
use aya_ebpf::maps::LruHashMap;
use uniproc_linux_agent_common::ProcessInfo;

#[map]
pub static PROCESS_CACHE: LruHashMap<u32, ProcessInfo> = LruHashMap::with_max_entries(4096, 0);