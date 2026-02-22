mod globals;
mod processes;

use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;
use crate::map::PROCESS_CACHE;
use crate::utils::get_pid;

#[tracepoint]
pub fn handle_process_exit(ctx: TracePointContext) {
    let pid = get_pid();
    PROCESS_CACHE.remove(&pid).ok();
}
