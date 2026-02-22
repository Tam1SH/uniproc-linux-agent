#![no_std]
#![no_main]
#![allow(unsafe_op_in_unsafe_fn)]

#[allow(all, clippy::all, warnings)]
mod vmlinux {
    include!("./vmlinux.rs");
}

mod map;
mod utils;
mod programs;

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

#[tracepoint]
pub fn uniproc_linux_agent(ctx: TracePointContext) -> u32 {
    try_uniproc_linux_agent(ctx).unwrap_or_else(|ret| ret)
}

fn try_uniproc_linux_agent(ctx: TracePointContext) -> Result<u32, u32> {
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
