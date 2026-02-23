use aya_ebpf::{bpf_printk, EbpfContext};
use aya_ebpf::helpers::{bpf_get_stack, bpf_probe_read_kernel};
use aya_ebpf::macros::{fentry, fexit, kprobe, kretprobe};
use aya_ebpf::programs::{FEntryContext, FExitContext, ProbeContext, RetProbeContext};
use macros::unsafe_body;
use crate::{bpf_read, bpf_read_leaf, print_stack};
use crate::constants::AF_VSOCK;
use crate::programs::processes::PROCESS_STATS;
use crate::utils::{get_pid, ERR_CODE};
use crate::vmlinux::{msghdr, p9_req_t, socket};


//int sock_sendmsg(struct socket *sock, struct msghdr *msg);
// https://elixir.bootlin.com/linux/v6.6-rc1/source/include/linux/net.h#L259
#[fexit(function = "sock_sendmsg")]
#[unsafe_body]
pub fn socket_tracing_enter(ctx: FExitContext) -> Result<i32, i32> {

    let sock: *const socket = ctx.arg(0);
    let size: i32 = ctx.arg(2);

    if size <= 0 || sock.is_null() {
        return Err(ERR_CODE);
    }

    let sk = bpf_read_leaf!(sock, sk, __sk_common)?;

    let pid = get_pid();

    if sk.skc_family == 40 {
        bpf_printk!(b"socket family is vsock and send: %d", size, 0, 0, 0);
    }

    match sk.skc_family {
        AF_VSOCK => update_tx_vsock_stats(pid, size as u64),
        _ => {}
    };

    Ok(0)
}


//int sock_recvmsg(struct socket *sock, struct msghdr *msg, int flags);
// https://elixir.bootlin.com/linux/v6.6-rc1/source/include/linux/net.h#L260
#[fexit(function = "sock_recvmsg")]
#[unsafe_body]
pub fn socket_tracing_exit(ctx: FExitContext) -> Result<i32, i32> {

    let sock_ptr: *const socket = ctx.arg(0);
    let msg_ptr: *const msghdr = ctx.arg(1);
    let flags: i32 = ctx.arg(2);
    let ret: i32 = ctx.arg(3);


    if ret <= 0 {
        return Err(ERR_CODE);
    }

    let sock: *const socket = ctx.arg(0);

    if sock.is_null() {
        return Err(ERR_CODE);
    }



    let sk = bpf_read_leaf!(sock, sk, __sk_common)?;

    if sk.skc_family == 40 {
        bpf_printk!(b"socket family is vsock and recv: %d", ret, 0, 0, 0);
    }

    let pid = get_pid();

    match sk.skc_family {
        AF_VSOCK => update_rx_vsock_stats(pid, ret as u64),
        _ => {}
    }


    Ok(0)
}

#[kretprobe(function = "p9_client_rpc")]
#[unsafe_body]
pub fn p9_client_rpc_kretprobe(ctx: RetProbeContext) -> Result<i32, i32> {

    let req_ptr: *const p9_req_t = ctx.ret();

    if req_ptr.is_null() || (req_ptr as usize) > (-4096isize as usize) {
        return Ok(0);
    }

    let pid = get_pid();


    let tx_call = bpf_read_leaf!(req_ptr, tc)?;
    let tx_size = tx_call.size;

    let rx_call = bpf_read_leaf!(req_ptr, rc)?;
    let rx_size = rx_call.size;

    bpf_printk!(b"9P RPC: pid:%d tx:%d rx:%d", pid, tx_size, rx_size, 0);

    if tx_size > 0 || rx_size > 0 {

        if tx_size > 0 {
            update_tx_p9_stats(pid, tx_size as u64);
        }
        if rx_size > 0 {
            update_rx_p9_stats(pid, rx_size as u64);
        }
    }

    Ok(0)
}

unsafe fn update_rx_p9_stats(pid: u32, len: u64) {
    if let Some(stats) = PROCESS_STATS.get_ptr_mut(&pid) {
        (*stats).p9_rx_bytes += len;
    }
}

unsafe fn update_tx_p9_stats(pid: u32, len: u64) {
    if let Some(stats) = PROCESS_STATS.get_ptr_mut(&pid) {
        (*stats).p9_tx_bytes += len;
    }
}

unsafe fn update_rx_vsock_stats(pid: u32, len: u64) {
    if let Some(stats) = PROCESS_STATS.get_ptr_mut(&pid) {
        (*stats).vsock_rx_bytes += len;
    }
}
unsafe fn update_tx_vsock_stats(pid: u32, len: u64) {
    if let Some(stats) = PROCESS_STATS.get_ptr_mut(&pid) {
        (*stats).vsock_tx_bytes += len;
    }
}