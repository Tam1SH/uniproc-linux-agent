use aya_ebpf::{bpf_printk, EbpfContext};
use aya_ebpf::helpers::{bpf_get_stack, bpf_probe_read_kernel};
use aya_ebpf::macros::{fentry, fexit, kprobe, kretprobe};
use aya_ebpf::programs::{FEntryContext, FExitContext, ProbeContext, RetProbeContext};
use macros::unsafe_body;
use crate::{bpf_read, bpf_read_leaf, print_stack};
use crate::constants::{AF_VSOCK, AF_INET, AF_INET6, AF_UNIX, IPPROTO_TCP, SOCK_STREAM, IPPROTO_UDP, SOCK_DGRAM};
use crate::programs::http_detect::is_http_port;
use crate::programs::processes::PROCESS_STATS;
use crate::utils::{get_pid, ERR_CODE};
use crate::vmlinux::{in6_addr, msghdr, p9_req_t, socket};

#[derive(Copy, Clone)]
pub enum TrafficDir {
    Tx,
    Rx,
}

#[inline(always)]
fn is_loopback_v6(skc_v6_daddr: &in6_addr) -> bool {
    unsafe {
        let addr32 = skc_v6_daddr.in6_u.u6_addr32;

        addr32[0] == 0 &&
            addr32[1] == 0 &&
            addr32[2] == 0 &&
            addr32[3] == 0x01000000
    }
}

#[inline(always)]
fn is_loopback_v4(addr: u32) -> bool {
    (addr & 0x000000FF) == 0x7F
}



// int sock_sendmsg(struct socket *sock, struct msghdr *msg);
// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/net.h#L259
#[fexit(function = "sock_sendmsg")]
#[unsafe_body]
pub fn socket_tracing_enter(ctx: FExitContext) -> Result<i32, i32> {

    let sock: *const socket = ctx.arg(0);
    let size = ctx.arg::<i32>(2) as u64;

    if size <= 0 || sock.is_null() {
        return Err(ERR_CODE);
    }

    let sk = bpf_read_leaf!(sock, sk, __sk_common)?;

    handle_socket_stats(ctx.arg(0), size, TrafficDir::Tx, get_pid())?;

    Ok(0)
}


// int sock_recvmsg(struct socket *sock, struct msghdr *msg, int flags);
// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/net.h#L260
#[fexit(function = "sock_recvmsg")]
#[unsafe_body]
pub fn socket_tracing_exit(ctx: FExitContext) -> Result<i32, i32> {

    let size = ctx.arg::<i32>(3) as u64;

    if size <= 0 {
        return Err(ERR_CODE);
    }

    let sock: *const socket = ctx.arg(0);

    if sock.is_null() {
        return Err(ERR_CODE);
    }

    handle_socket_stats(ctx.arg(0), size, TrafficDir::Rx, get_pid())?;

    Ok(0)
}

#[inline(always)]
unsafe fn handle_socket_stats(sock: *const socket, size: u64, dir: TrafficDir, pid: u32) -> Result<(), i32> {
    if sock.is_null() { return Err(ERR_CODE); }

    let sk = bpf_read_leaf!(sock, sk, __sk_common)?;
    let sock_type = bpf_read_leaf!(sock, type_)?;
    let family = sk.skc_family;

    match sk.skc_family {
        AF_UNIX => update_uds_stats(pid, size, dir),
        AF_VSOCK => update_vsock_stats(pid, size, dir),
        AF_INET | AF_INET6 => {

            let protocol = bpf_read_leaf!(sock, sk, sk_protocol)?;

            let is_lo = if family == AF_INET {
                let daddr = sk.__bindgen_anon_1.__bindgen_anon_1.skc_daddr;
                is_loopback_v4(daddr)
            } else {
                is_loopback_v6(&sk.skc_v6_daddr)
            };

            if protocol == IPPROTO_TCP || sock_type == SOCK_STREAM {
                if is_lo {
                    update_tcp_lo_stats(pid, size, dir);
                } else {
                    update_tcp_remote_stats(pid, size, dir);
                }
            } else if protocol == IPPROTO_UDP || sock_type == SOCK_DGRAM {
                if is_lo {
                    update_udp_lo_stats(pid, size, dir);
                } else {
                    update_udp_remote_stats(pid, size, dir);
                }
            }
        }
        _ => return Err(ERR_CODE),
    }
    Ok(())
}

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/net/9p/client.c#L582
// static struct p9_req_t *
// p9_client_rpc(struct p9_client *c, int8_t type, const char *fmt, ...);
#[kretprobe(function = "p9_client_rpc")]
#[unsafe_body]
pub fn p9_client_rpc_kretprobe(ctx: RetProbeContext) -> Result<i32, i32> {
    let req_ptr: *const p9_req_t = ctx.ret();
    if req_ptr.is_null() || (req_ptr as usize) > (-4096isize as usize) { return Ok(0); }

    let pid = get_pid();
    let tx_size = bpf_read_leaf!(req_ptr, tc)?.size as u64;
    let rx_size = bpf_read_leaf!(req_ptr, rc)?.size as u64;

    if tx_size > 0 { update_p9_stats(pid, tx_size, TrafficDir::Tx); }
    if rx_size > 0 { update_p9_stats(pid, rx_size, TrafficDir::Rx); }

    Ok(0)
}

macro_rules! gen_update_fn {
    ($fn_name:ident, $tx_field:ident, $rx_field:ident) => {
        #[inline(always)]
        pub unsafe fn $fn_name(pid: u32, len: u64, dir: TrafficDir) {
            if let Some(stats) = PROCESS_STATS.get_ptr_mut(&pid) {
                match dir {
                    TrafficDir::Tx => (*stats).$tx_field += len,
                    TrafficDir::Rx => (*stats).$rx_field += len,
                }
            }
        }
    };
}

gen_update_fn!(update_p9_stats, p9_tx_bytes, p9_rx_bytes);
gen_update_fn!(update_vsock_stats, vsock_tx_bytes, vsock_rx_bytes);
gen_update_fn!(update_tcp_remote_stats, tcp_tx_remote_bytes, tcp_rx_remote_bytes);
gen_update_fn!(update_tcp_lo_stats, tcp_tx_lo_bytes, tcp_rx_lo_bytes);
gen_update_fn!(update_uds_stats, uds_tx_bytes, uds_rx_bytes);
gen_update_fn!(update_udp_remote_stats, udp_tx_remote_bytes, udp_rx_remote_bytes);
gen_update_fn!(update_udp_lo_stats, udp_tx_lo_bytes, udp_rx_lo_bytes);
gen_update_fn!(update_disk_stats, disk_write_bytes, disk_read_bytes);
gen_update_fn!(update_pipe_stats, pipe_write_bytes, pipe_read_bytes);