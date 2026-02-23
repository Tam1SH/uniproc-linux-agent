use aya_ebpf::helpers::bpf_probe_read_kernel;
use aya_ebpf::macros::fexit;
use aya_ebpf::programs::FExitContext;
use macros::unsafe_body;
use crate::bpf_read_leaf;
use crate::constants::{S_IFMT, S_IFREG, S_IFIFO};
use crate::programs::processes::PROCESS_STATS;
use crate::programs::sockets::{update_disk_stats, update_pipe_stats, TrafficDir};
use crate::utils::get_pid;
use crate::vmlinux::{file, inode, umode_t};

#[inline(always)]
unsafe fn is_regular_file(file_ptr: *const file) -> bool {
    if file_ptr.is_null() { return false; }

    let inode_ptr = match bpf_read_leaf!(file_ptr, f_inode) {
        Ok(ptr) => ptr,
        Err(_) => return false,
    };

    if inode_ptr.is_null() { return false; }

    let mode = match bpf_read_leaf!(inode_ptr, i_mode) {
        Ok(m) => m,
        Err(_) => return false,
    };

    (mode & S_IFMT) == S_IFREG
}


// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/fs.h#L2026
// extern ssize_t vfs_read(struct file *, char __user *, size_t, loff_t *);
#[fexit(function = "vfs_read")]
#[unsafe_body]
pub fn vfs_read_exit(ctx: FExitContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg::<i64>(4);
    if ret <= 0 { return Ok(0); }
    let size = ret as u64;

    let file_ptr: *const file = ctx.arg(0);
    let inode_ptr = bpf_read_leaf!(file_ptr, f_inode)?;
    let mode = bpf_read_leaf!(inode_ptr, i_mode)?;
    let pid = get_pid();

    match mode & S_IFMT {
        S_IFREG => {
            update_disk_stats(pid, size, TrafficDir::Rx);
            increment_disk_iops(pid, TrafficDir::Rx);
        }
        S_IFIFO => {
            update_pipe_stats(pid, size, TrafficDir::Rx);
        }
        _ => {}
    }

    Ok(0)
}

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/fs.h#L2027
// extern ssize_t vfs_write(struct file *, const char __user *, size_t, loff_t *);
#[fexit(function = "vfs_write")]
#[unsafe_body]
pub fn vfs_write_exit(ctx: FExitContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg::<i64>(4);
    if ret <= 0 { return Ok(0); }
    let size = ret as u64;

    let file_ptr: *const file = ctx.arg(0);
    let inode_ptr = bpf_read_leaf!(file_ptr, f_inode)?;
    let mode = bpf_read_leaf!(inode_ptr, i_mode)?;
    let pid = get_pid();

    match mode & S_IFMT {
        S_IFREG => {
            update_disk_stats(pid, size, TrafficDir::Tx);
            increment_disk_iops(pid, TrafficDir::Tx);
        }
        S_IFIFO => {
            update_pipe_stats(pid, size, TrafficDir::Tx);
        }
        _ => {}
    }

    Ok(0)
}

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/fs.h#L2985
// ssize_t vfs_iter_read(struct file *file, struct iov_iter *iter, loff_t *ppos,
// 		rwf_t flags);
#[fexit(function = "vfs_iter_read")]
#[unsafe_body]
pub fn vfs_iter_read_exit(ctx: FExitContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg::<i64>(5);
    if ret <= 0 { return Ok(0); }

    let file_ptr: *const file = ctx.arg(0);
    if is_regular_file(file_ptr) {
        update_disk_stats(get_pid(), ret as u64, TrafficDir::Rx);
    }
    Ok(0)
}

// https://github.com/microsoft/WSL2-Linux-Kernel/blob/427645e3db3a8896714f22a3d3fe0c3f7b317ad4/include/linux/fs.h#L2987
// ssize_t vfs_iter_write(struct file *file, struct iov_iter *iter, loff_t *ppos,
// 		rwf_t flags);
#[fexit(function = "vfs_iter_write")]
#[unsafe_body]
pub fn vfs_iter_write_exit(ctx: FExitContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg::<i64>(5);
    if ret <= 0 { return Ok(0); }

    let file_ptr: *const file = ctx.arg(0);
    if is_regular_file(file_ptr) {
        update_disk_stats(get_pid(), ret as u64, TrafficDir::Tx);
    }
    Ok(0)
}

#[inline(always)]
unsafe fn increment_disk_iops(pid: u32, dir: TrafficDir) {
    if let Some(stats) = PROCESS_STATS.get_ptr_mut(&pid) {
        match dir {
            TrafficDir::Tx => (*stats).disk_write_iops += 1,
            TrafficDir::Rx => (*stats).disk_read_iops += 1,
        }
    }
}
