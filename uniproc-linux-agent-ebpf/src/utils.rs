use aya_ebpf::helpers::bpf_get_current_pid_tgid;

#[inline(always)]
pub fn get_pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}