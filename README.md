part of the [uniproc](https://github.com/Tam1SH/uniproc)

to generate vmlinux:
bpftool btf dump file /sys/kernel/btf/vmlinux format c > uniproc-linux-agent-ebpf/src/vmlinux.h
