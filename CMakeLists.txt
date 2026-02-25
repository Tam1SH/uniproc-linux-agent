cmake_minimum_required(VERSION 3.16)
project(uniproc-linux-agent-ebpf C)

set(CMAKE_C_STANDARD 11)

include_directories(uniproc-linux-agent-ebpf/src /usr/include)

add_definitions(-D__BPF_TRACING__ -D__x86_64__)

add_executable(ebpf_prog
        uniproc-linux-agent-ebpf/src/prog.bpf.c
        uniproc-linux-agent-ebpf/src/constants.h
        uniproc-linux-agent-ebpf/src/maps.h
        uniproc-linux-agent-ebpf/src/utils.h
        uniproc-linux-agent-ebpf/src/vmlinux.h)