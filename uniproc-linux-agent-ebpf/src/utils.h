#pragma once
#include <bpf/bpf_helpers.h>

#define ERR_CODE -1337

static __always_inline __u32 get_pid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}