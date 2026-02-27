#include "include/process.h"
#include "include/mem.h"

SEC("tracepoint/sched/sched_stat_runtime")
int global_cpu_monitor(struct trace_event_raw_sched_stat_runtime *ctx) {
    __u64 runtime = ctx->runtime;
    __u64 now     = bpf_ktime_get_ns();
    __u32 zero    = 0;

    update_process_metrics((__u32)(bpf_get_current_pid_tgid() >> 32), runtime);

    struct machine_stats *ms = bpf_map_lookup_elem(&machine_stats_map, &zero);
    if (!ms) return 0;

    ms->busy_ns  += runtime;
    ms->last_tsc  = now;

    __u64 *last_update = bpf_map_lookup_elem(&last_mem_update_map, &zero);
    if (last_update && (now - *last_update >= MEM_UPDATE_INTERVAL_NS)) {
        update_mem_stats(ms);
        *last_update = now;
    }

    return 0;
}