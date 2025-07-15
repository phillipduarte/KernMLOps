#include <linux/fs.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

typedef struct scheduler_core_perf_event {
  u32 pid;
  u32 tgid;
  u64 ts_uptime_us;
  char comm[TASK_COMM_LEN];
  int flags;
  int mode;
  char event_name[32];
} scheduler_core_perf_event_t;

BPF_PERF_OUTPUT(scheduler_core_events);

int trace_syscall(struct pt_regs* ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  u32 tgid = bpf_get_current_pid_tgid() >> 32;

  if (FILTER || pid == 0)
    return 0;

  struct scheduler_core_perf_event data = {};
  data.pid = pid;
  data.tgid = tgid;
  data.ts_uptime_us = bpf_ktime_get_ns() / 1000;

  // Get the process name
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  // IMPORTANT: Don't try to set event_name in BPF code
  // We'll set it in the Python handler function

  // Submit the event
  scheduler_core_events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}
