#include <linux/fs.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

// Branch types for TCP receive processing
#define PICK_ENTRY                  0
#define PICK_IDLE                   1
#define PICK_DONE                   2
#define PICK_WHILE_IS_GROUP         3
#define PICK_WHILE_DIFFERENT_GROUPS 4

typedef struct scheduler_core_perf_event {
  u32 pid;
  u32 tgid;
  u64 ts_uptime_us;
  char comm[TASK_COMM_LEN];
  int flags;
  int mode;
  u8 event_type;
} scheduler_core_perf_event_t;

BPF_PERF_OUTPUT(scheduler_core_events);

int entry(struct pt_regs* ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  u32 tgid = bpf_get_current_pid_tgid() >> 32;

  if (FILTER || pid == 0)
    return 0;

  struct scheduler_core_perf_event data = {};
  data.pid = pid;
  data.tgid = tgid;
  data.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  data.event_type = PICK_ENTRY;

  // Get the process name
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  // IMPORTANT: Don't try to set event_name in BPF code
  // We'll set it in the Python handler function

  // Submit the event
  scheduler_core_events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

int idle(struct pt_regs* ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  u32 tgid = bpf_get_current_pid_tgid() >> 32;

  if (FILTER || pid == 0)
    return 0;

  struct scheduler_core_perf_event data = {};
  data.pid = pid;
  data.tgid = tgid;
  data.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  data.event_type = PICK_IDLE;

  // Get the process name
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  // IMPORTANT: Don't try to set event_name in BPF code
  // We'll set it in the Python handler function

  // Submit the event
  scheduler_core_events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}
int done(struct pt_regs* ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  u32 tgid = bpf_get_current_pid_tgid() >> 32;

  if (FILTER || pid == 0)
    return 0;

  struct scheduler_core_perf_event data = {};
  data.pid = pid;
  data.tgid = tgid;
  data.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  data.event_type = PICK_DONE;

  // Get the process name
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  // IMPORTANT: Don't try to set event_name in BPF code
  // We'll set it in the Python handler function

  // Submit the event
  scheduler_core_events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}
int while_is_group(struct pt_regs* ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  u32 tgid = bpf_get_current_pid_tgid() >> 32;

  if (FILTER || pid == 0)
    return 0;

  struct scheduler_core_perf_event data = {};
  data.pid = pid;
  data.tgid = tgid;
  data.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  data.event_type = PICK_WHILE_IS_GROUP;

  // Get the process name
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  // IMPORTANT: Don't try to set event_name in BPF code
  // We'll set it in the Python handler function

  // Submit the event
  scheduler_core_events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}
int while_different_groups(struct pt_regs* ctx) {
  u32 pid = bpf_get_current_pid_tgid();
  u32 tgid = bpf_get_current_pid_tgid() >> 32;

  if (FILTER || pid == 0)
    return 0;

  struct scheduler_core_perf_event data = {};
  data.pid = pid;
  data.tgid = tgid;
  data.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  data.event_type = PICK_WHILE_DIFFERENT_GROUPS;

  // Get the process name
  bpf_get_current_comm(&data.comm, sizeof(data.comm));

  // IMPORTANT: Don't try to set event_name in BPF code
  // We'll set it in the Python handler function

  // Submit the event
  scheduler_core_events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}
