#include <linux/fs.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

typedef struct compound_perf_event {
  u64 timestamp;       // timestamp in microseconds
  u64 stack_hash;      // hash of the stack trace
  char event_name[32]; // name of the event (function name)
} compound_perf_event_t;

BPF_PERF_OUTPUT(compound_events);
BPF_STACK_TRACE(stack_traces, 1024);

int trace_function_call(struct pt_regs* ctx) {
  u32 pid = bpf_get_current_pid_tgid();

  if (FILTER || pid == 0)
    return 0;

  struct compound_perf_event data = {};
  data.timestamp = bpf_ktime_get_ns() / 1000; // Convert to microseconds

  // Get stack trace and hash it
  int stack_id = stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID);
  if (stack_id >= 0) {
    data.stack_hash = (u64)stack_id;
  } else {
    data.stack_hash = 0;
  }

  // Submit the event
  compound_events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}
