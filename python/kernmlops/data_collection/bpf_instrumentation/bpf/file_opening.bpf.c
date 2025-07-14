#include <linux/fs.h>
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

typedef struct file_opening_perf_event {
  u32 pid;
  u32 tgid;
  u64 ts_uptime_us;
  char filename[NAME_MAX];
  int flags;
  int mode;
} file_opening_perf_event_t;

BPF_PERF_OUTPUT(file_opening_events);

int trace_sys_openat(struct pt_regs* ctx, int dfd, const char* filename, int flags, umode_t mode) {
  u32 pid = bpf_get_current_pid_tgid();
  u32 tgid = bpf_get_current_pid_tgid() >> 32;

  // Filter if needed (currently accepting all - same pattern as other hooks)
  if (FILTER || pid == 0)
    return 0;

  struct file_opening_perf_event data = {};
  data.pid = pid;
  data.tgid = tgid;
  data.ts_uptime_us = bpf_ktime_get_ns() / 1000;
  data.flags = flags;
  data.mode = mode;

  // Copy the filename (safely)
  bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

  file_opening_events.perf_submit(ctx, &data, sizeof(data));

  return 0;
}

BPF_HASH(counter, u64, u64);

int count_calls(struct pt_regs* ctx) {
  u64 key = 0;
  u64* val = counter.lookup(&key);
  if (val) {
    (*val)++;
  } else {
    u64 init_val = 1;
    counter.update(&key, &init_val);
  }
  return 0;
}
