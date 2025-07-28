from dataclasses import dataclass
from pathlib import Path

import polars as pl
from bcc import BPF
from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable, SchedulerCoreTable

# Define constants for event types
PICK_ENTRY = 0
PICK_IDLE = 1
PICK_DONE = 2
PICK_WHILE_IS_GROUP = 3
PICK_WHILE_DIFFERENT_GROUPS = 4

EVENT_NAMES = {
    PICK_ENTRY: "entry",
    PICK_IDLE: "idle",
    PICK_DONE: "done",
    PICK_WHILE_IS_GROUP: "while_is_group",
    PICK_WHILE_DIFFERENT_GROUPS: "while_different_groups",
}

@dataclass(frozen=True)
class SchedulerCoreData:
    cpu: int
    pid: int
    tgid: int
    ts_uptime_us: int
    comm: str
    flags: int
    mode: int
    event_name: str


class SchedulerCoreBPFHook(BPFProgram):
    @classmethod
    def name(cls) -> str:
        return "scheduler_core"

    def __init__(self):
        bpf_text = open(Path(__file__).parent / "bpf/scheduler_core.bpf.c", "r").read()

        # Replace the FILTER placeholder with '0' to accept all events
        self.bpf_text = bpf_text.replace('FILTER', '0')
        self.scheduler_core_data = list[SchedulerCoreData]()

    def load(self, collection_id: str):
        print(f"[DEBUG] Loading scheduler_core hook with collection_id {collection_id}")
        self.collection_id = collection_id

        # Define all kernel events we want to monitor
        kernel_events = [
            ("entry", 0),
            ("idle", 0x31),
            ("done", 0x126),
            ("while_is_group", 0xa4),
            ("while_different_groups", 0x1d3),
        ]

        event_bpf = self.bpf_text
        self.bpf = BPF(text=event_bpf)
        # Create a version of the BPF program for each event
        for event, offset in kernel_events:
            # Attach the kprobe
            self.bpf.attach_kprobe(
                event="pick_next_task_fair",
                fn_name=event.encode(),
                event_off=offset,
            )

        # Set up the perf buffer with a handler that knows its event name
        self.bpf["scheduler_core_events"].open_perf_buffer(
                self._scheduler_core_event_handler,
                page_cnt=64
            )

    def poll(self):
        # Poll all BPF programs
        self.bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)

    def close(self):
        # Clean up all BPF programs
        self.bpf.cleanup()

    def data(self) -> list[CollectionTable]:
        if not self.scheduler_core_data:
            return []

        # Convert the dataclass objects to dictionaries and then to DataFrame
        data_dicts = []
        for data in self.scheduler_core_data:
            data_dicts.append({
                "cpu": data.cpu,
                "pid": data.pid,
                "tgid": data.tgid,
                "ts_uptime_us": data.ts_uptime_us,  # Use the correct column name
                "comm": data.comm,
                "flags": data.flags,
                "mode": data.mode,
                "event_name": data.event_name,
            })

        df = pl.DataFrame(data_dicts)

        return [
            SchedulerCoreTable.from_df_id(
                df,
                collection_id=self.collection_id,
            ),
        ]

    def clear(self):
        self.scheduler_core_data.clear()

    def pop_data(self) -> list[CollectionTable]:
        scheduler_core_tables = self.data()
        self.clear()
        return scheduler_core_tables

    def _scheduler_core_event_handler(self, cpu, data, size):
        event = self.bpf["scheduler_core_events"].event(data)

        # Get the event name from the kernel context
        # This requires modifying the BPF C code to include event_type in the data
        event_name = event.event_name.decode('utf-8', errors='replace') if hasattr(event, 'event_name') else "unknown"

        print(f"[DEBUG] Scheduler core event '{event_name}' received on CPU {cpu}")

        try:
            core_data = SchedulerCoreData(
                cpu=cpu,
                pid=event.pid,
                tgid=event.tgid,
                ts_uptime_us=event.ts_uptime_us,
                comm=event.comm.decode('utf-8', errors='replace'),
                flags=event.flags,
                mode=event.mode,
                event_name=EVENT_NAMES.get(event.event_type, "unknown"),
            )
            self.scheduler_core_data.append(core_data)
        except Exception as e:
            print(f"[ERROR] Scheduler event handler failed: {e}")
