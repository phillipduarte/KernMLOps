from dataclasses import dataclass
from pathlib import Path

import polars as pl
from bcc import BPF
from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable, SchedulerCoreTable


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
            "schedule+0x0",
            "schedule+0xf62",
            "schedule+0x5cf",
            # Add more events as needed
        ]

        # Create a version of the BPF program for each event
        for event in kernel_events:
            event_bpf = self.bpf_text.replace('USER_EVENT_NAME', f'"{event}"')
            event_bpf_program = BPF(text=event_bpf)

            # Store the BPF program in a dictionary
            if not hasattr(self, 'bpf_programs'):
                self.bpf_programs = {}
            self.bpf_programs[event] = event_bpf_program

            # Attach the kprobe
            event_bytes = event.encode()
            self.bpf_programs[event].attach_kprobe(
                event=event_bytes,
                fn_name=b"trace_syscall"
            )

            # Set up the perf buffer with a handler that knows its event name
            self.bpf_programs[event]["scheduler_core_events"].open_perf_buffer(
                self.create_event_handler(event),
                page_cnt=64
            )

        # Keep a reference to the primary BPF program for the regular methods
        self.bpf = next(iter(self.bpf_programs.values()))

    def poll(self):
        # Poll all BPF programs
        for event, program in self.bpf_programs.items():
            program.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)

    def close(self):
        # Clean up all BPF programs
        for event, program in self.bpf_programs.items():
            program.cleanup()

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
                event_name=event_name
            )
            self.scheduler_core_data.append(core_data)
        except Exception as e:
            print(f"[ERROR] Scheduler event handler failed: {e}")

    def create_event_handler(self, event_name):
        """Creates a handler function specific to a particular event"""
        def handler(cpu, data, size):
            try:
                event = self.bpf_programs[event_name]["scheduler_core_events"].event(data)
                print(f"[DEBUG] {event_name} event received on CPU {cpu}")

                core_data = SchedulerCoreData(
                    cpu=cpu,
                    pid=event.pid,
                    tgid=event.tgid,
                    ts_uptime_us=event.ts_uptime_us,
                    comm=event.comm.decode('utf-8', errors='replace'),
                    flags=event.flags,
                    mode=event.mode,
                    event_name=event_name  # Set the event name here in Python
                )
                self.scheduler_core_data.append(core_data)
            except Exception as e:
                print(f"[ERROR] {event_name} handler failed: {e}")

        return handler
