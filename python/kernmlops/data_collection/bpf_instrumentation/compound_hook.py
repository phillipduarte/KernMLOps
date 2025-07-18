from dataclasses import dataclass
from pathlib import Path

import polars as pl
from bcc import BPF
from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable, CompoundTable


@dataclass(frozen=True)
class CompoundData:
    timestamp: int           # ts_uptime_us
    function: str           # function name
    stack_hash: int         # hash of the stack trace


class CompoundBPFHook(BPFProgram):
    @classmethod
    def name(cls) -> str:
        return "compound"

    def __init__(self):
        bpf_text = open(Path(__file__).parent / "bpf/compound.bpf.c", "r").read()

        # Replace the FILTER placeholder with '0' to accept all events
        self.bpf_text = bpf_text.replace('FILTER', '0')
        self.compound_data = list[CompoundData]()

    def load(self, collection_id: str):
        print(f"[DEBUG] Loading compound hook with collection_id {collection_id}")
        self.collection_id = collection_id

        # Define all kernel events we want to monitor
        kernel_events= [
            "pick_next_task",
            "enqueue_task_fair",
            "pick_next_task_fair",
            "check_preempt_wakeup",
            "schedule",
            "vfs_read",
            "filemap_read",
            "ext4_file_read_iter",
            "write_cache_pages",
            "submit_bh_wbc",
            "__alloc_pages",
            "mempool_alloc",
            "swap_readpage",
            "filemap_fault",
            "blk_mq_start_request",
            "blk_mq_dispatch_rq_list",
            "blk_bio_list_merge",
            "nvme_queue_rq",
            "blk_stat_add",
            # Add more events as needed
        ]

        for event in kernel_events:
            event_bpf = self.bpf_text.replace('USER_EVENT_NAME', f'"{event}"')
            event_bpf_program = BPF(text=event_bpf)

            # Store the BPF program in a dictionary
            if not hasattr(self, 'bpf_programs'):
                self.bpf_programs = {}
            self.bpf_programs[event] = event_bpf_program

            just_event_name = event.split('+')[0]
            offset = int(event.split('+')[1], 16) if '+' in event else 0x0

            # Attach the kprobe
            event_bytes = just_event_name.encode()
            self.bpf_programs[event].attach_kprobe(
                event=event_bytes,
                fn_name=b"trace_function_call",
                event_off=offset
            )

            # Set up the perf buffer with a handler that knows its event name
            self.bpf_programs[event]["compound_events"].open_perf_buffer(
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
        if not self.compound_data:
            return []

        # Convert the dataclass objects to dictionaries
        data_dicts = []
        for data in self.compound_data:
            data_dicts.append({
                "timestamp": data.timestamp,
                "function": data.function,
                "stack_hash": data.stack_hash,
            })

        df = pl.DataFrame(data_dicts)

        return [
            CompoundTable.from_df_id(
                df,
                collection_id=self.collection_id,
            ),
        ]

    def clear(self):
        self.compound_data.clear()

    def pop_data(self) -> list[CollectionTable]:
        compound_tables = self.data()
        self.clear()
        return compound_tables

    def _compound_event_handler(self, cpu, data, size):
        event = self.bpf["compound_events"].event(data)

        print(f"[DEBUG] Compound event received on CPU {cpu}")
        event_name = event.event_name.decode('utf-8', errors='replace') if hasattr(event, 'event_name') else "unknown"

        try:
            # Use the event name as function name for now
            function_name = event_name

            compound_data = CompoundData(
                timestamp=event.timestamp,
                function=function_name,
                stack_hash=event.stack_hash,
            )
            self.compound_data.append(compound_data)
        except Exception as e:
            print(f"[ERROR] Compound event handler failed: {e}")

    def create_event_handler(self, event_name):
        """Creates a handler function specific to a particular event"""
        def handler(cpu, data, size):
            try:
                event = self.bpf_programs[event_name]["compound_events"].event(data)
                print(f"[DEBUG] {event_name} event received on CPU {cpu}")

                # Use event name as function name
                function_name = event_name

                compound_data = CompoundData(
                    timestamp=event.timestamp,
                    function=function_name,
                    stack_hash=event.stack_hash,
                )
                self.compound_data.append(compound_data)
            except Exception as e:
                print(f"[ERROR] {event_name} handler failed: {e}")

        return handler
