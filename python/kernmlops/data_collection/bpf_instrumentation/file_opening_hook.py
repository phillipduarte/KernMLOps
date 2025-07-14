from dataclasses import dataclass
from pathlib import Path

import polars as pl
from bcc import BPF
from data_collection.bpf_instrumentation.bpf_hook import POLL_TIMEOUT_MS, BPFProgram
from data_schema import CollectionTable, FileOpeningTable


@dataclass(frozen=True)
class FileOpeningData:
    cpu: int
    pid: int
    tgid: int
    ts_uptime_us: int
    filename: str
    flags: int
    mode: int


class FileOpeningBPFHook(BPFProgram):
    @classmethod
    def name(cls) -> str:
        return "file_opening"

    def __init__(self):
        bpf_text = open(Path(__file__).parent / "bpf/file_opening.bpf.c", "r").read()

        # Replace the FILTER placeholder with '0' to accept all events
        self.bpf_text = bpf_text.replace('FILTER', '0')
        self.file_opening_data = list[FileOpeningData]()

    def load(self, collection_id: str):
        print(f"[DEBUG] Loading file_opening hook with collection_id {collection_id}")
        self.collection_id = collection_id
        self.bpf = BPF(text=self.bpf_text)

        # Attach to the openat syscall
        self.bpf.attach_kprobe(event=b"__x64_sys_openat", fn_name=b"trace_sys_openat")

        # Open perf buffer to receive events
        self.bpf["file_opening_events"].open_perf_buffer(
            self._file_opening_event_handler, page_cnt=64
        )

    def poll(self):
        self.bpf.perf_buffer_poll(timeout=POLL_TIMEOUT_MS)

    def close(self):
        self.bpf.cleanup()

    def data(self) -> list[CollectionTable]:
        if not self.file_opening_data:
            return []

        # Convert the dataclass objects to dictionaries and then to DataFrame
        data_dicts = []
        for data in self.file_opening_data:
            data_dicts.append({
                "cpu": data.cpu,
                "pid": data.pid,
                "tgid": data.tgid,
                "ts_uptime_us": data.ts_uptime_us,  # Use the correct column name
                "filename": data.filename,
                "flags": data.flags,
                "mode": data.mode,
            })

        df = pl.DataFrame(data_dicts)

        return [
            FileOpeningTable.from_df_id(
                df,
                collection_id=self.collection_id,
            ),
        ]

    def clear(self):
        self.file_opening_data.clear()

    def pop_data(self) -> list[CollectionTable]:
        file_tables = self.data()
        self.clear()
        return file_tables

    def _file_opening_event_handler(self, cpu, file_opening_perf_event, size):
        print(f"[DEBUG] File opening event received on CPU {cpu}")
        event = self.bpf["file_opening_events"].event(file_opening_perf_event)
        try:
            data = FileOpeningData(
                cpu=cpu,
                pid=event.pid,
                tgid=event.tgid,
                ts_uptime_us=event.ts_uptime_us,
                filename=event.filename.decode('utf-8', errors='replace'),
                flags=event.flags,
                mode=event.mode,
            )
            self.file_opening_data.append(data)
        except Exception as e:
            print(f"[ERROR] File opening event handler failed: {e}")
            pass
