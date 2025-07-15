import polars as pl
from data_schema.schema import (
    UPTIME_TIMESTAMP,
    CollectionGraph,
    CollectionTable,
)


class SchedulerCoreTable(CollectionTable):

    @classmethod
    def name(cls) -> str:
        return "scheduler_core"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            "cpu": pl.Int64(),
            "pid": pl.Int64(),
            "tgid": pl.Int64(),
            UPTIME_TIMESTAMP: pl.Int64(),
            "comm": pl.String(),
            "flags": pl.Int64(),
            "mode": pl.Int64(),
            "event_name": pl.String(),
            "collection_id": pl.String(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "SchedulerCoreTable":
        return SchedulerCoreTable(table=table.cast(cls.schema(), strict=True))  # pyright: ignore [reportArgumentType]

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self.table

    def graphs(self) -> list[type[CollectionGraph]]:
        return []  # Add graph types here if needed

    def total_events(self) -> int:
        """Returns the total number of scheduler events captured."""
        return len(self.table)

    def events_by_type(self) -> pl.DataFrame:
        """Returns count of events grouped by event_name."""
        return self.table.group_by("event_name").agg(
            pl.count().alias("count")
        ).sort("count", descending=True)

    def events_by_process(self) -> pl.DataFrame:
        """Returns count of events grouped by process."""
        return self.table.group_by(["comm", "pid"]).agg(
            pl.count().alias("count")
        ).sort("count", descending=True)

    def get_events(self, event_name: str) -> pl.DataFrame:
        """Filter events by name."""
        return self.table.filter(pl.col("event_name") == event_name)
