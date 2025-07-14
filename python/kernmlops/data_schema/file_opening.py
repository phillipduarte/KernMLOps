import polars as pl
from data_schema.schema import (
    UPTIME_TIMESTAMP,
    CollectionGraph,
    CollectionTable,
)


class FileOpeningTable(CollectionTable):

    @classmethod
    def name(cls) -> str:
        return "file_opening"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            "cpu": pl.Int64(),
            "pid": pl.Int64(),
            "tgid": pl.Int64(),
            UPTIME_TIMESTAMP: pl.Int64(),
            "filename": pl.String(),
            "flags": pl.Int64(),
            "mode": pl.Int64(),
            "collection_id": pl.String(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "FileOpeningTable":
        return FileOpeningTable(table=table.cast(cls.schema(), strict=True))  # pyright: ignore [reportArgumentType]

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self.table

    def graphs(self) -> list[type[CollectionGraph]]:
        return []

    def total_file_open_attempts(self) -> int:
        """Returns the total number of file open attempts captured."""
        return len(self.filtered_table())

    def get_file_operations(self, filename: str) -> pl.DataFrame:
        """Filter operations for a specific filename."""
        return self.filtered_table().filter(pl.col("filename") == filename)

    def get_first_open_attempt_us(self, filename: str) -> int | None:
        """Get the timestamp of the first attempt to open a file."""
        file_data = self.get_file_operations(filename)
        if len(file_data) == 0:
            return None
        return file_data.sort(
            UPTIME_TIMESTAMP, descending=False
        ).head(n=1).select(
            UPTIME_TIMESTAMP
        ).to_series().to_list()[0]

    def get_last_open_attempt_us(self, filename: str) -> int | None:
        """Get the timestamp of the most recent attempt to open a file."""
        file_data = self.get_file_operations(filename)
        if len(file_data) == 0:
            return None
        return file_data.sort(
            UPTIME_TIMESTAMP, descending=True
        ).head(n=1).select(
            UPTIME_TIMESTAMP
        ).to_series().to_list()[0]
