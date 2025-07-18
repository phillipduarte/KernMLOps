import polars as pl
from data_schema.schema import (
    CollectionGraph,
    CollectionTable,
)


class CompoundTable(CollectionTable):

    @classmethod
    def name(cls) -> str:
        return "compound"

    @classmethod
    def schema(cls) -> pl.Schema:
        return pl.Schema({
            "timestamp": pl.Int64(),
            "function": pl.String(),
            "stack_hash": pl.Int64(),
            "collection_id": pl.String(),
        })

    @classmethod
    def from_df(cls, table: pl.DataFrame) -> "CompoundTable":
        return CompoundTable(table=table.cast(cls.schema(), strict=True))

    def __init__(self, table: pl.DataFrame):
        self._table = table

    @property
    def table(self) -> pl.DataFrame:
        return self._table

    def filtered_table(self) -> pl.DataFrame:
        return self.table

    def graphs(self) -> list[type[CollectionGraph]]:
        return []

    def stack_analysis(self) -> pl.DataFrame:
        """Returns unique stack traces and their frequencies."""
        return self.table.group_by("stack_hash").agg(
            pl.count().alias("frequency"),
            pl.first("function").alias("function")
        ).sort("frequency", descending=True)
