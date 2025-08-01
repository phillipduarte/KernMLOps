from dataclasses import field, make_dataclass
from typing import Mapping

from kernmlops_benchmark.benchmark import (
    Benchmark,
    FauxBenchmark,
    GenericBenchmarkConfig,
)
from kernmlops_benchmark.cloudsuite import WebServingBenchmark
from kernmlops_benchmark.errors import (
    BenchmarkError,
    BenchmarkNotConfiguredError,
    BenchmarkNotRunningError,
    BenchmarkRunningError,
)
from kernmlops_benchmark.fio import FioBenchmark
from kernmlops_benchmark.gap import GapBenchmark
from kernmlops_benchmark.linnos import LinnosBenchmark
from kernmlops_benchmark.linux_build import LinuxBuildBenchmark
from kernmlops_benchmark.memcached import MemcachedBenchmark
from kernmlops_benchmark.mongodb import MongoDbBenchmark
from kernmlops_benchmark.redis import RedisBenchmark
from kernmlops_benchmark.terasort import TeraSortBenchmark
from kernmlops_benchmark.xsbench import XSBenchBenchmark
from kernmlops_config import ConfigBase

benchmarks: Mapping[str, type[Benchmark]] = {
    WebServingBenchmark.name(): WebServingBenchmark,
    FauxBenchmark.name(): FauxBenchmark,
    LinuxBuildBenchmark.name(): LinuxBuildBenchmark,
    GapBenchmark.name(): GapBenchmark,
    MongoDbBenchmark.name(): MongoDbBenchmark,
    FioBenchmark.name(): FioBenchmark,
    XSBenchBenchmark.name(): XSBenchBenchmark,
    LinnosBenchmark.name(): LinnosBenchmark,
    RedisBenchmark.name(): RedisBenchmark,
    MemcachedBenchmark.name(): MemcachedBenchmark,
    TeraSortBenchmark.name(): TeraSortBenchmark
}

BenchmarkConfig = make_dataclass(
    cls_name="BenchmarkConfig",
    bases=(ConfigBase,),
    fields=[
        (
            "generic",
            GenericBenchmarkConfig,
            field(default=GenericBenchmarkConfig()),
        )
    ] + [
        (name, ConfigBase, field(default=benchmark.default_config()))
        for name, benchmark in benchmarks.items()
    ],
    frozen=True,
)


__all__ = [
    "Benchmark",
    "BenchmarkConfig",
    "BenchmarkError",
    "BenchmarkRunningError",
    "BenchmarkNotConfiguredError",
    "BenchmarkNotRunningError",
    "FauxBenchmark",
    "LinnosBenchmark",
    "LinuxBuildBenchmark",
    "GapBenchmark",
    "RedisBenchmark",
    "MongoDbBenchmark",
    "MemcachedBenchmark",
    "benchmarks",
]
