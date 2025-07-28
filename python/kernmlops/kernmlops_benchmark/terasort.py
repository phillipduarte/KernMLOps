import os
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import cast

from data_schema import GraphEngine
from kernmlops_benchmark.benchmark import Benchmark, GenericBenchmarkConfig
from kernmlops_benchmark.errors import (
    BenchmarkNotInCollectionData,
    BenchmarkNotRunningError,
    BenchmarkRunningError,
)
from kernmlops_config import ConfigBase
from pytimeparse.timeparse import timeparse


@dataclass(frozen=True)
class TeraSortConfig(ConfigBase):
    hadoop_version: str = "3.2.4"
    num_records: int = 1000000
    input_dir: str = "terasort-input"
    output_dir: str = "terasort-output"
    sleep: str | None = None

class TeraSortBenchmark(Benchmark):
    @classmethod
    def name(cls) -> str:
        return "terasort"

    @classmethod
    def default_config(cls) -> ConfigBase:
        return TeraSortConfig()

    @classmethod
    def from_config(cls, config: ConfigBase) -> "Benchmark":
        generic = cast(GenericBenchmarkConfig, getattr(config, "generic"))
        spec    = cast(TeraSortConfig, getattr(config, cls.name()))
        return TeraSortBenchmark(generic_config=generic, config=spec)

    def __init__(self, *, generic_config: GenericBenchmarkConfig, config: TeraSortConfig):
        self.generic_config = generic_config
        self.config         = config
        # Hadoop is installed under BENCHMARK_DIR/terasort/hadoop-<version>
        self.benchmark_dir  = self.generic_config.get_benchmark_dir() / "terasort"
        self.process: subprocess.Popen | None = None

    def is_configured(self) -> bool:
        return (self.benchmark_dir / f"hadoop-{self.config.hadoop_version}").is_dir()

    def setup(self) -> None:
        if self.process is not None:
            raise BenchmarkRunningError()
        self.generic_config.generic_setup()

    def run(self) -> None:
        if self.process is not None:
            raise BenchmarkRunningError()
        hdir = self.benchmark_dir / f"hadoop-{self.config.hadoop_version}"
        jar  = hdir / "share" / "hadoop" / "mapreduce" / f"hadoop-mapreduce-examples-{self.config.hadoop_version}.jar"
        env  = os.environ.copy()
        env["HADOOP_HOME"] = str(hdir)
        env["PATH"]        = f"{hdir}/bin:" + env.get("PATH", "")
        # optional warm-up
        if self.config.sleep:
            time.sleep(timeparse(self.config.sleep))
        # teragen → terasort
        cmds = [
            ["hadoop", "jar", str(jar), "teragen", str(self.config.num_records), self.config.input_dir],
            ["hadoop", "jar", str(jar), "terasort", self.config.input_dir, self.config.output_dir],
        ]
        # run teragen synchronously, then start terasort
        subprocess.run(cmds[0], env=env, check=True)
        self.process = subprocess.Popen(cmds[1], env=env)

    def poll(self) -> int | None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        return self.process.poll()

    def wait(self) -> None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        self.process.wait()

    def kill(self) -> None:
        if self.process is None:
            raise BenchmarkNotRunningError()
        self.process.send_signal(signal.SIGINT)
        self.process.wait()

    @classmethod
    def plot_events(cls, graph_engine: GraphEngine) -> None:
        if graph_engine.collection_data.benchmark != cls.name():
            raise BenchmarkNotInCollectionData()
        # no special events
        pass
