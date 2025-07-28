#!/usr/bin/env bash
set -e

HADOOP_VERSION="3.2.4"
BENCH_DIR="${BENCHMARK_DIR:-$HOME/kernmlops-benchmark}"
TS_DIR="$BENCH_DIR/terasort"

if [ -d "$TS_DIR/hadoop-$HADOOP_VERSION" ]; then
    echo "Hadoop $HADOOP_VERSION already installed at $TS_DIR/hadoop-$HADOOP_VERSION"
    exit 0
fi

echo "Installing Hadoop $HADOOP_VERSION into $TS_DIR..."
mkdir -p "$TS_DIR"
pushd "$TS_DIR" >/dev/null

# download & unpack
wget -q "https://downloads.apache.org/hadoop/common/hadoop-$HADOOP_VERSION/hadoop-$HADOOP_VERSION.tar.gz"
tar -xzf "hadoop-$HADOOP_VERSION.tar.gz"
rm "hadoop-$HADOOP_VERSION.tar.gz"

popd >/dev/null
echo "Hadoop $HADOOP_VERSION installation complete."
