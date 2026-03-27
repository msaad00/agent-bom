#!/bin/bash -eu
# ClusterFuzzLite build script for agent-bom.
#
# Installs atheris and agent-bom, then copies fuzz targets to $OUT.
# Runs inside the ClusterFuzzLite Docker container (Ubuntu + Python 3.11+).

python3 -m pip install "pip==26.0.1" "pyyaml==6.0.3"  # pinned — update periodically
python3 -m pip install .

for fuzzer in $SRC/agent-bom/fuzz/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
