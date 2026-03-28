#!/bin/bash -eu
# ClusterFuzzLite build script for agent-bom.
#
# Installs atheris and agent-bom, then copies fuzz targets to $OUT.
# Runs inside the ClusterFuzzLite Docker container (Ubuntu + Python 3.11+).

# Step 1: Pin pip + pyyaml with hash verification
python3 -m pip install --require-hashes -r "$SRC/agent-bom/.clusterfuzzlite/requirements.txt"
# Step 2: Install agent-bom with deps (local build — cannot hash-pin)
python3 -m pip install .

for fuzzer in $SRC/agent-bom/fuzz/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
done
