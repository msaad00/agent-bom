#!/bin/bash -eu
# ClusterFuzzLite build script for agent-bom.
#
# Installs atheris and agent-bom, then copies fuzz targets to $OUT.
# Runs inside the ClusterFuzzLite Docker container (Ubuntu + Python 3.11+).

python3 -m pip install --upgrade pip atheris
python3 -m pip install --no-deps .
python3 -m pip install pyyaml  # needed by policy.py for YAML policy files

for fuzzer in fuzz/fuzz_*.py; do
  name=$(basename "$fuzzer" .py)
  cp "$fuzzer" "$OUT/$name"
  chmod +x "$OUT/$name"
done
