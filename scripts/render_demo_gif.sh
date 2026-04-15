#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TAPE_PATH="${AGENT_BOM_DEMO_TAPE:-$ROOT_DIR/docs/demo.tape}"
OUTPUT_GIF="${AGENT_BOM_DEMO_GIF:-$ROOT_DIR/docs/images/demo-latest.gif}"
TRIM_FRAMES="${AGENT_BOM_DEMO_TRIM_FRAMES:-45}"

cd "$ROOT_DIR"

if ! command -v vhs >/dev/null 2>&1; then
  printf 'vhs is required to render the terminal demo GIF\n' >&2
  exit 1
fi

SOURCE_GIF_RELATIVE="$(awk '/^Output[[:space:]]+/ { print $2; exit }' "$TAPE_PATH")"
if [[ -z "$SOURCE_GIF_RELATIVE" ]]; then
  printf 'could not determine demo GIF output from %s\n' "$TAPE_PATH" >&2
  exit 1
fi

SOURCE_GIF="$ROOT_DIR/$SOURCE_GIF_RELATIVE"
mkdir -p "$(dirname "$OUTPUT_GIF")"

vhs "$TAPE_PATH"

if [[ ! -f "$SOURCE_GIF" ]]; then
  printf 'expected demo GIF %s was not generated\n' "$SOURCE_GIF" >&2
  exit 1
fi

python - "$SOURCE_GIF" "$TRIM_FRAMES" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image

gif_path = Path(sys.argv[1])
trim_frames = int(sys.argv[2])

source = Image.open(gif_path)
frame_count = getattr(source, "n_frames", 1)
if trim_frames <= 0 or trim_frames >= frame_count:
    raise SystemExit(f"invalid trim frame count: {trim_frames} for {frame_count} frame GIF")

frames = []
durations = []
for frame_index in range(trim_frames, frame_count):
    source.seek(frame_index)
    frames.append(source.convert("P", palette=Image.ADAPTIVE))
    durations.append(source.info.get("duration", 40))

frames[0].save(
    gif_path,
    save_all=True,
    append_images=frames[1:],
    duration=durations,
    loop=0,
    optimize=False,
    disposal=2,
)
PY

if [[ "$OUTPUT_GIF" != "$SOURCE_GIF" ]]; then
  cp "$SOURCE_GIF" "$OUTPUT_GIF"
fi
