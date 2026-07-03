#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_GIF="${AGENT_BOM_DEMO_GIF:-$ROOT_DIR/docs/images/demo-latest.gif}"
TRIM_FRAMES="${AGENT_BOM_DEMO_TRIM_FRAMES:-12}"
FRAME_STEP="${AGENT_BOM_DEMO_FRAME_STEP:-2}"
GIF_COLORS="${AGENT_BOM_DEMO_GIF_COLORS:-48}"
GIF_LOSSY="${AGENT_BOM_DEMO_GIF_LOSSY:-140}"

cd "$ROOT_DIR"

vhs docs/demo.tape

uv run --with pillow python - "$OUTPUT_GIF" "$TRIM_FRAMES" "$FRAME_STEP" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image

gif_path = Path(sys.argv[1])
trim_frames = int(sys.argv[2])
frame_step = max(1, int(sys.argv[3]))

source = Image.open(gif_path)
frame_count = getattr(source, "n_frames", 1)
if trim_frames <= 0 or trim_frames >= frame_count:
    raise SystemExit(f"invalid trim frame count: {trim_frames} for {frame_count} frame GIF")

frames = []
durations = []
for frame_index in range(trim_frames, frame_count, frame_step):
    source.seek(frame_index)
    frames.append(source.convert("P", palette=Image.ADAPTIVE))
    base_duration = source.info.get("duration", 40)
    durations.append(base_duration * frame_step)

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

if command -v gifsicle >/dev/null 2>&1; then
  tmp_gif="${OUTPUT_GIF}.tmp"
  gifsicle -O3 --lossy="$GIF_LOSSY" --colors "$GIF_COLORS" "$OUTPUT_GIF" -o "$tmp_gif"
  mv "$tmp_gif" "$OUTPUT_GIF"
fi
