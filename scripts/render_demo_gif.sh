#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_GIF="${AGENT_BOM_DEMO_GIF:-$ROOT_DIR/docs/images/demo-latest.gif}"
TRIM_FRAMES="${AGENT_BOM_DEMO_TRIM_FRAMES:-1}"
FRAME_STEP="${AGENT_BOM_DEMO_FRAME_STEP:-3}"
GIF_COLORS="${AGENT_BOM_DEMO_GIF_COLORS:-128}"
GIF_LOSSY="${AGENT_BOM_DEMO_GIF_LOSSY:-0}"

cd "$ROOT_DIR"

# Preserve the previous artifact if VHS records a failed scan or incomplete playback.
recording_dir="$(mktemp -d)"
trap 'rm -rf "$recording_dir"' EXIT
export AGENT_BOM_DEMO_STATUS_FILE="$recording_dir/complete"
python - "$ROOT_DIR/docs/demo.tape" "$recording_dir/demo.tape" "$recording_dir/demo.gif" <<'PYTAPE'
import sys
from pathlib import Path
source, tape, output = map(Path, sys.argv[1:])
lines = source.read_text().splitlines()
tape.write_text("\n".join(f'Output "{output}"' if line.startswith("Output ") else line for line in lines) + "\n")
PYTAPE
vhs "$recording_dir/demo.tape"
if [[ ! -f "$AGENT_BOM_DEMO_STATUS_FILE" ]]; then
  printf 'Demo recording failed: CLI playback did not complete. Previous GIF preserved.\n' >&2
  exit 1
fi
recorded_gif="$recording_dir/demo.gif"

python - "$recorded_gif" "$TRIM_FRAMES" "$FRAME_STEP" <<'PY'
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
  tmp_gif="$recording_dir/optimized.gif"
  gifsicle -O3 --lossy="$GIF_LOSSY" --colors "$GIF_COLORS" "$recorded_gif" -o "$tmp_gif"
  mv "$tmp_gif" "$recorded_gif"
fi

mv "$recorded_gif" "$OUTPUT_GIF"
