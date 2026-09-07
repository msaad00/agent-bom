#!/usr/bin/env bash
# Record selected sections of real CLI output; never substitute fixture text.
set -euo pipefail
export TERM=xterm-256color
unset NO_COLOR
export COLUMNS=110
export FORCE_COLOR=1
export AGENT_BOM_LOG_LEVEL=error
report="$(mktemp)"
trap 'rm -f "$report"' EXIT
status=0
agent-bom scan --demo --offline -f console >"$report" 2>&1 || status=$?
if [[ "$status" -ne 1 ]]; then
  cat "$report" >&2
  printf 'Expected the synthetic demo security verdict 1, received %s\n' "$status" >&2
  exit 2
fi
python - "$report" <<'PY'
import os
import re
import sys
import time
from pathlib import Path

lines = Path(sys.argv[1]).read_text().splitlines()
plain = [re.sub(r"\x1b\[[0-9;]*m", "", line) for line in lines]
scenes = [
    ("Inventory and posture", "Summary", "ANALYZE | Top Findings"),
    ("Prioritized findings", "ANALYZE | Top Findings", "ANALYZE | Critical Details"),
    ("Remediation guidance", "PROTECT | Fix First", "GOVERN | Compliance"),
]
pages = []
for title, start, stop in scenes:
    try:
        begin = next(i for i, line in enumerate(plain) if start in line)
        end = next(i for i, line in enumerate(plain[begin + 1:], begin + 1) if stop in line)
    except StopIteration:
        raise SystemExit(f"Missing required CLI section: {start} -> {stop}") from None
    excerpt = lines[begin:end]
    while excerpt and not re.sub(r"\x1b\[[0-9;]*m", "", excerpt[-1]).strip():
        excerpt.pop()
    clipped = len(excerpt) > 24
    if clipped:
        # End on a complete paragraph, never midway through an action or table row.
        boundaries = [i for i, line in enumerate(excerpt[:24]) if not line.strip()]
        if not boundaries:
            raise SystemExit(f"CLI section exceeds the recording viewport: {start}")
        excerpt = excerpt[:boundaries[-1]]
    if len(excerpt) < 2:
        raise SystemExit(f"Empty required CLI section: {start}")
    pages.append((title, excerpt, clipped))
if os.environ.get("AGENT_BOM_DEMO_CHECK_ONLY") == "1":
    raise SystemExit(0)
for title, excerpt, clipped in pages:
    print("\033[H\033[2J", end="")
    print(f"\033[1;36m{title}\033[0m  ·  recorded CLI excerpt")
    print("$ agent-bom scan --demo --offline -f console\n")
    print("\n".join(excerpt))
    if clipped:
        print("\033[2m… additional output omitted from this excerpt\033[0m")
    print("\n\033[2mBundled synthetic sample · security-gate exit 1 · no fix executed\033[0m", flush=True)
    time.sleep(7)
if status_file := os.environ.get("AGENT_BOM_DEMO_STATUS_FILE"):
    Path(status_file).write_text("complete\n")
PY
