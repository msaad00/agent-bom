# Terminal Demo Refresh

This document is the refresh contract for the terminal demo GIF.

## What the pipeline does

- `scripts/render_demo.sh` runs the live terminal demo flow used in the recording.
- `scripts/render_demo_gif.sh` renders `docs/demo.tape` with VHS, trims the lead-in frames, and writes `docs/images/demo-latest.gif`.
- `scripts/check_release_consistency.py` verifies the demo tape, GIF reference, and release storefront markers stay aligned.

## Required inputs

- `AGENT_BOM_DEMO_DB_SOURCE`: path to a local `vulns.db` copy
- `AGENT_BOM_DEMO_TAPE`: optional alternate VHS tape path
- `AGENT_BOM_DEMO_GIF`: optional alternate output path
- `AGENT_BOM_DEMO_TRIM_FRAMES`: optional lead-in trim count, defaults to `45`

## Refresh steps

```bash
export AGENT_BOM_DEMO_DB_SOURCE=/path/to/local/vulns.db

scripts/render_demo.sh
scripts/render_demo_gif.sh
python scripts/check_release_consistency.py
```

If you need a different tape or output path, set `AGENT_BOM_DEMO_TAPE` or `AGENT_BOM_DEMO_GIF` before running `scripts/render_demo_gif.sh`.

## Notes

- The tape is intentionally small and deterministic.
- The demo GIF is the source of truth for README and PyPI storefront references.
- Do not hand-edit `docs/images/demo-latest.gif`; regenerate it from the tape.
