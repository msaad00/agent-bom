#!/usr/bin/env python3
"""Cloud-SDK pin-drift gate + reference refresher (issue #3835).

Two jobs, one deterministic surface:

* **check (default, offline)** — assert the cloud-provider anchor SDK floors
  pinned in ``pyproject.toml`` are in lockstep with the dated in-repo reference
  (``src/agent_bom/data/cloud_sdk_reference.json``). Exits non-zero when a pin
  has fallen **below** the reference floor, an anchor is missing from either
  side, or a floor is unparseable — i.e. the pins and the dated reference have
  silently drifted apart. This is the CI backstop behind Dependabot's
  ``cloud-and-ai-sdks`` group: Dependabot opens the bump PRs; this gate makes a
  quietly-rotted pin fail loudly. It also prints the **non-blocking** ecosystem
  drift ("floor N months / releases behind known-latest as of <date>").

* **refresh (``--refresh``, online)** — re-query the official PyPI JSON API for
  each anchor, restamp ``known_latest`` / release dates / the retrieval date,
  and rewrite the reference. This is the maintainer/auto-bump helper that keeps
  the dated reference — and therefore the freshness signal — moving. Network is
  used ONLY in this mode; the default check is fully offline and air-gap safe.

Honesty (§7): the check never claims a pin is "current" without the dated
reference, and ``--refresh`` records the retrieval date + official source so the
provenance is always explicit.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Import agent_bom without requiring an install (mirrors check_surface_freshness).
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.cloud_sdk_freshness import (  # noqa: E402
    RECOMMENDED_FLOORS,
    REFERENCE_PATH,
    cloud_sdk_pin_drift,
    evaluate_pin_reference_gate,
    load_sdk_reference,
    pyproject_sdk_floors,
)

PYPI_JSON = "https://pypi.org/pypi/{distribution}/json"


def _check(reference_path: Path, pyproject_path: Path, as_json: bool) -> int:
    reference = load_sdk_reference(reference_path)
    floors = pyproject_sdk_floors(pyproject_path)
    gate = evaluate_pin_reference_gate(pyproject_floors=floors, reference=reference)
    drift = cloud_sdk_pin_drift(reference=reference)

    if as_json:
        print(json.dumps({"gate": gate, "drift": drift}, indent=2))
    else:
        checked_on = drift["last_checked"] or "never"
        print(f"Cloud-SDK pin-drift check — reference last checked: {checked_on}")
        print(f"  anchors checked: {gate['checked']}")
        # Non-blocking ecosystem drift (informational).
        for sdk in drift["sdks"]:
            print(f"  [drift/{sdk['status']}] {sdk['message']}")
        # Blocking gate.
        if gate["ok"]:
            print("  [gate] OK — pins and dated reference are in lockstep.")
        else:
            print("  [gate] FAIL — pins drifted from the dated reference:")
            for v in gate["violations"]:
                print(f"    - {v['code']}: {v['message']}")

    return 0 if gate["ok"] else 1


def _refresh(reference_path: Path) -> int:
    reference = load_sdk_reference(reference_path)
    existing = {s.get("distribution"): dict(s) for s in reference.get("sdks", [])}
    today = date.today().isoformat()

    sdks: list[dict[str, object]] = []
    for anchor in RECOMMENDED_FLOORS:
        prior = existing.get(anchor.distribution, {})
        entry: dict[str, object] = {
            "provider": anchor.provider,
            "distribution": anchor.distribution,
            "floor": anchor.floor,
            "floor_released": prior.get("floor_released", ""),
            "known_latest": prior.get("known_latest", ""),
            "latest_released": prior.get("latest_released", ""),
        }
        try:
            url = PYPI_JSON.format(distribution=anchor.distribution)
            with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - official PyPI only
                data = json.load(resp)
            latest = data["info"]["version"]
            files = data["releases"].get(latest, [])
            latest_dt = min(
                (f["upload_time_iso_8601"] for f in files if f.get("upload_time_iso_8601")),
                default="",
            )
            entry["known_latest"] = latest
            entry["latest_released"] = latest_dt[:10]
            entry["floor_released"] = _floor_release_date(data, anchor.floor) or entry["floor_released"]
        except Exception as exc:  # noqa: BLE001 - surface, keep prior value
            print(f"  ! could not refresh {anchor.distribution}: {exc}", file=sys.stderr)
        sdks.append(entry)

    out = {
        "schema_version": reference.get("schema_version", 1),
        "description": reference.get("description", ""),
        "retrieved": today,
        "source": PYPI_JSON,
        "sdks": sdks,
    }
    reference_path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"Refreshed {reference_path} (retrieved {today}) from {PYPI_JSON}.")
    return 0


def _floor_release_date(pypi_json: dict, floor: str) -> str | None:
    """Earliest upload date among releases on the same major.minor as ``floor``."""
    from packaging.version import InvalidVersion, Version

    try:
        fv = Version(floor)
    except InvalidVersion:
        return None
    dates: list[str] = []
    for ver, files in pypi_json.get("releases", {}).items():
        try:
            v = Version(ver)
        except InvalidVersion:
            continue
        if (v.release + (0, 0))[:2] == (fv.release + (0, 0))[:2] and files:
            dts = [f["upload_time_iso_8601"] for f in files if f.get("upload_time_iso_8601")]
            if dts:
                dates.append(min(dts))
    return min(dates)[:10] if dates else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, default=REFERENCE_PATH, help="reference JSON path")
    parser.add_argument("--pyproject", type=Path, default=ROOT / "pyproject.toml", help="pyproject.toml path")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="query the official PyPI JSON API and rewrite the dated reference (network)",
    )
    args = parser.parse_args(argv)

    if args.refresh:
        return _refresh(args.reference)
    return _check(args.reference, args.pyproject, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
