#!/usr/bin/env python3
"""Build the committed corpus for scripts/cve_matching_accuracy.py.

Pulls real advisories from api.osv.dev and keeps only those that state their
affected releases twice — once as ``ranges`` and once as an explicit
``versions`` list. That overlap is what makes the corpus self-labelling.

The result is committed so the accuracy gate is deterministic and runs offline;
regenerate deliberately, and review the diff, because changing the corpus
changes the meaning of the score.

Run: python scripts/build_cve_accuracy_corpus.py [--packages pkgs.json]
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "cve_accuracy_corpus.json"
OSV_QUERY = "https://api.osv.dev/v1/query"

# Ecosystem spread matters more than volume: a corpus of only PyPI would hide a
# semver or distro-ordering defect. These are high-advisory-count packages with
# long release histories, so their ranges exercise multi-window shapes.
DEFAULT_PACKAGES: list[tuple[str, str]] = [
    ("PyPI", "django"),
    ("PyPI", "flask"),
    ("PyPI", "requests"),
    ("PyPI", "pillow"),
    ("PyPI", "cryptography"),
    ("npm", "next"),
    ("npm", "lodash"),
    ("npm", "axios"),
    ("npm", "express"),
    ("Go", "github.com/gogo/protobuf"),
    ("Maven", "org.springframework:spring-web"),
    ("RubyGems", "rails"),
    ("crates.io", "openssl"),
    ("Packagist", "symfony/http-kernel"),
]


def _query(ecosystem: str, name: str) -> list[dict]:
    body = json.dumps({"package": {"ecosystem": ecosystem, "name": name}}).encode()
    request = urllib.request.Request(  # noqa: S310  # nosec B310 - fixed https host
        OSV_QUERY, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310  # nosec B310
            return json.loads(response.read()).get("vulns", []) or []
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        print(f"  ! {ecosystem}:{name} query failed: {exc}", file=sys.stderr)
        return []


def _is_self_labelling(vuln: dict) -> bool:
    """True when at least one affected block declares both ranges and versions."""
    for block in vuln.get("affected") or []:
        if block.get("ranges") and block.get("versions"):
            return True
    return False


def _multi_window(vuln: dict) -> bool:
    """True when a range carries more than one ``introduced`` event.

    This is the shape that broke twice: per-branch fixes encoded as alternating
    introduced/fixed events inside ONE range. Single-window advisories dominate
    upstream, so a corpus built by taking whatever arrives first is almost all
    single-window and cannot detect a collapse bug at all — verified by mutation
    against a first-12-per-package corpus, where reintroducing the bug did not
    move the score. Selection therefore prefers this shape deliberately.
    """
    for block in vuln.get("affected") or []:
        for rng in block.get("ranges") or []:
            if sum(1 for event in rng.get("events") or [] if "introduced" in event) > 1:
                return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limit-per-package", type=int, default=12)
    args = parser.parse_args()

    entries: list[dict] = []
    seen: set[str] = set()
    for ecosystem, name in DEFAULT_PACKAGES:
        vulns = _query(ecosystem, name)
        # Multi-window advisories first so the corpus covers the failure mode
        # rather than whatever upstream happened to return earliest.
        vulns.sort(key=lambda v: (not _multi_window(v), str(v.get("id"))))
        kept = 0
        for vuln in vulns:
            if kept >= args.limit_per_package:
                break
            vuln_id = vuln.get("id")
            if not vuln_id or vuln_id in seen or not _is_self_labelling(vuln):
                continue
            seen.add(vuln_id)
            # Keep only the fields the matcher reads, so the corpus stays small
            # and reviewable rather than a dump of full advisory records.
            entries.append(
                {
                    "advisory": {
                        "id": vuln_id,
                        "affected": [
                            {
                                "package": block.get("package", {}),
                                "ranges": block.get("ranges", []),
                                "versions": block.get("versions", []),
                            }
                            for block in vuln.get("affected", [])
                            if block.get("ranges") and block.get("versions")
                        ],
                    }
                }
            )
            kept += 1
        print(f"  {ecosystem}:{name} -> {kept} self-labelling advisories")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps({"source": "api.osv.dev", "entries": sorted(entries, key=lambda e: e["advisory"]["id"])}, indent=1) + "\n",
        encoding="utf-8",
    )
    multi = sum(1 for e in entries if _multi_window(e["advisory"]))
    print(f"wrote {len(entries)} advisories to {OUT.relative_to(ROOT)} ({multi} multi-window)")
    if not multi:
        print("  ! no multi-window advisories captured; the corpus cannot detect a window-collapse bug", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
