#!/usr/bin/env python3
"""Anchor installed-package SARIF to a generated evidence artifact for GitHub.

GitHub requires a physical location. The JSONL file records the original finding;
its location is scan evidence, never a fabricated source manifest. Keep both the
unmodified SARIF and this artifact with the upload. The vulnerability gate must
run on the original findings before this presentation-only transformation.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path, PurePosixPath
from urllib.parse import quote


def prepare(document: dict, evidence_uri: str) -> tuple[dict, str]:
    path = PurePosixPath(evidence_uri)
    if not evidence_uri or path.is_absolute() or ".." in path.parts or ":" in evidence_uri or "\\" in evidence_uri:
        raise ValueError("Evidence must be a checkout-relative artifact")
    output = copy.deepcopy(document)
    records: list[str] = []
    for run in output.get("runs", []):
        for result in run.get("results", []):
            locations = result.get("locations", [])
            if len(locations) != 1 or "physicalLocation" in locations[0]:
                continue
            logical = locations[0].get("logicalLocations", [])
            if not any(str(item.get("fullyQualifiedName", "")).startswith("self-scan://") for item in logical):
                continue
            fingerprint = result.get("fingerprints", {}).get("agent-bom/v1")
            if not isinstance(fingerprint, str) or not fingerprint:
                raise ValueError("Self-scan finding is missing its stable fingerprint")
            records.append(json.dumps({"schema_version": "agent-bom.self-scan-evidence/v1", "finding": result}, sort_keys=True))
            locations[0]["physicalLocation"] = {
                "artifactLocation": {"uri": quote(evidence_uri, safe="/"), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": len(records)},
            }
            locations[0]["message"] = {"text": "Generated installed-package scan evidence; not a source manifest."}
            for related in result.get("relatedLocations", []):
                if "physicalLocation" not in related and related.get("logicalLocations"):
                    related["physicalLocation"] = copy.deepcopy(locations[0]["physicalLocation"])
            result.setdefault("partialFingerprints", {})["primaryLocationLineHash"] = fingerprint
    return output, "".join(record + "\n" for record in records)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence_path = args.evidence.resolve()
    if evidence_path == args.sarif.resolve():
        parser.error("Evidence and SARIF paths must differ")
    evidence_uri = evidence_path.relative_to(Path.cwd().resolve()).as_posix()
    document, records = prepare(json.loads(args.sarif.read_text()), evidence_uri)
    if records:
        args.evidence.write_text(records)
    args.sarif.write_text(json.dumps(document, indent=2) + "\n")


if __name__ == "__main__":
    main()
