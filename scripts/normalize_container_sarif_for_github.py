#!/usr/bin/env python3
"""Make container SARIF artifact locations acceptable to GitHub code scanning.

GitHub rejects a SARIF upload when a result URI uses ``docker://`` while the
checked-out source root uses ``file://``. Preserve the scanned image reference
in result properties, but point GitHub at the checked-in Dockerfile for source
rendering and deduplication.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _github_artifact_path(uri: str) -> str:
    return "Dockerfile" if uri.startswith("docker://") else uri


def _normalize_artifact_location(physical: dict[str, Any], result: dict[str, Any]) -> None:
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict):
        return
    uri = artifact.get("uri")
    if not isinstance(uri, str) or not uri.startswith("docker://"):
        return
    properties = result.setdefault("properties", {})
    if isinstance(properties, dict):
        properties.setdefault("agent-bom:container_uri", uri)
    artifact["uri"] = _github_artifact_path(uri)
    artifact["uriBaseId"] = "%SRCROOT%"


def normalize_document(document: dict[str, Any]) -> dict[str, Any]:
    for run in document.get("runs", []):
        if not isinstance(run, dict):
            continue
        run.pop("automationDetails", None)
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            for location in result.get("locations", []):
                if not isinstance(location, dict):
                    continue
                physical = location.get("physicalLocation")
                if not isinstance(physical, dict):
                    continue
                _normalize_artifact_location(physical, result)
            # SARIF 2.1 permits logical-only related locations, but GitHub's
            # ingestion rejects them while building its related-location index.
            # Add checked-in source context without discarding the graph hop.
            for related in result.get("relatedLocations", []):
                if not isinstance(related, dict):
                    continue
                physical = related.get("physicalLocation")
                if not isinstance(physical, dict):
                    related["physicalLocation"] = {"artifactLocation": {"uri": "Dockerfile", "uriBaseId": "%SRCROOT%"}}
                    continue
                _normalize_artifact_location(physical, result)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    document = json.loads(args.path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise SystemExit("SARIF root must be an object")
    normalized = normalize_document(document)
    args.path.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
