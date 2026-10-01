#!/usr/bin/env python3
"""Read-only, bounded graph integration probe. Retain the private evidence receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import httpx

ENVELOPE = "agent-bom.graph/v1"
EVIDENCE = "agent-bom.graph-evidence/v1"


class ContractError(ValueError):
    """The consumer cannot safely interpret or combine these responses."""


def require(condition, message):
    if not condition:
        raise ContractError(message)


def validate_base_url(value):
    parsed = urlsplit(value)
    require(
        parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}),
        "Use HTTPS, or HTTP only on loopback",
    )
    require(
        bool(parsed.hostname) and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment,
        "The API URL must not contain credentials, a query or a fragment",
    )
    return value.rstrip("/")


def qualify(client, *, scan_id="", page_size=100, max_pages=2):
    """Use only public HTTP shapes; never import server graph models."""
    require(1 <= page_size <= 5000 and 1 <= max_pages <= 100, "Invalid consumer bounds")

    def fetch(path, params=None):
        response = client.get(path, params=params)
        require(response.status_code == 200, f"Graph request failed with HTTP {response.status_code}; restart on 409")
        return response.json()

    schema = fetch("graph/schema")
    require(schema.get("interchange", {}).get("envelope") == ENVELOPE, "Unsupported graph envelope")
    require(schema.get("interchange", {}).get("evidence") == EVIDENCE, "Unsupported evidence contract")
    node_kinds, edge_kinds = set(schema["node_types"]), set(schema["edge_types"])
    params = {"limit": page_size, "scan_id": scan_id}
    identity, pages, nodes, edges = None, [], {}, {}
    has_more = True
    for _ in range(max_pages):
        page = fetch("graph", params)
        scope = tuple(page.get(key) for key in ("tenant_id", "scan_id", "snapshot_generation"))
        require(all(isinstance(value, str) and value for value in scope), "Backend did not return a pinned scope")
        require(identity is None or identity == scope, "Graph scope or revision changed")
        identity = scope
        completeness = page.get("completeness", {})
        require(
            isinstance(completeness, dict)
            and completeness.get("status") in {"complete", "truncated", "sampled"}
            and isinstance(completeness.get("complete"), bool)
            and isinstance(completeness.get("truncated"), bool),
            "Missing graph completeness",
        )
        require(len(page["nodes"]) <= page_size, "Server exceeded the requested node-page bound")
        for node in page["nodes"]:
            require(bool(node.get("id")) and bool(node.get("canonical_id")), "Missing stable node identity")
            require(node["entity_type"] in node_kinds, "Unknown entity kind")
            require(node.get("evidence_provenance", {}).get("schema_version") == EVIDENCE, "Missing versioned node provenance")
            require(node["id"] not in nodes, "Node repeated across pages")
            nodes[node["id"]] = node
        for edge in page["edges"]:
            require(bool(edge.get("id")) and bool(edge.get("canonical_id")), "Missing stable relationship identity")
            require(edge["relationship"] in edge_kinds, "Unknown relationship kind")
            require(edge.get("direction") in {"directed", "bidirectional"}, "Unknown relationship direction")
            require(edge["id"] not in edges or edges[edge["id"]] == edge, "Relationship evidence changed between pages")
            edges[edge["id"]] = edge
        pages.append({"sha256": hashlib.sha256(json.dumps(page, sort_keys=True).encode()).hexdigest(), "response": page})
        paging = page["pagination"]
        has_more = paging["has_more"]
        require(isinstance(has_more, bool), "Missing pagination completion state")
        if not has_more:
            break
        require(bool(page["nodes"]), "Empty page cannot advance")
        params = {"scan_id": scope[1], "snapshot_generation": scope[2], "limit": page_size}
        if paging.get("next_cursor"):
            params["cursor"] = paging["next_cursor"]
        else:
            params["offset"] = paging["offset"] + paging["limit"]
    return {
        "status": "passed",
        "contract": ENVELOPE,
        "scope": dict(zip(("tenant_id", "scan_id", "snapshot_generation"), identity)),
        "nodes": len(nodes),
        "relationships": len(edges),
        "node_pages_exhausted": not has_more,
        "collection_coverage": "unknown",
        "execution": "not_established",
        "pages": pages,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="Control-plane origin, without /v1")
    parser.add_argument("--token-file", required=True, type=Path, help="Viewer API key in a private file")
    parser.add_argument("--scan-id", default="")
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--max-pages", type=int, default=2)
    parser.add_argument("--output", required=True, type=Path, help="New private JSON receipt; existing files are never overwritten")
    args = parser.parse_args()
    url = validate_base_url(args.url)
    token = args.token_file.read_text().strip()
    require(bool(token) and "\n" not in token and "\r" not in token, "Invalid token file")
    with httpx.Client(base_url=url + "/v1/", headers={"Authorization": "Bearer " + token}, timeout=30, follow_redirects=False) as client:
        result = qualify(client, scan_id=args.scan_id, page_size=args.page_size, max_pages=args.max_pages)
    # The receipt contains authorized inventory. Create it privately and never replace an older receipt.
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print(json.dumps({key: value for key, value in result.items() if key not in {"pages", "scope"}}))


if __name__ == "__main__":
    main()
