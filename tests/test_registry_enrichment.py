from __future__ import annotations

import json
from pathlib import Path

from agent_bom.registry_enrichment import _flag_risks, enrich_registry


def test_flag_risks_marks_stale_unverified_low_adoption():
    flags = _flag_risks(
        {
            "github_last_push": "2020-01-01T00:00:00Z",
            "github_archived": True,
            "smithery_use_count": 4,
            "github_stars": 2,
            "smithery_verified": False,
        }
    )

    assert any(flag.startswith("abandoned (") for flag in flags)
    assert "archived" in flags
    assert "low-adoption" in flags
    assert "unverified" in flags


def test_enrich_registry_merges_existing_entries_and_adds_new_ones(tmp_path: Path, monkeypatch):
    registry_path = tmp_path / "mcp_registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "servers": {
                    "acme/fs-server": {
                        "package": "@acme/fs-server",
                        "name": "FS Server",
                        "category": "official",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("agent_bom.registry_enrichment._REGISTRY_PATH", registry_path)
    monkeypatch.setattr(
        "agent_bom.registry_enrichment._fetch_smithery",
        lambda max_pages=40: {
            "acme/fs-server": {
                "smithery_use_count": 42,
                "smithery_verified": True,
                "smithery_display_name": "Acme FS",
                "smithery_description": "Filesystem MCP",
                "smithery_homepage": "https://acme.example/fs",
            },
            "community/new-server": {
                "smithery_use_count": 3,
                "smithery_verified": False,
                "smithery_display_name": "New Server",
                "smithery_description": "New community MCP",
                "smithery_homepage": "https://community.example/new",
            },
        },
    )
    monkeypatch.setattr(
        "agent_bom.registry_enrichment._fetch_docker_hub",
        lambda max_pages=5: {
            "mcp/fs-server": {
                "docker_pull_count": 1000,
                "docker_last_updated": "2026-04-01T00:00:00Z",
            }
        },
    )
    monkeypatch.setattr(
        "agent_bom.registry_enrichment._fetch_github",
        lambda max_results=1000: {
            "acme/fs-server": {
                "github_stars": 99,
                "github_last_push": "2026-03-31T00:00:00Z",
                "github_archived": False,
            }
        },
    )

    stats = enrich_registry()
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    servers = data["servers"]

    assert stats == {"smithery": 2, "docker": 1, "github": 1, "total": 2, "new": 1}
    assert servers["acme/fs-server"]["smithery_use_count"] == 42
    assert servers["acme/fs-server"]["docker_pull_count"] == 1000
    assert servers["acme/fs-server"]["github_stars"] == 99
    assert servers["acme/fs-server"]["risk_flags"] == []
    assert servers["community/new-server"]["name"] == "New Server"
    assert "low-adoption" in servers["community/new-server"]["risk_flags"]
    assert data["_total_servers"] == 2
    assert data["_enrichment_sources"] == ["smithery", "docker_hub", "github"]
