from __future__ import annotations

import json


def test_model_advisory_feed_posture_reports_bundled_entries() -> None:
    from agent_bom.model_advisories import feed_posture, load_model_advisory_feed

    feed = load_model_advisory_feed()
    posture = feed_posture(feed)

    assert posture["schema_version"] == 1
    assert posture["status"] == "available"
    assert posture["entry_count"] >= 1
    assert posture["freshness"] == "bundled"


def test_model_advisory_matching_uses_model_card_tags_without_cve_overlap() -> None:
    from agent_bom.model_advisories import match_model_advisories, model_advisories_to_dict

    advisories = match_model_advisories(
        "org/custom-model",
        registry="huggingface",
        tags=["custom_code", "text-generation"],
        card_data={"license": "apache-2.0"},
    )
    payload = model_advisories_to_dict(advisories)

    assert payload
    assert payload[0]["advisory_id"].startswith("AGENT-BOM-HF-")
    assert payload[0]["risk_type"] == "remote_code_on_model_load"
    assert "CVE" not in payload[0]["advisory_id"]


def test_external_model_advisory_feed_path(tmp_path, monkeypatch) -> None:
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source": "customer-ai-intel",
                "freshness": "2026-04-25",
                "entries": [
                    {
                        "id": "CUSTOM-MODEL-001",
                        "registry": "huggingface",
                        "model_id_pattern": "acme/*",
                        "risk_type": "revoked_model",
                        "severity": "critical",
                        "confidence": "high",
                        "summary": "Model revoked by internal review.",
                        "evidence_url": "https://example.invalid/advisory",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_BOM_AI_MODEL_ADVISORY_FEED", str(feed_path))

    from agent_bom.model_advisories import load_model_advisory_feed, match_model_advisories

    feed = load_model_advisory_feed()
    advisories = match_model_advisories("acme/model-a", feed=feed)

    assert feed["source"] == "customer-ai-intel"
    assert advisories[0].advisory_id == "CUSTOM-MODEL-001"
    assert advisories[0].risk_type == "revoked_model"
