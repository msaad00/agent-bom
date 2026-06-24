"""The cloud-inventory CLI summary counts every asset collection (no hardcoded drift)."""

from __future__ import annotations

from agent_bom.cli._cloud_group import _asset_summary


def test_summary_counts_all_new_collections() -> None:
    report = {
        "provider": "aws",
        "status": "ok",
        "vpcs": [{"name": "v1"}],
        "rds_instances": [{"name": "db"}, {"name": "db2"}],
        "cloudfront_distributions": [{"name": "cf"}],
        "buckets": [],  # empty → omitted
        "warnings": ["w1", "w2"],  # metadata → never counted
        "discovery_envelope": None,
    }
    out = _asset_summary(report)
    assert "vpcs=1" in out
    assert "rds_instances=2" in out
    assert "cloudfront_distributions=1" in out
    assert "buckets" not in out
    assert "warnings" not in out  # metadata excluded


def test_empty_report_says_none() -> None:
    assert _asset_summary({"provider": "aws", "status": "ok", "warnings": []}) == "[dim]none[/dim]"
