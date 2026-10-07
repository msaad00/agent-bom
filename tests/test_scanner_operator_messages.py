"""Operator copy follows measured coverage and supported client paths."""

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.secret_scanner import scan_secrets
from agent_bom.vuln_freshness import VulnDataFreshness


def test_mcp_help_uses_supported_desktop_config_locations():
    output = CliRunner().invoke(main, ["mcp", "server", "--help"]).output
    assert "~/Library/Application Support/Claude/claude_desktop_config.json" in output
    assert "~/.claude/claude_desktop_config.json" not in output


def test_offline_with_no_cache_does_not_claim_a_local_cache():
    message = VulnDataFreshness(mode="offline", record_count=0, last_updated=None, danger=True).summary_line()
    assert "no local cache" in message
    assert "age unknown" not in message


def test_exact_aws_documentation_key_is_not_a_real_credential(tmp_path):
    (tmp_path / "credentials.txt").write_text("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
    assert not any(f.severity == "critical" for f in scan_secrets(tmp_path).findings)
    (tmp_path / "credentials.txt").write_text("aws_access_key_id = " + "AKIA" + "IOSFODNN7EXAMPLZ\n")
    assert any(f.severity == "critical" for f in scan_secrets(tmp_path).findings)


def test_spdx_tag_value_reports_supported_intake_format(tmp_path):
    import pytest

    from agent_bom.parsers.sbom_context import load_sbom_agent
    from agent_bom.sbom import load_sbom

    path = tmp_path / "bom.spdx"
    path.write_text("SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\n")
    for load in (load_sbom, load_sbom_agent):
        with pytest.raises(ValueError, match="SPDX tag-value.*JSON"):
            load(str(path))


def test_missing_amazon_linux_feed_is_not_labeled_end_of_life(tmp_path, monkeypatch):
    import asyncio
    import io

    from rich.console import Console

    from agent_bom.db.schema import init_db
    from agent_bom.models import Package
    from agent_bom.scanners import IncompleteScanError, ScanOptions, scan_packages

    db_path = tmp_path / "vulns.db"
    init_db(db_path).close()
    monkeypatch.setattr("agent_bom.db.schema.DB_PATH", db_path)
    monkeypatch.setattr("agent_bom.db.schema.db_freshness_days", lambda path=None: 0)
    monkeypatch.setattr(
        "agent_bom.coverage.detect_release_coverage_gaps",
        lambda packages: [
            {
                "release": "amazon-linux:2023",
                "package_count": 1,
                "advisory_rows": 0,
                "reason": "advisory_source_unavailable",
                "detail": "No supported advisory source is configured for this distro family.",
            }
        ],
    )
    stream = io.StringIO()
    monkeypatch.setattr("agent_bom.scanners.console", Console(file=stream, color_system=None))
    try:
        asyncio.run(
            scan_packages(
                [Package(name="openssl", version="3.0.1", ecosystem="rpm", distro_name="amzn", distro_version="2023")],
                options=ScanOptions(offline=True),
            )
        )
    except IncompleteScanError:
        pass  # The copy is emitted before the honest missing-cache outcome.
    assert "end-of-life" not in stream.getvalue().lower()
    assert "advisory" in stream.getvalue().lower()
