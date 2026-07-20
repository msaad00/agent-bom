"""End-to-end console honesty: every severity total on the demo scan screen
states its scope, and the headline reconciles with the unified findings stream
(the same stream the JSON/API report carries).

Runs the real curated demo scan offline (no network), once per output format.
"""

from __future__ import annotations

import json
import re

import pytest
from click.testing import CliRunner

from agent_bom.cli import main


@pytest.fixture(scope="module")
def demo_console_output(tmp_path_factory) -> str:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", "--demo", "--offline", "--no-auto-update-db", "-f", "console"],
        catch_exceptions=False,
    )
    return re.sub(r"\x1b\[[0-9;]*m", "", result.output)


@pytest.fixture(scope="module")
def demo_json_report(tmp_path_factory) -> dict:
    out = tmp_path_factory.mktemp("demo") / "report.json"
    runner = CliRunner()
    runner.invoke(
        main,
        ["scan", "--demo", "--offline", "--no-auto-update-db", "-f", "json", "-o", str(out)],
        catch_exceptions=False,
    )
    return json.loads(out.read_text(encoding="utf-8"))


def test_headline_counts_match_unified_stream(demo_console_output, demo_json_report):
    """Whichever severity headline the console shows equals the unified stream.

    With a local advisory DB the summary box prints CRIT/HIGH/MED counts;
    without one (CI) it honestly shows PARTIAL COVERAGE and the labeled
    all-categories Findings line is the reconciliation surface instead.
    """
    by_sev = demo_json_report["finding_summary"]["by_severity"]
    match = re.search(r"CRIT\s+(\d+)\s+HIGH\s+(\d+)\s+MED\s+(\d+)", demo_console_output)
    if match is None:
        assert "PARTIAL COVERAGE" in demo_console_output, "summary box severity headline missing"
        match = re.search(
            r"Findings — (\d+) critical · (\d+) high · (\d+) medium", demo_console_output
        )
        assert match, "all-categories findings line missing"
    assert int(match.group(1)) == by_sev["critical"]
    assert int(match.group(2)) == by_sev["high"]
    assert int(match.group(3)) == by_sev["medium"]


def test_progress_severity_line_is_scope_labeled(demo_console_output):
    """The scan-progress severity breakdown is package-CVE-scoped and says so."""
    assert re.search(r"Scan complete — package CVEs: \d+ critical", demo_console_output)


def test_unified_totals_line_reconciles_progress_with_summary(demo_console_output, demo_json_report):
    """A labeled all-categories totals line bridges the package-CVE progress
    line and the unified summary box — no unlabeled second denominator."""
    by_sev = demo_json_report["finding_summary"]["by_severity"]
    pattern = rf"all finding categories.*{by_sev['critical']} critical.*{by_sev['high']} high.*{by_sev['medium']} medium"
    assert re.search(pattern, demo_console_output) or re.search(
        rf"{by_sev['critical']} critical · {by_sev['high']} high · {by_sev['medium']} medium.*all finding categories",
        demo_console_output,
    )


def test_graph_derived_findings_drill_to_titles(demo_console_output):
    """COMBINATION findings list titles in the console, not just a count."""
    assert "AI agent can reach a credential or privileged tool" in demo_console_output


def test_bad_news_counts_do_not_use_checkmark(demo_console_output):
    """A non-zero toxic-combination count is a warning, not a success glyph."""
    assert not re.search(r"✓\s*Toxic combinations: [1-9]", demo_console_output)
    assert re.search(r"⚠\s*Toxic combinations: \d+", demo_console_output)


def test_package_cve_instance_total_is_scope_labeled(demo_console_output):
    """The per-package CVE-instance total cannot read as the finding count."""
    assert re.search(r"\d+ package CVE instance", demo_console_output)


def test_no_wrap_artifact_in_summary_box(demo_console_output):
    """No stray wrapped '—…' cell fragment at the default 80-col width."""
    assert not re.search(r"^│\s*—…", demo_console_output, flags=re.MULTILINE)


def test_findings_table_never_truncates_cve_ids(demo_console_output, demo_json_report):
    """Every CVE id shown in the findings table renders in full."""
    assert "CVE-2020-14343" in demo_console_output
    assert not re.search(r"CVE-[\d-]*…", demo_console_output)
