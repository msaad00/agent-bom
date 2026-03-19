"""Tests for the rescan (remediation verification) command."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.scan_cache import ScanCache

# ── ScanCache.evict / evict_many ─────────────────────────────────────────────


class TestScanCacheEvict:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.cache = ScanCache(db_path=self.tmp.name)

    def teardown_method(self):
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_evict_removes_entry(self):
        self.cache.put("pypi", "requests", "2.25.0", [{"id": "CVE-2023-1"}])
        assert self.cache.get("pypi", "requests", "2.25.0") is not None
        self.cache.evict("pypi", "requests", "2.25.0")
        assert self.cache.get("pypi", "requests", "2.25.0") is None

    def test_evict_nonexistent_is_noop(self):
        # Should not raise
        self.cache.evict("pypi", "nonexistent", "0.0.0")

    def test_evict_many_removes_multiple(self):
        self.cache.put_many(
            [
                ("pypi", "flask", "2.2.0", [{"id": "CVE-A"}]),
                ("pypi", "requests", "2.25.0", [{"id": "CVE-B"}]),
                ("npm", "lodash", "4.17.20", [{"id": "CVE-C"}]),
            ]
        )
        count = self.cache.evict_many([("pypi", "flask", "2.2.0"), ("pypi", "requests", "2.25.0")])
        assert count == 2
        assert self.cache.get("pypi", "flask", "2.2.0") is None
        assert self.cache.get("pypi", "requests", "2.25.0") is None
        # Untouched entry survives
        assert self.cache.get("npm", "lodash", "4.17.20") is not None

    def test_evict_many_empty_list(self):
        count = self.cache.evict_many([])
        assert count == 0


# ── rescan command ────────────────────────────────────────────────────────────


def _make_baseline(blast_radii: list[dict]) -> dict:
    return {
        "ai_bom_version": "0.60.2",
        "generated_at": "2026-03-08T00:00:00Z",
        "summary": {},
        "agents": [],
        "blast_radius": blast_radii,
    }


BASELINE_WITH_VULNS = _make_baseline(
    [
        {
            "vulnerability_id": "CVE-2023-32681",
            "package": "requests@2.25.0",
            "ecosystem": "pypi",
            "severity": "medium",
        },
        {
            "vulnerability_id": "GHSA-xxxx-yyyy-zzzz",
            "package": "flask@2.2.0",
            "ecosystem": "pypi",
            "severity": "high",
        },
    ]
)

BASELINE_EMPTY = _make_baseline([])


class TestRescanCommand:
    def setup_method(self):
        self.runner = CliRunner()

    def _write_baseline(self, data: dict, tmp_path: Path) -> Path:
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps(data))
        return p

    def test_empty_baseline_exits_0(self, tmp_path):
        p = self._write_baseline(BASELINE_EMPTY, tmp_path)
        result = self.runner.invoke(main, ["report", "rescan", str(p)])
        assert result.exit_code == 0

    def test_all_resolved_exits_0(self, tmp_path):
        p = self._write_baseline(BASELINE_WITH_VULNS, tmp_path)
        # Mock OSV returning nothing (all packages now clean)
        with (
            patch("agent_bom.scan_cache.ScanCache") as mock_cache_cls,
            patch("agent_bom.scanners.query_osv_batch", new_callable=AsyncMock) as mock_osv,
        ):
            mock_cache_cls.return_value = MagicMock()
            mock_cache_cls.return_value.evict_many.return_value = 2
            # OSV returns empty — all vulns resolved
            mock_osv.return_value = {}
            result = self.runner.invoke(main, ["report", "rescan", str(p)])
        assert result.exit_code == 0, result.output
        assert "Resolved" in result.output

    def test_remaining_vulns_exits_1(self, tmp_path):
        p = self._write_baseline(BASELINE_WITH_VULNS, tmp_path)
        # OSV still returns the same vuln for requests
        with (
            patch("agent_bom.scan_cache.ScanCache") as mock_cache_cls,
            patch("agent_bom.scanners.query_osv_batch", new_callable=AsyncMock) as mock_osv,
        ):
            mock_cache_cls.return_value = MagicMock()
            mock_cache_cls.return_value.evict_many.return_value = 2
            mock_osv.return_value = {
                "pypi:requests@2.25.0": [
                    {
                        "id": "CVE-2023-32681",
                        "summary": "Header leak on redirect",
                        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"}],
                        "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}, "ranges": []}],
                    }
                ],
                "pypi:flask@2.2.0": [],  # flask resolved
            }
            result = self.runner.invoke(main, ["report", "rescan", str(p)])
        assert result.exit_code == 1, result.output
        assert "Remaining" in result.output

    def test_writes_json_output(self, tmp_path):
        p = self._write_baseline(BASELINE_WITH_VULNS, tmp_path)
        out = tmp_path / "verification.json"
        with (
            patch("agent_bom.scan_cache.ScanCache") as mock_cache_cls,
            patch("agent_bom.scanners.query_osv_batch", new_callable=AsyncMock) as mock_osv,
        ):
            mock_cache_cls.return_value = MagicMock()
            mock_cache_cls.return_value.evict_many.return_value = 2
            mock_osv.return_value = {}
            self.runner.invoke(main, ["report", "rescan", str(p), "--output", str(out)])
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["type"] == "remediation_verification"
        assert "summary" in data
        assert "resolved" in data
        assert "remaining" in data

    def test_writes_markdown_output(self, tmp_path):
        p = self._write_baseline(BASELINE_WITH_VULNS, tmp_path)
        md = tmp_path / "verification.md"
        with (
            patch("agent_bom.scan_cache.ScanCache") as mock_cache_cls,
            patch("agent_bom.scanners.query_osv_batch", new_callable=AsyncMock) as mock_osv,
        ):
            mock_cache_cls.return_value = MagicMock()
            mock_cache_cls.return_value.evict_many.return_value = 2
            mock_osv.return_value = {}
            self.runner.invoke(main, ["report", "rescan", str(p), "--md", str(md)])
        assert md.exists()
        content = md.read_text()
        assert "Remediation Verification Report" in content
        assert "Resolved" in content

    def test_baseline_not_found_fails(self, tmp_path):
        result = self.runner.invoke(main, ["report", "rescan", str(tmp_path / "nonexistent.json")])
        assert result.exit_code != 0

    def test_newly_found_included_in_output(self, tmp_path):
        """A new CVE not in baseline appears in newly_found."""
        p = self._write_baseline(
            _make_baseline([{"vulnerability_id": "CVE-OLD-001", "package": "flask@2.2.0", "ecosystem": "pypi", "severity": "low"}]),
            tmp_path,
        )
        out = tmp_path / "v.json"
        with (
            patch("agent_bom.scan_cache.ScanCache") as mock_cache_cls,
            patch("agent_bom.scanners.query_osv_batch", new_callable=AsyncMock) as mock_osv,
        ):
            mock_cache_cls.return_value = MagicMock()
            mock_cache_cls.return_value.evict_many.return_value = 1
            mock_osv.return_value = {
                "pypi:flask@2.2.0": [
                    {
                        "id": "CVE-NEW-999",
                        "summary": "A brand new vuln",
                        "severity": [],
                        "affected": [],
                    }
                ]
            }
            self.runner.invoke(main, ["report", "rescan", str(p), "--output", str(out)])
        data = json.loads(out.read_text())
        assert len(data["newly_found"]) == 1
        assert data["newly_found"][0]["id"] == "CVE-NEW-999"
        assert len(data["resolved"]) == 1  # CVE-OLD-001 resolved
