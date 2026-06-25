"""Tests for the unified ``agent-bom cloud scan`` command and its aliases.

One cloud-aware command spans every configured provider; the per-cloud ``aws`` /
``azure`` / ``gcp`` subcommands remain as thin back-compat aliases that scope the
same path to a single provider. These tests pin:

- ``cloud scan --provider all`` runs every *configured* provider and skips the
  rest with a friendly note (auto-detect, graceful degradation).
- ``cloud scan --provider aws`` produces the same scan invocation as the legacy
  ``cloud aws`` alias.
- the aliases still work and still disable auto DB refresh.
- one provider failing does not abort the others (single multi-provider scan
  invocation, deterministic provider order).
"""

from __future__ import annotations

from click.testing import CliRunner

import agent_bom.cli._cloud_group as cg
from agent_bom.cli._cloud_group import (
    _detect_configured_providers,
    _resolve_scan_providers,
    cloud_group,
)


def _capture_scan(monkeypatch):
    """Patch the underlying scan callback and return the list of captured kwargs."""
    seen: list[dict] = []

    def fake_scan(**kwargs):
        seen.append(kwargs)

    monkeypatch.setattr("agent_bom.cli.agents.scan.callback", fake_scan)
    return seen


def _all_configured(monkeypatch, providers):
    """Force credential auto-detect to report exactly ``providers`` as configured."""
    monkeypatch.setattr(cg, "_provider_configured", lambda p: p in set(providers))


# ── auto-detect / resolution ────────────────────────────────────────────────


class TestProviderResolution:
    def test_detect_is_deterministic_and_sorted(self, monkeypatch):
        _all_configured(monkeypatch, {"gcp", "aws"})
        assert _detect_configured_providers() == ["aws", "gcp"]

    def test_resolve_all_splits_configured_and_skipped(self, monkeypatch):
        _all_configured(monkeypatch, {"aws"})
        selected, skipped = _resolve_scan_providers("all")
        assert selected == ["aws"]
        assert skipped == ["azure", "gcp"]

    def test_resolve_named_provider_always_selected(self, monkeypatch):
        # Even with nothing configured, an explicit provider is selected — the
        # underlying scan emits its own credential guidance.
        _all_configured(monkeypatch, set())
        selected, skipped = _resolve_scan_providers("azure")
        assert selected == ["azure"]
        assert skipped == []


# ── unified scan command ────────────────────────────────────────────────────


class TestUnifiedScan:
    def test_help(self):
        r = CliRunner().invoke(cloud_group, ["scan", "--help"])
        assert r.exit_code == 0
        assert "--provider" in r.output
        assert "--region" in r.output
        assert "--subscription" in r.output
        assert "--project" in r.output

    def test_scan_all_runs_configured_skips_unconfigured(self, monkeypatch):
        _all_configured(monkeypatch, {"aws", "gcp"})
        seen = _capture_scan(monkeypatch)

        r = CliRunner().invoke(cloud_group, ["scan", "--provider", "all"])
        assert r.exit_code == 0
        assert len(seen) == 1
        kw = seen[0]
        # Configured providers enabled, unconfigured Azure left off.
        assert kw["aws"] is True
        assert kw["gcp_flag"] is True
        assert kw["azure_flag"] is False
        # Friendly skip note for the unconfigured provider.
        assert "skipping AZURE" in r.output

    def test_scan_all_no_providers_is_graceful(self, monkeypatch):
        _all_configured(monkeypatch, set())
        seen = _capture_scan(monkeypatch)

        r = CliRunner().invoke(cloud_group, ["scan", "--provider", "all"])
        assert r.exit_code == 0
        # No scan invoked, but the command does not crash and guides the user.
        assert seen == []
        assert "No configured cloud providers" in r.output

    def test_scan_provider_aws_matches_legacy_alias(self, monkeypatch):
        seen = _capture_scan(monkeypatch)

        CliRunner().invoke(cloud_group, ["scan", "--provider", "aws"])
        CliRunner().invoke(cloud_group, ["aws"])
        assert len(seen) == 2

        def _provider_flags(kw):
            return {
                "aws": kw["aws"],
                "azure_flag": kw["azure_flag"],
                "gcp_flag": kw["gcp_flag"],
                "aws_cis_benchmark": kw["aws_cis_benchmark"],
                "azure_cis_benchmark": kw["azure_cis_benchmark"],
                "gcp_cis_benchmark": kw["gcp_cis_benchmark"],
                "auto_update_db": kw["auto_update_db"],
            }

        assert _provider_flags(seen[0]) == _provider_flags(seen[1])
        assert seen[0]["aws"] is True
        assert seen[0]["azure_flag"] is False
        assert seen[0]["gcp_flag"] is False

    def test_no_cis_disables_every_benchmark(self, monkeypatch):
        _all_configured(monkeypatch, {"aws", "azure", "gcp"})
        seen = _capture_scan(monkeypatch)

        r = CliRunner().invoke(cloud_group, ["scan", "--provider", "all", "--no-cis"])
        assert r.exit_code == 0
        kw = seen[0]
        assert kw["aws_cis_benchmark"] is False
        assert kw["azure_cis_benchmark"] is False
        assert kw["gcp_cis_benchmark"] is False
        # Discovery still enabled for each configured provider.
        assert kw["aws"] and kw["azure_flag"] and kw["gcp_flag"]

    def test_provider_scoped_options_forwarded(self, monkeypatch):
        seen = _capture_scan(monkeypatch)
        CliRunner().invoke(
            cloud_group,
            ["scan", "--provider", "gcp", "--project", "my-proj"],
        )
        assert seen[0]["gcp_project"] == "my-proj"
        assert seen[0]["gcp_flag"] is True


# ── back-compat aliases ──────────────────────────────────────────────────────


class TestAliases:
    def test_aliases_still_registered(self):
        for name in ("scan", "aws", "azure", "gcp"):
            assert name in cloud_group.commands

    def test_aliases_disable_auto_db_refresh(self, monkeypatch):
        seen = _capture_scan(monkeypatch)
        for command in ("aws", "azure", "gcp"):
            r = CliRunner().invoke(cloud_group, [command])
            assert r.exit_code == 0
        assert [item["auto_update_db"] for item in seen] == [False, False, False]

    def test_azure_alias_forwards_subscription(self, monkeypatch):
        seen = _capture_scan(monkeypatch)
        CliRunner().invoke(cloud_group, ["azure", "--subscription", "sub-123"])
        assert seen[0]["azure_subscription"] == "sub-123"
        assert seen[0]["azure_flag"] is True
        assert seen[0]["aws"] is False


# ── graceful per-provider degradation ────────────────────────────────────────


class TestDegradation:
    def test_one_provider_error_does_not_abort_others(self, monkeypatch):
        """A single multi-provider scan call enables every configured provider.

        `scan` discovers/benchmarks each provider under its own try/except, so a
        failure in one never aborts the others. This pins the contract that all
        selected providers reach that single invocation together.
        """
        _all_configured(monkeypatch, {"aws", "azure", "gcp"})
        seen = _capture_scan(monkeypatch)

        r = CliRunner().invoke(cloud_group, ["scan", "--provider", "all"])
        assert r.exit_code == 0
        assert len(seen) == 1
        kw = seen[0]
        assert kw["aws"] and kw["azure_flag"] and kw["gcp_flag"]
