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

import json

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
    # Keep the per-provider status surface consistent with the forced detection.
    monkeypatch.setattr(
        cg,
        "_provider_status",
        lambda p: (p in set(providers), "test source" if p in set(providers) else "no credentials"),
    )


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
        # Per-provider status: detected ones scanning, the unconfigured one skipped.
        assert "aws: scanning" in r.output
        assert "gcp: scanning" in r.output
        assert "azure: skipped" in r.output

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

    def test_aliases_auto_update_db_default_on(self, monkeypatch):
        # Cloud scans get-latest by default, matching `agent-bom scan`.
        monkeypatch.delenv("AGENT_BOM_AUTO_UPDATE_DB", raising=False)
        seen = _capture_scan(monkeypatch)
        for command in ("aws", "azure", "gcp"):
            r = CliRunner().invoke(cloud_group, [command])
            assert r.exit_code == 0
        assert [item["auto_update_db"] for item in seen] == [True, True, True]

    def test_aliases_auto_update_db_env_opt_out(self, monkeypatch):
        # AGENT_BOM_AUTO_UPDATE_DB=0 pins the DB (reproducible CI), like the main path.
        monkeypatch.setenv("AGENT_BOM_AUTO_UPDATE_DB", "0")
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


# ── credential-based detection wiring ────────────────────────────────────────


class TestCredentialDetection:
    def test_detect_routes_through_credential_probe(self, monkeypatch):
        """``_provider_configured`` delegates to the credential probe, not the CLI."""
        calls: list[str] = []

        def fake_probe(provider):
            calls.append(provider)
            return (provider == "aws", "env AWS_WEB_IDENTITY_TOKEN_FILE")

        monkeypatch.setattr("agent_bom.cloud.auth_probe.provider_has_credentials", fake_probe)
        assert cg._detect_configured_providers() == ["aws"]
        assert set(calls) >= {"aws", "azure", "gcp"}

    def test_status_line_names_the_credential_source(self, monkeypatch):
        """`--provider all` surfaces the resolved source per scanning provider."""
        monkeypatch.setattr(cg, "_provider_configured", lambda p: p == "aws")
        monkeypatch.setattr(
            cg,
            "_provider_status",
            lambda p: (p == "aws", "env AWS_WEB_IDENTITY_TOKEN_FILE" if p == "aws" else "no credentials"),
        )
        _capture_scan(monkeypatch)

        r = CliRunner().invoke(cloud_group, ["scan", "--provider", "all"])
        assert r.exit_code == 0
        assert "aws: scanning" in r.output
        assert "AWS_WEB_IDENTITY_TOKEN_FILE" in r.output

    def test_verify_flag_runs_opt_in_confirmation(self, monkeypatch):
        """``--verify`` triggers the network confirm path; default never does."""
        _all_configured(monkeypatch, {"aws"})
        _capture_scan(monkeypatch)
        verified: list[str] = []

        def fake_verify(provider):
            verified.append(provider)
            return True, "sts: arn:aws:iam::1:role/x"

        monkeypatch.setattr("agent_bom.cloud.auth_probe.verify_credentials", fake_verify)

        # Without --verify: no verification call.
        CliRunner().invoke(cloud_group, ["scan", "--provider", "aws"])
        assert verified == []

        # With --verify: the confirm path runs and its result is surfaced.
        r = CliRunner().invoke(cloud_group, ["scan", "--provider", "aws", "--verify"])
        assert r.exit_code == 0
        assert verified == ["aws"]
        assert "verified" in r.output


# ── --show-passed wiring to the grouped CIS renderer ─────────────────────────


class TestShowPassedWiring:
    """`--show-passed` is surfaced on every cloud command and the choice rides
    the click context ``meta`` through the ``cloud scan`` → ``scan`` invoke so
    the grouped CIS renderer can honor it."""

    def test_flag_present_in_help_for_every_command(self):
        for command in ("scan", "aws", "azure", "gcp"):
            r = CliRunner().invoke(cloud_group, [command, "--help"])
            assert r.exit_code == 0
            assert "--show-passed" in r.output, command

    @staticmethod
    def _capture_meta(monkeypatch):
        """Capture the show-passed meta value visible to the scan callback."""
        from agent_bom.cli.agents._cloud import CIS_SHOW_PASSED_META

        seen: list[object] = []

        def fake_scan(**kwargs):
            import click

            seen.append(click.get_current_context().meta.get(CIS_SHOW_PASSED_META))

        monkeypatch.setattr("agent_bom.cli.agents.scan.callback", fake_scan)
        return seen

    def test_show_passed_rides_context_meta(self, monkeypatch):
        seen = self._capture_meta(monkeypatch)
        r = CliRunner().invoke(cloud_group, ["scan", "--provider", "aws", "--show-passed"])
        assert r.exit_code == 0
        assert seen == [True]

    def test_default_meta_is_falsey(self, monkeypatch):
        seen = self._capture_meta(monkeypatch)
        r = CliRunner().invoke(cloud_group, ["scan", "--provider", "aws"])
        assert r.exit_code == 0
        assert seen == [False]

    def test_alias_forwards_show_passed(self, monkeypatch):
        seen = self._capture_meta(monkeypatch)
        CliRunner().invoke(cloud_group, ["aws", "--show-passed"])
        assert seen == [True]


# ── grouped CIS renderer routing (render_output → print_cis_findings) ────────


class _FakeBenchmarkReport:
    """Minimal stand-in for a benchmark report exposing ``to_dict()``."""

    def __init__(self, bundle: dict) -> None:
        self._bundle = bundle

    def to_dict(self) -> dict:
        return self._bundle


def _cis_bundle() -> dict:
    """Small AWS-style bundle: 1 critical fail, 1 high fail, 2 passes."""
    return {
        "benchmark": "CIS AWS Foundations",
        "pass_rate": 50.0,
        "passed": 2,
        "failed": 2,
        "total": 4,
        "checks": [
            {
                "check_id": "1.1",
                "title": "Root account has no access keys",
                "status": "fail",
                "severity": "critical",
                "evidence": "root key present",
                "resource_ids": ["arn:aws:iam::1:root"],
                "recommendation": "Delete root access keys.",
                "remediation": {"fix_cli": "aws iam delete-access-key", "priority": 1},
                "cis_section": "1 - IAM",
            },
            {
                "check_id": "2.1",
                "title": "CloudTrail enabled in all regions",
                "status": "fail",
                "severity": "high",
                "evidence": "trail missing",
                "resource_ids": ["trail-x"],
                "recommendation": "Enable multi-region CloudTrail.",
                "remediation": {"priority": 2},
                "cis_section": "2 - Logging",
            },
            {"check_id": "1.2", "title": "MFA on root", "status": "pass", "severity": "high"},
            {"check_id": "1.3", "title": "Password policy", "status": "pass", "severity": "medium"},
        ],
    }


def _render_ctx_cis(monkeypatch, *, show_passed: bool) -> str:
    """Run ``render_cis_findings_from_context`` with one AWS bundle and capture console output."""
    from io import StringIO

    import click
    from rich.console import Console

    import agent_bom.output as output_mod
    from agent_bom.cli.agents._cloud import CIS_SHOW_PASSED_META, render_cis_findings_from_context
    from agent_bom.cli.agents._context import ScanContext

    buf = StringIO()
    con = Console(file=buf, force_terminal=False, width=200)
    monkeypatch.setattr(output_mod, "console", con)

    ctx = ScanContext(con=con)
    ctx.cis_benchmark_report = _FakeBenchmarkReport(_cis_bundle())

    # --show-passed is carried on the click context meta; render under a click
    # context that mirrors how the cloud command sets it.
    with click.Context(click.Command("scan")) as click_ctx:
        click_ctx.meta[CIS_SHOW_PASSED_META] = show_passed
        render_cis_findings_from_context(ctx)
    return buf.getvalue()


class TestGroupedCisRendererRouting:
    def test_failed_first_grouped_and_passes_collapsed(self, monkeypatch):
        out = _render_ctx_cis(monkeypatch, show_passed=False)
        # Severity bands present, CRITICAL ahead of HIGH (failed-first ordering).
        assert "CRITICAL" in out and "HIGH" in out
        assert out.index("CRITICAL") < out.index("HIGH")
        # Failed checks carry evidence + fix lines.
        assert "evidence:" in out and "fix:" in out
        assert "arn:aws:iam::1:root" in out
        assert "aws iam delete-access-key" in out
        # Passes are collapsed into a count, not listed individually.
        assert "2 passed" in out
        assert "--show-passed" in out
        assert "Password policy" not in out

    def test_show_passed_lists_individual_passes(self, monkeypatch):
        out = _render_ctx_cis(monkeypatch, show_passed=True)
        assert "Passed (2)" in out
        assert "Password policy" in out

    def test_no_cis_data_emits_nothing(self, monkeypatch):
        from io import StringIO

        from rich.console import Console

        import agent_bom.output as output_mod
        from agent_bom.cli.agents._cloud import render_cis_findings_from_context
        from agent_bom.cli.agents._context import ScanContext

        buf = StringIO()
        con = Console(file=buf, force_terminal=False, width=200)
        monkeypatch.setattr(output_mod, "console", con)
        render_cis_findings_from_context(ScanContext(con=con))
        assert buf.getvalue() == ""


# ── requested-provider hard failure → non-zero exit (no silent CI pass) ───────


class TestRequestedProviderHardFailExits:
    """A provider that is explicitly requested but whose SDK or credentials are
    missing/invalid (CloudDiscoveryError) must make the scan exit non-zero. A
    genuinely empty-but-successful scan still exits 0, and one provider failing
    never aborts the others."""

    def test_discovery_sdk_missing_exits_nonzero(self, monkeypatch):
        from agent_bom.cli import main
        from agent_bom.cloud import CloudDiscoveryError

        def _raise(provider, **kwargs):
            raise CloudDiscoveryError("boto3 is required for AWS scanning. Install with pip install 'agent-bom[aws]'")

        monkeypatch.setattr("agent_bom.cloud.discover_from_provider", _raise)

        r = CliRunner().invoke(main, ["scan", "--aws", "--no-discover", "--offline"])
        assert r.exit_code == 1
        # The helpful install hint is preserved (brackets survive Rich markup),
        # and the gate message is shown. Normalize wrapping inserted by the
        # console at narrow widths before matching.
        normalized = " ".join(r.output.split())
        assert "pip install 'agent-bom[aws]'" in normalized
        assert "cloud provider discovery failed for aws" in normalized

    def test_cis_benchmark_sdk_missing_exits_nonzero(self, monkeypatch):
        from agent_bom.cli import main
        from agent_bom.cloud import CloudDiscoveryError

        # Discovery succeeds-but-empty; the CIS benchmark is the hard failure.
        monkeypatch.setattr("agent_bom.cloud.discover_from_provider", lambda provider, **kwargs: ([], []))

        def _raise_cis(**kwargs):
            raise CloudDiscoveryError("boto3 is required for AWS scanning.")

        monkeypatch.setattr("agent_bom.cloud.aws_cis_benchmark.run_benchmark", _raise_cis)

        r = CliRunner().invoke(main, ["scan", "--aws", "--aws-cis-benchmark", "--no-discover", "--offline"])
        assert r.exit_code == 1
        assert "cloud provider discovery failed for aws" in r.output

    def test_empty_but_successful_scan_still_exits_zero(self, monkeypatch):
        from agent_bom.cli import main

        # Credentials present, provider reachable, simply no AI resources found.
        monkeypatch.setattr("agent_bom.cloud.discover_from_provider", lambda provider, **kwargs: ([], []))

        r = CliRunner().invoke(main, ["scan", "--aws", "--no-discover", "--offline"])
        assert r.exit_code == 0
        assert "cloud provider discovery failed" not in r.output

    def test_single_requested_provider_failure_is_failed_in_json(self, monkeypatch, tmp_path):
        from agent_bom.cli import main
        from agent_bom.cloud import CloudDiscoveryError

        monkeypatch.setattr(
            "agent_bom.cloud.discover_from_provider",
            lambda provider, **kwargs: (_ for _ in ()).throw(CloudDiscoveryError(f"{provider} credentials unavailable")),
        )
        output = tmp_path / "failed.json"

        result = CliRunner().invoke(
            main,
            ["scan", "--aws", "--no-discover", "--offline", "--format", "json", "-o", str(output)],
        )

        assert result.exit_code == 1
        payload = json.loads(output.read_text(encoding="utf-8"))
        assert payload["scan_run"]["outcome"] == "failed"
        assert payload["scan_run"]["issues"][0]["source"] == "aws"

    def test_mixed_cloud_success_and_failure_is_partial_in_json(self, monkeypatch, tmp_path):
        from agent_bom.cli import main
        from agent_bom.cloud import CloudDiscoveryError

        def _discover(provider, **kwargs):
            if provider == "azure":
                raise CloudDiscoveryError("azure credentials unavailable")
            return [], []

        monkeypatch.setattr("agent_bom.cloud.discover_from_provider", _discover)
        output = tmp_path / "partial.json"

        result = CliRunner().invoke(
            main,
            ["scan", "--aws", "--azure", "--no-discover", "--offline", "--format", "json", "-o", str(output)],
        )

        assert result.exit_code == 1
        payload = json.loads(output.read_text(encoding="utf-8"))
        assert payload["scan_run"]["outcome"] == "partial"
        assert "cloud:aws" in payload["scan_sources"]

    def test_one_provider_failing_does_not_skip_the_others(self, monkeypatch):
        """Both requested providers are attempted even when the first hard-fails;
        the failure is recorded once per provider and the exit code is non-zero."""
        from rich.console import Console

        from agent_bom.cli.agents._cloud import run_cloud_discovery
        from agent_bom.cli.agents._context import ScanContext
        from agent_bom.cli.agents._post import compute_exit_code

        attempted: list[str] = []

        def _raise(provider, **kwargs):
            attempted.append(provider)
            raise RuntimeError(f"{provider} unexpected collector failure")

        monkeypatch.setattr("agent_bom.cloud.discover_from_provider", _raise)

        ctx = ScanContext(con=Console(quiet=True))
        run_cloud_discovery(
            ctx,
            skill_only=False,
            aws=True,
            aws_region=None,
            aws_profile=None,
            aws_include_lambda=False,
            aws_include_eks=False,
            aws_include_step_functions=False,
            aws_include_ec2=False,
            aws_include_iam=False,
            aws_ec2_tag=None,
            azure_flag=True,
            azure_subscription=None,
            gcp_flag=False,
            gcp_project=None,
            coreweave_flag=False,
            coreweave_context=None,
            coreweave_namespace=None,
            databricks_flag=False,
            snowflake_flag=False,
            snowflake_authenticator=None,
            nebius_flag=False,
            nebius_api_key=None,
            nebius_project_id=None,
            hf_flag=False,
            hf_token=None,
            hf_username=None,
            hf_organization=None,
            wandb_flag=False,
            wandb_api_key=None,
            wandb_entity=None,
            wandb_project=None,
            mlflow_flag=False,
            mlflow_tracking_uri=None,
            openai_flag=False,
            openai_api_key=None,
            openai_org_id=None,
            ollama_flag=False,
            ollama_host=None,
        )

        # Both requested providers were attempted (no early abort).
        assert attempted == ["aws", "azure"]
        failed = {f["provider"] for f in ctx.cloud_provider_failures}
        assert failed == {"aws", "azure"}
        code = compute_exit_code(
            ctx,
            fail_on_severity=None,
            warn_on_severity=None,
            fail_on_kev=False,
            fail_if_ai_risk=False,
            push_url=None,
            push_api_key=None,
            quiet=True,
        )
        assert code == 1


# ── regression: cloud aliases must call scan() with kwargs it actually accepts ──


class TestCloudAliasKwargsMatchScanSignature:
    """Guards the ``cloud`` group → ``scan`` invocation against keyword drift.

    Regression for the 0.94.2 break where ``_run_cloud_scan`` passed
    ``aws_include_lambda`` (the target ``scan`` command exposes ``no_aws_lambda``),
    raising ``TypeError`` on every ``cloud scan/aws/azure/gcp`` run. The prior
    tests missed it because they patched ``scan.callback`` with a permissive
    ``**kwargs`` fake that swallowed the bad keyword. Here we bind the captured
    kwargs against the REAL signature so any future rename fails loudly.
    """

    def _real_scan_signature(self):
        import inspect

        import agent_bom.cli.agents as agents

        return inspect.signature(agents.scan.callback)

    def _assert_kwargs_bind(self, kwargs: dict) -> None:
        # Raises TypeError if the kwargs don't match scan()'s real parameters.
        self._real_scan_signature().bind(**kwargs)
        assert "no_aws_lambda" in kwargs
        assert "aws_include_lambda" not in kwargs

    def test_cloud_aws_alias_invokes_scan_cleanly(self, monkeypatch):
        seen = _capture_scan(monkeypatch)
        _all_configured(monkeypatch, {"aws"})
        result = CliRunner().invoke(cloud_group, ["aws", "--region", "us-east-2"])
        assert result.exit_code == 0, result.output
        assert seen, "scan was never invoked"
        self._assert_kwargs_bind(seen[-1])

    def test_cloud_scan_provider_all_invokes_scan_cleanly(self, monkeypatch):
        seen = _capture_scan(monkeypatch)
        _all_configured(monkeypatch, {"aws", "gcp"})
        result = CliRunner().invoke(cloud_group, ["scan", "--provider", "all"])
        assert result.exit_code == 0, result.output
        assert seen, "scan was never invoked"
        self._assert_kwargs_bind(seen[-1])


# ── --aws-deep convenience flag ──────────────────────────────────────────────


class TestAwsDeep:
    def test_cloud_scan_aws_deep_sets_all_includes(self, monkeypatch):
        seen = _capture_scan(monkeypatch)
        r = CliRunner().invoke(cloud_group, ["scan", "--provider", "aws", "--aws-deep"])
        assert r.exit_code == 0
        assert seen[0]["aws_include_eks"] is True
        assert seen[0]["aws_include_ec2"] is True
        assert seen[0]["aws_include_iam"] is True

    def test_cloud_aws_alias_deep_sets_all_includes(self, monkeypatch):
        seen = _capture_scan(monkeypatch)
        r = CliRunner().invoke(cloud_group, ["aws", "--aws-deep"])
        assert r.exit_code == 0
        assert seen[0]["aws_include_eks"] is True
        assert seen[0]["aws_include_ec2"] is True
        assert seen[0]["aws_include_iam"] is True

    def test_cloud_scan_without_deep_leaves_includes_off(self, monkeypatch):
        seen = _capture_scan(monkeypatch)
        r = CliRunner().invoke(cloud_group, ["scan", "--provider", "aws"])
        assert r.exit_code == 0
        assert seen[0]["aws_include_eks"] is False
        assert seen[0]["aws_include_ec2"] is False
        assert seen[0]["aws_include_iam"] is False
