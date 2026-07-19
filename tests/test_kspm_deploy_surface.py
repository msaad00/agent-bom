"""Stage 4 (deploy) surface for KSPM — CLI posture-only + Helm KSPM job.

Covers the deployable-in-cluster acceptance of #4134:
  - ``agent-bom iac --k8s-live`` runs posture with no IaC path argument
    (the scheduled KSPM job invokes posture, not image discovery);
  - the Helm chart schedules a real k8s_posture job (distinct from image
    discovery) bound to the scanner service account with least-privilege,
    read-only RBAC (no secrets, no mutation, no proxy).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.iac.models import IaCFinding
from agent_bom.k8s import (
    CollectorState,
    K8sCollectorEvidence,
    K8sPostureResult,
    K8sPostureStatus,
)

CHART = Path(__file__).resolve().parents[1] / "deploy" / "helm" / "agent-bom"


def _posture_result() -> K8sPostureResult:
    return K8sPostureResult(
        findings=[
            IaCFinding(
                rule_id="K8S-LIVE-007",
                severity="critical",
                title="Running privileged container",
                message="privileged",
                file_path="k8s://default/risky",
                line_number=1,
                category="kubernetes-live",
                compliance=["CIS-K8s-5.2.1"],
            )
        ],
        collectors=[
            K8sCollectorEvidence(collector_id="pods", state=CollectorState.EXECUTED, object_count=2, transport="in-cluster"),
        ],
        status=K8sPostureStatus.COMPLETE,
        transport="in-cluster",
    )


# ── CLI posture-only path ────────────────────────────────────────────────────


def test_iac_k8s_live_runs_with_no_path_argument():
    """The scheduled KSPM job runs ``iac --k8s-live`` with no IaC path."""
    with patch(
        "agent_bom.k8s.scan_live_cluster_posture_with_evidence",
        return_value=_posture_result(),
    ) as mocked:
        result = CliRunner().invoke(main, ["iac", "--k8s-live", "--format", "json"])
    assert "Missing argument" not in result.output, result.output
    assert mocked.called, "posture collector was not invoked"


def test_iac_with_no_path_and_no_k8s_live_errors_clearly():
    """A bare ``iac`` with neither a path nor --k8s-live must not look clean."""
    result = CliRunner().invoke(main, ["iac"])
    assert result.exit_code != 0
    assert "k8s-live" in result.output.lower() or "path" in result.output.lower()


def test_iac_k8s_live_help_does_not_claim_kubectl_only():
    """In-cluster posture uses the native transport, not kubectl."""
    from agent_bom.cli._focused_commands import iac_cmd

    k8s_live_opt = next(p for p in iac_cmd.params if getattr(p, "name", "") == "k8s_live")
    # The stale "via kubectl" wording implied kubectl was required in-cluster.
    assert "kubectl" not in (k8s_live_opt.help or "").lower(), k8s_live_opt.help


# ── Helm KSPM job + least-privilege RBAC ─────────────────────────────────────


def _helm_render(*set_values: str) -> list[dict]:
    if shutil.which("helm") is None:
        pytest.skip("helm not installed")
    args = ["helm", "template", "abom", str(CHART)]
    for value in set_values:
        args += ["--set", value]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return [doc for doc in yaml.safe_load_all(proc.stdout) if doc]


def _by_kind(docs: list[dict], kind: str) -> list[dict]:
    return [d for d in docs if d.get("kind") == kind]


def test_helm_schedules_kspm_posture_job_bound_to_scanner_sa():
    docs = _helm_render("scanner.kspm.enabled=true")
    cronjobs = _by_kind(docs, "CronJob")
    kspm = [c for c in cronjobs if "kspm" in c["metadata"]["name"] or "posture" in c["metadata"]["name"]]
    assert kspm, "no KSPM posture CronJob rendered"
    job = kspm[0]
    spec = job["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    container = spec["containers"][0]
    argv = [str(container.get("command", [])), str(container.get("args", []))]
    joined = " ".join(argv)
    # Real posture path, NOT image discovery.
    assert "--k8s-live" in joined, joined
    assert "--k8s " not in joined and "'--k8s'" not in joined, "KSPM job must not run image discovery"
    # Bound to the scanner service account (the RBAC subject), not default.
    sa = spec.get("serviceAccountName", "")
    assert "scanner" in sa, f"KSPM job must use the scanner SA, got {sa!r}"


def test_helm_rbac_binds_reader_to_scanner_service_account():
    """The ClusterRoleBinding subject must match the scanner job's SA name."""
    docs = _helm_render("scanner.kspm.enabled=true")
    bindings = _by_kind(docs, "ClusterRoleBinding")
    reader = [b for b in bindings if "reader" in b["metadata"]["name"]]
    assert reader, "no reader ClusterRoleBinding rendered"
    subjects = reader[0]["subjects"]
    subject_names = {s["name"] for s in subjects}
    # The scanner job runs as the scanner SA — the binding must target it.
    assert any("scanner" in name for name in subject_names), subject_names

    cronjobs = _by_kind(docs, "CronJob")
    kspm = [c for c in cronjobs if "kspm" in c["metadata"]["name"] or "posture" in c["metadata"]["name"]][0]
    job_sa = kspm["spec"]["jobTemplate"]["spec"]["template"]["spec"]["serviceAccountName"]
    assert job_sa in subject_names, f"binding subjects {subject_names} do not include job SA {job_sa}"


def test_helm_reader_role_is_readonly_and_covers_posture_resources():
    docs = _helm_render("scanner.kspm.enabled=true")
    roles = _by_kind(docs, "ClusterRole")
    reader = [r for r in roles if "reader" in r["metadata"]["name"]]
    assert reader, "no reader ClusterRole rendered"
    rules = reader[0]["rules"]

    granted: dict[str, set[str]] = {}
    for rule in rules:
        verbs = {v.lower() for v in rule.get("verbs", [])}
        for res in rule.get("resources", []):
            granted.setdefault(res, set()).update(verbs)

    # Posture collectors read these resources.
    for required in ("pods", "networkpolicies", "clusterroles", "clusterrolebindings", "roles", "nodes"):
        assert required in granted, f"reader role missing {required}: {sorted(granted)}"

    # Read-only only: every granted verb is get/list (no watch, no mutation).
    allowed_verbs = {"get", "list"}
    for res, verbs in granted.items():
        assert verbs <= allowed_verbs, f"reader role grants non-read verbs on {res}: {sorted(verbs)}"

    # No secrets, no proxy subresource.
    assert "secrets" not in granted, "reader role must not read secrets"
    for res in granted:
        assert "proxy" not in res, f"reader role must not grant proxy: {res}"
