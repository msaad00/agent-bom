"""Deployment docs must describe the topology this repo actually ships.

The drift these guards exist for: ``docs/HOSTED_POC.md`` documented the public
demo as DNS pointing at an AWS VM behind Caddy long after the demo had moved to
Cloud Run, and the superseded EC2/SSM redeploy workflow stayed armed on the same
``Release`` trigger as its replacement. Nothing in CI compared the prose against
the workflow that actually deploys, so the drift stayed invisible until someone
curled the documented hostname and got a dead origin.

Each test below ties a documented claim to the file that implements it, so the
next topology move fails CI instead of rotting in prose.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
DEMO_DEPLOY_WORKFLOW = WORKFLOWS / "demo-deploy-cloudrun.yml"
HOSTED_POC = ROOT / "docs" / "HOSTED_POC.md"

# `${{ vars.NAME }}` / `${{ secrets.NAME }}` as GitHub Actions expands them.
_SETTING_RE = re.compile(r"\$\{\{\s*(?:vars|secrets)\.([A-Z0-9_]+)")
# `${{ vars.NAME || 'default' }}` — the workflow's own fallback value.
_DEFAULTED_RE = re.compile(r"\$\{\{\s*vars\.([A-Z0-9_]+)\s*\|\|\s*'([^']*)'\s*\}\}")
# A `.github/workflows/<name>.yml` path named in prose.
_WORKFLOW_PATH_RE = re.compile(r"\.github/workflows/([A-Za-z0-9_.-]+\.ya?ml)")
# Any `DEMO_*` setting name mentioned anywhere in the doc.
_DEMO_SETTING_RE = re.compile(r"\bDEMO_[A-Z0-9_]+\b")


def _demo_settings(text: str) -> set[str]:
    """Every `DEMO_*` var/secret the workflow actually reads."""
    return {name for name in _SETTING_RE.findall(text) if name.startswith("DEMO_")}


def _markdown_files() -> list[Path]:
    paths = sorted(ROOT.glob("*.md"))
    for directory in ("docs", "site-docs", "deploy"):
        paths.extend(sorted((ROOT / directory).rglob("*.md")))
    return paths


def test_hosted_poc_documents_every_setting_the_demo_deploy_reads() -> None:
    """A setting the deploy needs but the runbook omits is an undeployable demo."""
    workflow = DEMO_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
    doc = HOSTED_POC.read_text(encoding="utf-8")

    undocumented = sorted(name for name in _demo_settings(workflow) if name not in doc)

    assert undocumented == [], f"{DEMO_DEPLOY_WORKFLOW.name} reads {undocumented} but docs/HOSTED_POC.md never mentions them"


def test_hosted_poc_documents_no_demo_setting_that_nothing_reads() -> None:
    """The reverse guard: a documented knob no workflow reads is stale prose.

    This is the exact shape of the AWS drift — the runbook kept a configuration
    table for `DEMO_INSTANCE_ID` / `DEMO_DEPLOY_DIR` / `DEMO_DEPLOY_ROLE_ARN`
    after the demo stopped being deployed that way.
    """
    doc = HOSTED_POC.read_text(encoding="utf-8")
    live = set()
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        live |= _demo_settings(workflow.read_text(encoding="utf-8"))

    phantom = sorted(set(_DEMO_SETTING_RE.findall(doc)) - live)

    assert phantom == [], f"docs/HOSTED_POC.md documents {phantom}, which no workflow in .github/workflows reads"


def test_hosted_poc_states_the_defaults_the_deploy_workflow_actually_applies() -> None:
    """A documented default that contradicts the workflow misconfigures the demo."""
    workflow = DEMO_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
    doc_lines = HOSTED_POC.read_text(encoding="utf-8").splitlines()

    defaults = {name: value for name, value in _DEFAULTED_RE.findall(workflow) if name.startswith("DEMO_")}
    assert defaults, "expected the Cloud Run deploy to carry `vars.X || 'default'` fallbacks"

    for name, value in sorted(defaults.items()):
        mentions = [line for line in doc_lines if name in line]
        assert mentions, f"docs/HOSTED_POC.md never documents {name}"
        assert any(value in line for line in mentions), (
            f"{name} defaults to {value!r} in {DEMO_DEPLOY_WORKFLOW.name}, but docs/HOSTED_POC.md states: {mentions}"
        )


def test_hosted_poc_states_the_runtime_contract_the_deploy_workflow_applies() -> None:
    """Cost and port ceilings are only true if the doc quotes the real flags."""
    workflow = DEMO_DEPLOY_WORKFLOW.read_text(encoding="utf-8")
    doc = HOSTED_POC.read_text(encoding="utf-8")

    for flag in ("--concurrency", "--timeout", "--port"):
        match = re.search(rf"{flag}=(\S+)", workflow)
        assert match is not None, f"{DEMO_DEPLOY_WORKFLOW.name} no longer passes {flag}"
        value = match.group(1)
        # Match the flag and its value together. Looking for the bare number
        # passes vacuously — "40" is a substring of the "400,000 vCPU-seconds"
        # free-tier figure two paragraphs away.
        assert f"{flag}={value}" in doc or f"{flag} {value}" in doc, (
            f"{DEMO_DEPLOY_WORKFLOW.name} passes {flag}={value}, which docs/HOSTED_POC.md does not state"
        )


def test_docs_only_reference_workflows_that_exist() -> None:
    """Prose naming a deleted workflow sends operators to a file that is gone."""
    missing: list[str] = []
    for path in _markdown_files():
        for name in _WORKFLOW_PATH_RE.findall(path.read_text(encoding="utf-8")):
            if not (WORKFLOWS / name).is_file():
                missing.append(f"{path.relative_to(ROOT)} -> .github/workflows/{name}")

    assert missing == [], f"docs reference workflows that do not exist: {missing}"


def test_no_workflow_still_deploys_the_demo_to_retired_aws_infrastructure() -> None:
    """The demo VM is retired; automation targeting it must not stay armed.

    A workflow that assumes an IAM role to `ssm:SendCommand` a decommissioned
    instance is dead automation holding a live trust relationship, and it fired
    on the same `Release` completion as the Cloud Run deploy.
    """
    assert not (WORKFLOWS / "demo-redeploy.yml").exists(), (
        "the EC2/SSM demo redeploy is superseded by demo-deploy-cloudrun.yml and must not stay armed"
    )

    offenders = [
        workflow.name for workflow in sorted(WORKFLOWS.glob("*.yml")) if "DEMO_INSTANCE_ID" in workflow.read_text(encoding="utf-8")
    ]
    assert offenders == [], f"workflows still target the retired demo VM: {offenders}"


def test_hosted_poc_keeps_the_project_demo_and_the_self_host_runbook_distinct() -> None:
    """The VM runbook stays as a self-host option, never as the project's demo."""
    doc = HOSTED_POC.read_text(encoding="utf-8")

    # The project's own public demo is Cloud Run, deployed by this workflow.
    assert "demo-deploy-cloudrun.yml" in doc

    # The VM/Caddy path survives, but only as the reader's own infrastructure.
    assert "Self-host" in doc
    assert "AWS VM public IPv4" not in doc, "the demo no longer resolves to an AWS VM"
    assert "Customer-0 AWS VM" not in doc, "the runbook is generic self-host, not an AWS VM we run"

    # The unmapped custom domain is a deferred option, never a live endpoint and
    # never an outstanding fault. Prose wraps, so compare on normalized text.
    prose = " ".join(doc.split())
    if "demo.agent-bom.com" in prose:
        assert "No custom domain is currently mapped" in prose
        assert "optional future step" in prose
