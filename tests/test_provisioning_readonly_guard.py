"""Tests for scripts/check_provisioning_readonly.py — the trust-contract guard
that keeps agent-bom's cloud-connect provisioning modules read-only."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_provisioning_readonly.py"


def _load_guard():
    spec = importlib.util.spec_from_file_location("check_provisioning_readonly", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    # Register before exec so @dataclass can resolve the module's namespace.
    sys.modules["check_provisioning_readonly"] = mod
    spec.loader.exec_module(mod)
    return mod


GUARD = _load_guard()


def _files(text: str) -> dict[Path, str]:
    # Path must live under the repo root so Result.fail()'s relative_to works.
    return {ROOT / "deploy" / "terraform" / "_synthetic" / "main.tf": text}


# ---------------------------------------------------------------------------
# Current tree must PASS (end-to-end, real modules).
# ---------------------------------------------------------------------------
def test_current_tree_passes() -> None:
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS:" in proc.stdout


def test_demo_deploy_is_explicitly_operational_and_instance_scoped() -> None:
    """Demo redeploy may mutate only its own VM, never a connected estate."""
    assert "demo-deploy-oidc" in GUARD.OPERATIONAL_MODULES
    content = (ROOT / "deploy" / "terraform" / "demo-deploy-oidc" / "main.tf").read_text()
    assert 'actions = ["ssm:SendCommand"]' in content
    assert "local.demo_instance_arn" in content
    assert '"ssm:*"' not in content


# ---------------------------------------------------------------------------
# Rule 1 — read-only connect modules.
# ---------------------------------------------------------------------------
def test_readonly_connect_accepts_describe_list_get() -> None:
    res = GUARD.Result()
    tf = """
    data "aws_iam_policy_document" "ro" {
      statement {
        actions = ["ec2:DescribeInstances", "s3:ListBucket", "iam:GetRole"]
        resources = ["*"]
      }
    }
    """
    GUARD.check_readonly_connect("connect-aws", _files(tf), res)
    assert res.failures == []


def test_readonly_connect_rejects_write_action() -> None:
    res = GUARD.Result()
    tf = """
    data "aws_iam_policy_document" "bad" {
      statement {
        actions = ["ec2:DescribeInstances", "ec2:CreateVolume"]
        resources = ["*"]
      }
    }
    """
    GUARD.check_readonly_connect("connect-aws", _files(tf), res)
    assert any("ec2:CreateVolume" in f for f in res.failures)


def test_readonly_connect_rejects_wildcard_action() -> None:
    res = GUARD.Result()
    tf = 'statement { actions = ["s3:*"] resources = ["*"] }'
    GUARD.check_readonly_connect("connect-aws", _files(tf), res)
    assert any("s3:*" in f for f in res.failures)


def test_readonly_connect_rejects_admin_managed_policy() -> None:
    res = GUARD.Result()
    tf = 'managed = ["arn:aws:iam::aws:policy/AdministratorAccess"]'
    GUARD.check_readonly_connect("connect-aws", _files(tf), res)
    assert any("AdministratorAccess" in f for f in res.failures)


def test_readonly_connect_accepts_security_audit_policy() -> None:
    res = GUARD.Result()
    tf = 'x = ["arn:aws:iam::aws:policy/SecurityAudit"]'
    GUARD.check_readonly_connect("connect-aws", _files(tf), res)
    assert res.failures == []


def test_readonly_connect_rejects_non_reader_azure_role() -> None:
    res = GUARD.Result()
    tf = 'role_definition_name = "Contributor"'
    GUARD.check_readonly_connect("connect-azure", _files(tf), res)
    assert any("Contributor" in f for f in res.failures)


def test_readonly_connect_accepts_reader_azure_role() -> None:
    res = GUARD.Result()
    tf = 'role_definition_name = "Reader"'
    GUARD.check_readonly_connect("connect-azure", _files(tf), res)
    assert res.failures == []


def test_readonly_connect_rejects_gcp_editor_role() -> None:
    res = GUARD.Result()
    tf = 'role = "roles/editor"'
    GUARD.check_readonly_connect("connect-gcp", _files(tf), res)
    assert any("roles/editor" in f for f in res.failures)


def test_readonly_connect_rejects_snowflake_write_privilege() -> None:
    res = GUARD.Result()
    tf = 'privileges = ["INSERT", "USAGE"]'
    GUARD.check_readonly_connect("connect-snowflake", _files(tf), res)
    assert any("INSERT" in f for f in res.failures)


def test_readonly_connect_accepts_snowflake_readonly_privileges() -> None:
    res = GUARD.Result()
    tf = 'privileges = ["IMPORTED PRIVILEGES", "MONITOR USAGE", "USAGE"]'
    GUARD.check_readonly_connect("connect-snowflake", _files(tf), res)
    assert res.failures == []


# ---------------------------------------------------------------------------
# Rule 2 — privileged (allowlisted) modules.
# ---------------------------------------------------------------------------
def test_privileged_accepts_scoped_snapshot_lifecycle() -> None:
    res = GUARD.Result()
    tf = """
    statement {
      actions = ["ec2:DeleteSnapshot", "ec2:DeleteVolume"]
      resources = ["*"]
      condition {
        test = "StringEquals"
        variable = "aws:ResourceTag/agent-bom-sidescan"
        values = ["true"]
      }
    }
    """
    GUARD.check_privileged("connect-aws-sidescan", _files(tf), res)
    assert res.failures == []


def test_privileged_rejects_action_outside_snapshot_lifecycle() -> None:
    res = GUARD.Result()
    tf = """
    statement {
      actions = ["ec2:RunInstances"]
      resources = ["*"]
      condition {
        test = "StringEquals"
        variable = "aws:ResourceTag/agent-bom-sidescan"
        values = ["true"]
      }
    }
    """
    GUARD.check_privileged("connect-aws-sidescan", _files(tf), res)
    assert any("ec2:RunInstances" in f for f in res.failures)


def test_privileged_rejects_mutation_without_tag_condition() -> None:
    res = GUARD.Result()
    tf = """
    statement {
      actions = ["ec2:DeleteSnapshot"]
      resources = ["*"]
    }
    """
    GUARD.check_privileged("connect-aws-sidescan", _files(tf), res)
    assert any("tag-scoping condition" in f for f in res.failures)


# ---------------------------------------------------------------------------
# Rule 3 — no surprises (unlisted module with write actions).
# ---------------------------------------------------------------------------
def test_module_has_write_detects_write() -> None:
    tf = 'statement { actions = ["s3:PutObject"] resources = ["*"] }'
    assert GUARD.module_has_write(_files(tf)) is not None


def test_module_has_write_ignores_readonly() -> None:
    tf = 'statement { actions = ["s3:GetObject", "s3:ListBucket"] resources = ["*"] }'
    assert GUARD.module_has_write(_files(tf)) is None


def test_condition_key_not_treated_as_action() -> None:
    # ec2:CreateAction is a condition key, not a grant — must not be flagged.
    tf = """
    statement {
      actions = ["ec2:CreateTags"]
      resources = ["*"]
      condition {
        variable = "ec2:CreateAction"
        values = ["CreateSnapshot", "CreateVolume"]
      }
    }
    """
    res = GUARD.Result()
    GUARD.check_privileged("connect-aws-sidescan", _files(tf), res)
    assert res.failures == []
