"""First-class skills-scan REST route (#4790 parity: CLI/MCP had it, REST did not).

The route reuses the exact shared skills-scan impl (``scan_skill_targets``) the
CLI and MCP already call — it never reimplements detection. It mirrors the
sibling AI supply-chain scans (``/v1/scan/prompt-scan``): local-path scans are
disabled by default and confined to a configured scan root, the blocking scan
runs off the event loop under backpressure, the per-tenant latest result is
persisted, and the returned envelope carries the same per-file trust verdict and
provenance the SARIF export models — an unsigned skill reads ``review`` /
``pending``, never a laundered clean pass.
"""

from __future__ import annotations

from pathlib import Path

from starlette.testclient import TestClient

from agent_bom.api.server import app
from agent_bom.api.skills_scan_store import (
    InMemorySkillsScanStore,
    set_skills_scan_store,
)
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_SCAN_ALPHA = proxy_headers(role="admin", tenant="tenant-alpha")
_READ_ALPHA = proxy_headers(role="viewer", tenant="tenant-alpha")
_READ_BETA = proxy_headers(role="viewer", tenant="tenant-beta")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_skills_scan_store(InMemorySkillsScanStore())


def _seed_scan_root(tmp_path: Path) -> None:
    """Write a skill file that yields a real finding (a credential env reference)."""
    skill = tmp_path / "SKILL.md"
    skill.write_text(
        "---\nname: sample-skill\ndescription: A sample skill.\n---\n\n# Sample Skill\n\nUse the OPENAI_API_KEY to call the model.\n"
    )


def _enable_local_scans(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AGENT_BOM_API_LOCAL_PATH_SCANS", "enabled")
    monkeypatch.setenv("AGENT_BOM_API_SCAN_ROOT", str(tmp_path))


def test_post_scan_returns_real_verdicts_and_provenance(monkeypatch, tmp_path) -> None:
    set_skills_scan_store(InMemorySkillsScanStore())
    _seed_scan_root(tmp_path)
    _enable_local_scans(monkeypatch, tmp_path)

    client = TestClient(app)
    resp = client.post("/v1/skills/scan", json={"files": ["SKILL.md"]}, headers=_SCAN_ALPHA)
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["scan_type"] == "skills"
    assert body["report_type"] == "skills_scan"
    assert body["summary"]["files_scanned"] == 1
    assert len(body["files"]) == 1

    file_report = body["files"][0]
    # The verdict/provenance the SARIF export models must be present per-file.
    assert "trust" in file_report and "verdict" in file_report["trust"]
    assert file_report["trust"]["content_verdict"] in {"benign", "suspicious", "malicious"}
    assert "provenance" in file_report
    # An unsigned local skill is review/pending — never a clean pass.
    assert file_report["trust"]["provenance_verdict"] == "unverified"
    assert file_report["status"] == "pending"
    # The credential reference surfaces as a real finding (not zero-signal).
    assert body["summary"]["credential_env_vars"] >= 1


def test_get_returns_latest_persisted_scan(monkeypatch, tmp_path) -> None:
    set_skills_scan_store(InMemorySkillsScanStore())
    _seed_scan_root(tmp_path)
    _enable_local_scans(monkeypatch, tmp_path)

    client = TestClient(app)
    posted = client.post("/v1/skills/scan", json={"directories": ["."]}, headers=_SCAN_ALPHA)
    assert posted.status_code == 200, posted.text

    got = client.get("/v1/skills/scan", headers=_READ_ALPHA)
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["scan_type"] == "skills"
    assert body["summary"]["files_scanned"] == posted.json()["summary"]["files_scanned"]
    assert body["run_id"]
    assert body["created_at"]


def test_get_without_prior_scan_is_honest_empty() -> None:
    set_skills_scan_store(InMemorySkillsScanStore())
    client = TestClient(app)
    resp = client.get("/v1/skills/scan", headers=_READ_BETA)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scan_type"] == "skills"
    assert body["status"] == "no_data"
    assert body["summary"]["files_scanned"] == 0
    assert body["files"] == []


def test_scan_is_tenant_isolated(monkeypatch, tmp_path) -> None:
    """A scan by tenant-alpha must never surface to tenant-beta's GET."""
    set_skills_scan_store(InMemorySkillsScanStore())
    _seed_scan_root(tmp_path)
    _enable_local_scans(monkeypatch, tmp_path)

    client = TestClient(app)
    assert client.post("/v1/skills/scan", json={"files": ["SKILL.md"]}, headers=_SCAN_ALPHA).status_code == 200

    beta = client.get("/v1/skills/scan", headers=_READ_BETA)
    assert beta.status_code == 200
    assert beta.json()["status"] == "no_data"


def test_local_scans_disabled_by_default_is_rejected(monkeypatch, tmp_path) -> None:
    set_skills_scan_store(InMemorySkillsScanStore())
    _seed_scan_root(tmp_path)
    # Explicitly disabled: no enable flag set.
    monkeypatch.setenv("AGENT_BOM_API_LOCAL_PATH_SCANS", "disabled")
    monkeypatch.setenv("AGENT_BOM_API_SCAN_ROOT", str(tmp_path))

    client = TestClient(app)
    resp = client.post("/v1/skills/scan", json={"files": ["SKILL.md"]}, headers=_SCAN_ALPHA)
    assert resp.status_code == 400, resp.text


def test_scan_requires_scan_permission(monkeypatch, tmp_path) -> None:
    set_skills_scan_store(InMemorySkillsScanStore())
    _seed_scan_root(tmp_path)
    _enable_local_scans(monkeypatch, tmp_path)

    client = TestClient(app)
    # A viewer (read-only) may not trigger a scan.
    resp = client.post("/v1/skills/scan", json={"files": ["SKILL.md"]}, headers=_READ_ALPHA)
    assert resp.status_code == 403, resp.text
