"""The public package replay must execute the parser and scanner with bounded claims."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_replay_records_real_advisory_before_and_after_without_deployment_claim(tmp_path: Path) -> None:
    output = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/replay_package_remediation.py"), "--output", str(output)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(output.read_text())
    assert payload["schema_version"] == "agent-bom.package-remediation-replay/v1"
    assert payload["advisory"] == "CVE-2023-4863"
    assert payload["coverage"] == "bundled_pinned_advisories_only"
    assert payload["deployed_remediation"] == "not_tested"
    assert payload["exploit_execution"] == "not_performed"
    assert payload["package_installation"] == "not_performed"
    assert payload["before"]["matched"] is True
    assert payload["after"]["matched"] is False
    for stage, version in (("before", "9.0.0"), ("after", "10.0.1")):
        receipt = payload[stage]
        assert receipt["package"] == f"pkg:pypi/pillow@{version}"
        assert receipt["manifest_sha256"] == "sha256:" + hashlib.sha256(f"Pillow=={version}\n".encode()).hexdigest()
    assert not (tmp_path / "requirements.txt").exists()
