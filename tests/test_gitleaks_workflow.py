from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "gitleaks.yml"


def test_gitleaks_scans_event_git_ranges_without_github_api_dependency() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "gitleaks/gitleaks-action@" not in workflow
    assert "GITHUB_TOKEN" not in workflow
    assert "GITLEAKS_LICENSE" not in workflow
    assert "GITLEAKS_ENABLE_COMMENTS" not in workflow
    assert "GITLEAKS_ENABLE_UPLOAD_ARTIFACT" not in workflow
    assert "github.event.pull_request.base.sha" in workflow
    assert "github.event.pull_request.head.sha" in workflow
    assert "github.event.before" in workflow
    assert "git cat-file -e" in workflow
    assert "--log-opts" in workflow


def test_gitleaks_binary_and_scan_contract_are_fail_closed() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "timeout-minutes: 15" in workflow
    assert "fetch-depth: 0" in workflow
    assert "persist-credentials: false" in workflow
    assert 'GITLEAKS_VERSION: "8.24.3"' in workflow
    assert 'GITLEAKS_ARCHIVE_SHA256: "9991e0b2903da4c8f6122b5c3186448b927a5da4deef1fe45271c3793f4ee29c"' in workflow
    assert "https://github.com/gitleaks/gitleaks/releases/download/" in workflow
    assert "sha256sum --check --strict" in workflow
    assert "set -euo pipefail" in workflow
    assert "--config .gitleaks.toml" in workflow
    assert "--gitleaks-ignore-path .gitleaksignore" in workflow
    assert "--redact=100" in workflow
