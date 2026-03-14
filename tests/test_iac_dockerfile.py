"""Tests for Dockerfile misconfiguration scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.iac.dockerfile import scan_dockerfile


@pytest.fixture()
def tmp_dockerfile(tmp_path: Path):
    """Helper to create a temporary Dockerfile with given content."""

    def _write(content: str, name: str = "Dockerfile") -> Path:
        p = tmp_path / name
        p.write_text(content)
        return p

    return _write


class TestDockerLatestTag:
    """DOCKER-001: FROM uses :latest or no tag."""

    def test_no_tag(self, tmp_dockerfile):
        findings = scan_dockerfile(tmp_dockerfile("FROM ubuntu\nRUN echo hi"))
        ids = [f.rule_id for f in findings]
        assert "DOCKER-001" in ids

    def test_latest_tag(self, tmp_dockerfile):
        findings = scan_dockerfile(tmp_dockerfile("FROM python:latest\nRUN echo hi"))
        docker001 = [f for f in findings if f.rule_id == "DOCKER-001"]
        assert len(docker001) >= 1
        assert "latest" in docker001[0].message.lower()

    def test_pinned_tag_no_finding(self, tmp_dockerfile):
        findings = scan_dockerfile(tmp_dockerfile("FROM python:3.12-slim\nUSER app\nHEALTHCHECK CMD true"))
        docker001 = [f for f in findings if f.rule_id == "DOCKER-001"]
        assert len(docker001) == 0

    def test_scratch_no_finding(self, tmp_dockerfile):
        findings = scan_dockerfile(tmp_dockerfile("FROM scratch\nCOPY app /app"))
        docker001 = [f for f in findings if f.rule_id == "DOCKER-001"]
        assert len(docker001) == 0


class TestDockerRootUser:
    """DOCKER-002: USER root or no USER directive."""

    def test_user_root(self, tmp_dockerfile):
        findings = scan_dockerfile(tmp_dockerfile("FROM python:3.12\nUSER root\nHEALTHCHECK CMD true"))
        docker002 = [f for f in findings if f.rule_id == "DOCKER-002"]
        assert any("root" in f.title.lower() for f in docker002)

    def test_no_user_directive(self, tmp_dockerfile):
        findings = scan_dockerfile(tmp_dockerfile("FROM python:3.12\nRUN echo hi\nHEALTHCHECK CMD true"))
        docker002 = [f for f in findings if f.rule_id == "DOCKER-002"]
        assert len(docker002) >= 1

    def test_nonroot_user_ok(self, tmp_dockerfile):
        findings = scan_dockerfile(tmp_dockerfile("FROM python:3.12\nUSER appuser\nHEALTHCHECK CMD true"))
        docker002 = [f for f in findings if f.rule_id == "DOCKER-002"]
        assert len(docker002) == 0


class TestDockerHardcodedSecrets:
    """DOCKER-003: Hardcoded secrets in ENV."""

    def test_secret_in_env(self, tmp_dockerfile):
        content = "FROM python:3.12\nENV API_KEY=sk-abc123456789\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker003 = [f for f in findings if f.rule_id == "DOCKER-003"]
        assert len(docker003) == 1
        assert docker003[0].severity == "critical"

    def test_normal_env_ok(self, tmp_dockerfile):
        content = "FROM python:3.12\nENV APP_PORT=8080\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker003 = [f for f in findings if f.rule_id == "DOCKER-003"]
        assert len(docker003) == 0


class TestDockerAdd:
    """DOCKER-004: ADD used instead of COPY."""

    def test_add_flagged(self, tmp_dockerfile):
        content = "FROM python:3.12\nADD . /app\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker004 = [f for f in findings if f.rule_id == "DOCKER-004"]
        assert len(docker004) == 1

    def test_copy_ok(self, tmp_dockerfile):
        content = "FROM python:3.12\nCOPY . /app\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker004 = [f for f in findings if f.rule_id == "DOCKER-004"]
        assert len(docker004) == 0


class TestDockerPipeInstall:
    """DOCKER-005: curl|sh or wget|bash."""

    def test_curl_pipe_sh(self, tmp_dockerfile):
        content = "FROM python:3.12\nRUN curl -fsSL https://example.com/install.sh | sh\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker005 = [f for f in findings if f.rule_id == "DOCKER-005"]
        assert len(docker005) == 1

    def test_wget_pipe_bash(self, tmp_dockerfile):
        content = "FROM python:3.12\nRUN wget -q https://example.com/setup | bash\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker005 = [f for f in findings if f.rule_id == "DOCKER-005"]
        assert len(docker005) == 1

    def test_normal_run_ok(self, tmp_dockerfile):
        content = "FROM python:3.12\nRUN pip install flask\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker005 = [f for f in findings if f.rule_id == "DOCKER-005"]
        assert len(docker005) == 0


class TestDockerHealthcheck:
    """DOCKER-006: No HEALTHCHECK directive."""

    def test_no_healthcheck(self, tmp_dockerfile):
        content = "FROM python:3.12\nUSER app"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker006 = [f for f in findings if f.rule_id == "DOCKER-006"]
        assert len(docker006) == 1
        assert docker006[0].severity == "low"

    def test_has_healthcheck(self, tmp_dockerfile):
        content = "FROM python:3.12\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nUSER app"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker006 = [f for f in findings if f.rule_id == "DOCKER-006"]
        assert len(docker006) == 0


class TestDockerPackageCache:
    """DOCKER-007: Package install without cache cleanup."""

    def test_apt_no_cache(self, tmp_dockerfile):
        content = "FROM python:3.12\nRUN apt-get install -y curl\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker007 = [f for f in findings if f.rule_id == "DOCKER-007"]
        assert len(docker007) == 1

    def test_apk_with_no_cache(self, tmp_dockerfile):
        content = "FROM alpine:3.18\nRUN apk add --no-cache curl\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker007 = [f for f in findings if f.rule_id == "DOCKER-007"]
        assert len(docker007) == 0


class TestDockerSSHPort:
    """DOCKER-008: Exposed port 22."""

    def test_ssh_port(self, tmp_dockerfile):
        content = "FROM python:3.12\nEXPOSE 22\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker008 = [f for f in findings if f.rule_id == "DOCKER-008"]
        assert len(docker008) == 1

    def test_normal_port_ok(self, tmp_dockerfile):
        content = "FROM python:3.12\nEXPOSE 8080\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker008 = [f for f in findings if f.rule_id == "DOCKER-008"]
        assert len(docker008) == 0


class TestDockerCopyDot:
    """DOCKER-009: COPY . . without .dockerignore."""

    def test_copy_dot_no_dockerignore(self, tmp_dockerfile):
        content = "FROM python:3.12\nCOPY . .\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker009 = [f for f in findings if f.rule_id == "DOCKER-009"]
        assert len(docker009) == 1

    def test_copy_dot_with_dockerignore(self, tmp_dockerfile):
        content = "FROM python:3.12\nCOPY . .\nUSER app\nHEALTHCHECK CMD true"
        p = tmp_dockerfile(content)
        (p.parent / ".dockerignore").write_text(".git\n.env\n")
        findings = scan_dockerfile(p)
        docker009 = [f for f in findings if f.rule_id == "DOCKER-009"]
        assert len(docker009) == 0


class TestDockerUnpinnedDigest:
    """DOCKER-010: FROM without digest pin."""

    def test_no_digest(self, tmp_dockerfile):
        content = "FROM python:3.12-slim\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker010 = [f for f in findings if f.rule_id == "DOCKER-010"]
        assert len(docker010) >= 1

    def test_with_digest(self, tmp_dockerfile):
        content = "FROM python@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890\nUSER app\nHEALTHCHECK CMD true"
        findings = scan_dockerfile(tmp_dockerfile(content))
        docker010 = [f for f in findings if f.rule_id == "DOCKER-010"]
        assert len(docker010) == 0


class TestDockerCompliance:
    """All findings have compliance tags."""

    def test_compliance_tags(self, tmp_dockerfile):
        content = "FROM ubuntu\nRUN apt-get install -y curl\nADD . /app\nEXPOSE 22"
        findings = scan_dockerfile(tmp_dockerfile(content))
        for f in findings:
            assert len(f.compliance) > 0, f"Finding {f.rule_id} has no compliance tags"
            assert f.category == "dockerfile"


class TestDockerSeverities:
    """Verify severity levels match the spec."""

    def test_severity_levels(self, tmp_dockerfile):
        content = "FROM ubuntu\nENV API_KEY=sk-verylongsecretvalue123\nADD . /app\nRUN curl https://x.com/i | sh\nEXPOSE 22\n"
        findings = scan_dockerfile(tmp_dockerfile(content))
        by_id = {f.rule_id: f.severity for f in findings}
        assert by_id.get("DOCKER-001") == "high"
        assert by_id.get("DOCKER-003") == "critical"
        assert by_id.get("DOCKER-004") == "medium"
        assert by_id.get("DOCKER-005") == "medium"
        assert by_id.get("DOCKER-008") == "medium"
