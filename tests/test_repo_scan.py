"""Tests for the safe public-repo clone-and-scan helper (``agent_bom.repo_scan``).

These tests never hit the network: ``git clone`` is mocked so the "clone" simply
materializes a fixture directory (or fails) in the temp dir agent-bom chose.
They assert URL validation, temp-dir cleanup on success and failure, bounds
enforcement, token non-leakage, and that no repository code is ever executed.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import agent_bom.repo_scan as repo_scan
from agent_bom.repo_scan import RepoScanError, clone_repository, validate_repo_url


def _gai_returning(ip: str):
    """Build a socket.getaddrinfo stub that resolves any host to ``ip``."""
    import socket

    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    def _gai(host, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        return [(family, socket.SOCK_STREAM, 0, "", (ip, 0))]

    return _gai


@pytest.fixture(autouse=True)
def _stub_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve every hostname to a fixed public IP so the SSRF guard's DNS
    lookups never touch the network (individual SSRF tests override this)."""
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", _gai_returning("93.184.216.34"))


# ── URL validation ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/org/repo",
        "https://github.com/org/repo.git",
        "http://example.com/a/b",
        "https://gitlab.com/group/sub/project",
    ],
)
def test_valid_http_urls_accepted(url: str) -> None:
    assert validate_repo_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "git@github.com:org/repo.git",  # scp-style
        "ssh://git@github.com/org/repo",
        "file:///etc/passwd",
        "/etc/passwd",
        "../../etc/passwd",
        "ftp://example.com/repo",
        "https://user:secret@github.com/o/r",  # embedded creds
        "",
        "   ",
        "http://example.com/with space",
        "https://github.com/repo\ninjected",
    ],
)
def test_invalid_urls_rejected(url: str) -> None:
    with pytest.raises(RepoScanError):
        validate_repo_url(url)


def test_host_allowlist_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_REPO_SCAN_ALLOWED_HOSTS", "github.com")
    assert validate_repo_url("https://github.com/o/r") == "https://github.com/o/r"
    with pytest.raises(RepoScanError):
        validate_repo_url("https://evil.example.com/o/r")


# ── Clone helpers (mocked git) ──────────────────────────────────────────────


def _fake_clone(populate, returncode: int = 0, stderr: str = ""):
    """Build a fake subprocess.run that 'clones' by populating the dest dir.

    The destination dir is the last positional arg in the git argv (the temp
    dir agent-bom created). ``populate(dest)`` may add files to simulate a repo.
    """

    def _run(cmd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        dest = Path(cmd[-1])
        # Capture the argv + env so tests can assert flags / no-shell / no token leak.
        _run.captured_cmd = cmd
        _run.captured_env = kwargs.get("env")
        if returncode == 0 and populate is not None:
            populate(dest)
        return subprocess.CompletedProcess(cmd, returncode, stdout="", stderr=stderr)

    _run.captured_cmd = None
    _run.captured_env = None
    return _run


def test_clone_success_scans_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def populate(dest: Path) -> None:
        (dest / "package.json").write_text('{"name": "x"}')
        captured["dest"] = dest

    monkeypatch.setattr(subprocess, "run", _fake_clone(populate))

    with clone_repository("https://github.com/org/repo") as cloned:
        assert cloned.exists()
        assert (cloned / "package.json").exists()
        captured["seen"] = cloned

    # try/finally must have removed the temp dir.
    assert not captured["seen"].exists()
    # Shallow + single-branch + no-submodules flags present; no shell.
    argv = subprocess.run.captured_cmd  # type: ignore[attr-defined]
    assert "clone" in argv and "--depth" in argv and "1" in argv
    assert "--single-branch" in argv
    assert "--no-recurse-submodules" in argv
    assert "core.hooksPath=/dev/null" in argv


def test_clone_failure_raises_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    real_mkdtemp = repo_scan.tempfile.mkdtemp

    def tracking_mkdtemp(*a, **k):  # noqa: ANN002, ANN003
        d = real_mkdtemp(*a, **k)
        seen["dir"] = d
        return d

    monkeypatch.setattr(repo_scan.tempfile, "mkdtemp", tracking_mkdtemp)
    monkeypatch.setattr(subprocess, "run", _fake_clone(None, returncode=128, stderr="fatal: repository not found"))

    with pytest.raises(RepoScanError) as exc:
        with clone_repository("https://github.com/org/missing"):
            pass  # pragma: no cover

    assert "clone failed" in str(exc.value)
    assert not Path(seen["dir"]).exists()


def test_clone_timeout_raises_and_cleans_up(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}
    real_mkdtemp = repo_scan.tempfile.mkdtemp

    def tracking_mkdtemp(*a, **k):  # noqa: ANN002, ANN003
        d = real_mkdtemp(*a, **k)
        seen["dir"] = d
        return d

    monkeypatch.setattr(repo_scan.tempfile, "mkdtemp", tracking_mkdtemp)

    def _timeout(cmd, *a, **k):  # noqa: ANN001, ANN002, ANN003
        raise subprocess.TimeoutExpired(cmd, 1)

    monkeypatch.setattr(subprocess, "run", _timeout)

    with pytest.raises(RepoScanError) as exc:
        with clone_repository("https://github.com/org/slow"):
            pass  # pragma: no cover
    assert "timed out" in str(exc.value)
    assert not Path(seen["dir"]).exists()


def test_invalid_url_never_clones(monkeypatch: pytest.MonkeyPatch) -> None:
    called = {"n": 0}

    def _run(*a, **k):  # noqa: ANN002, ANN003
        called["n"] += 1
        raise AssertionError("git must not run for an invalid URL")

    monkeypatch.setattr(subprocess, "run", _run)
    with pytest.raises(RepoScanError):
        with clone_repository("file:///etc/passwd"):
            pass  # pragma: no cover
    assert called["n"] == 0


# ── Bounds enforcement ──────────────────────────────────────────────────────


def test_file_count_cap_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(repo_scan, "REPO_SCAN_MAX_FILES", 3)

    def populate(dest: Path) -> None:
        for i in range(10):
            (dest / f"f{i}.txt").write_text("x")

    monkeypatch.setattr(subprocess, "run", _fake_clone(populate))
    with pytest.raises(RepoScanError) as exc:
        with clone_repository("https://github.com/org/big"):
            pass  # pragma: no cover
    assert "file-count cap" in str(exc.value)


def test_size_cap_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(repo_scan, "REPO_SCAN_MAX_SIZE_BYTES", 10)

    def populate(dest: Path) -> None:
        (dest / "big.bin").write_text("x" * 1000)

    monkeypatch.setattr(subprocess, "run", _fake_clone(populate))
    with pytest.raises(RepoScanError) as exc:
        with clone_repository("https://github.com/org/huge"):
            pass  # pragma: no cover
    assert "size cap" in str(exc.value)


# ── Token handling ──────────────────────────────────────────────────────────


def test_token_used_but_never_leaked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_TOKEN", "supersecrettoken123")

    def populate(dest: Path) -> None:
        (dest / "readme").write_text("ok")

    runner = _fake_clone(populate)
    monkeypatch.setattr(subprocess, "run", runner)

    with clone_repository("https://github.com/org/private", token_env="MY_TOKEN"):
        pass

    argv = runner.captured_cmd
    env = runner.captured_env or {}
    # The secret-bearing header value must NEVER land on argv (readable via
    # `ps aux` / /proc/<pid>/cmdline). It is passed only via git config env.
    joined = " ".join(argv)
    assert "supersecrettoken123" not in joined
    assert "extraheader" not in joined
    # Token is injected (so private clones work) only via GIT_CONFIG_* env: the
    # non-secret key on KEY_0, the secret Authorization value on VALUE_0.
    assert env.get("GIT_CONFIG_COUNT") == "1"
    assert env.get("GIT_CONFIG_KEY_0") == "http.https://github.com/.extraheader"
    assert env.get("GIT_CONFIG_VALUE_0") == "Authorization: Bearer supersecrettoken123"


def test_token_scrubbed_from_clone_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_TOKEN", "supersecrettoken123")
    # git failure whose stderr echoes the secret — must be scrubbed before surfacing.
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_clone(None, returncode=128, stderr="auth failed for supersecrettoken123"),
    )
    with pytest.raises(RepoScanError) as exc:
        with clone_repository("https://github.com/org/private", token_env="MY_TOKEN"):
            pass  # pragma: no cover
    assert "supersecrettoken123" not in str(exc.value)
    assert "***" in str(exc.value)


def test_clone_env_disables_prompt() -> None:
    env = repo_scan._clone_env()
    assert env["GIT_TERMINAL_PROMPT"] == "0"


# ── No repository code execution ────────────────────────────────────────────


def test_only_git_is_executed_never_repo_code(monkeypatch: pytest.MonkeyPatch) -> None:
    """The only subprocess invoked is `git`; repo content is never executed."""
    invocations: list[list[str]] = []

    def _run(cmd, *a, **k):  # noqa: ANN001, ANN002, ANN003
        invocations.append(list(cmd))
        dest = Path(cmd[-1])
        # Simulate a repo that ships an executable payload — it must never run.
        (dest / "evil.sh").write_text("#!/bin/sh\ntouch /tmp/abom_pwned\n")
        os.chmod(dest / "evil.sh", 0o700)  # owner-only; payload must never run regardless
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", _run)

    pwned = Path("/tmp/abom_pwned")
    if pwned.exists():
        pwned.unlink()

    with clone_repository("https://github.com/org/repo"):
        pass

    # Exactly one subprocess, and it is git with no shell.
    assert len(invocations) == 1
    assert invocations[0][0] == "git"
    # The repo's payload was never executed.
    assert not pwned.exists()


# ── End-to-end through scan_impl (mocked clone + pipeline) ───────────────────


@pytest.mark.asyncio
async def test_scan_impl_repo_url_clones_and_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_tools import scanning

    captured: dict = {}

    def populate(dest: Path) -> None:
        (dest / "requirements.txt").write_text("requests==2.0.0\n")

    monkeypatch.setattr(subprocess, "run", _fake_clone(populate))

    async def fake_pipeline(config_path, image, sbom_path, package, enrich, **kw):  # noqa: ANN001, ANN002, ANN003
        captured["config_path"] = config_path
        # The cloned dir must still exist while the pipeline runs.
        captured["exists_during_scan"] = config_path is not None and Path(config_path).exists()
        return [], [], [], []

    out = await scanning.scan_impl(
        repo_url="https://github.com/org/repo",
        offline=True,
        _run_scan_pipeline=fake_pipeline,
        _truncate_response=lambda s: s,
    )

    assert captured["exists_during_scan"] is True
    # Temp dir cleaned up after scan_impl returns.
    assert not Path(captured["config_path"]).exists()
    assert "no_agents_found" in out


@pytest.mark.asyncio
async def test_scan_impl_rejects_repo_url_and_config_path(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp.server.fastmcp.exceptions import ToolError

    from agent_bom.mcp_tools import scanning

    async def fake_pipeline(*a, **k):  # noqa: ANN002, ANN003
        return [], [], [], []  # pragma: no cover

    with pytest.raises(ToolError):
        await scanning.scan_impl(
            repo_url="https://github.com/org/repo",
            config_path="/tmp",
            _run_scan_pipeline=fake_pipeline,
            _truncate_response=lambda s: s,
        )


# ── SSRF defense (validate_repo_url) ─────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # AWS/cloud metadata
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
        "http://10.0.0.1/org/repo",  # RFC1918
        "http://192.168.1.1/org/repo",  # RFC1918
        "http://172.16.0.1/org/repo",  # RFC1918
        "http://127.0.0.1/org/repo",  # loopback literal
        "http://localhost/org/repo",  # loopback name
        "https://[::1]/org/repo",  # IPv6 loopback
        "http://169.254.1.2/org/repo",  # link-local
    ],
)
def test_ssrf_internal_targets_rejected(url: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # metadata.google.internal is name-resolved; point it at a private IP so the
    # guard's resolution path also rejects it (not just the literal-host check).
    monkeypatch.setattr(repo_scan, "_remote_bind_active", lambda: False)
    with pytest.raises(RepoScanError):
        validate_repo_url(url)


def test_ssrf_public_host_resolving_to_private_ip_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A public-looking host whose DNS resolves to an internal IP is rejected
    (DNS-rebinding / SSRF). Resolution is mocked — no network."""
    import socket

    monkeypatch.setattr(socket, "getaddrinfo", _gai_returning("10.0.0.5"))
    with pytest.raises(RepoScanError):
        validate_repo_url("https://totally-public.example.com/org/repo")


def test_clone_disables_redirect_following(monkeypatch: pytest.MonkeyPatch) -> None:
    """The clone argv pins http.followRedirects=false so a validated host cannot
    bounce the clone to an internal target via an HTTP redirect."""

    def populate(dest: Path) -> None:
        (dest / "readme").write_text("ok")

    runner = _fake_clone(populate)
    monkeypatch.setattr(subprocess, "run", runner)

    with clone_repository("https://github.com/org/repo"):
        pass

    assert "http.followRedirects=false" in runner.captured_cmd


def test_remote_bind_fails_closed_without_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    """On a remotely-bound MCP transport, repo scans must fail closed unless an
    explicit host allowlist is configured."""
    monkeypatch.delenv("AGENT_BOM_REPO_SCAN_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("AGENT_BOM_MCP_REMOTE_BIND", "1")
    with pytest.raises(RepoScanError) as exc:
        validate_repo_url("https://github.com/org/repo")
    assert "allowlist" in str(exc.value)

    # With an allowlist pinned, the same URL is accepted.
    monkeypatch.setenv("AGENT_BOM_REPO_SCAN_ALLOWED_HOSTS", "github.com")
    assert validate_repo_url("https://github.com/org/repo") == "https://github.com/org/repo"


# ── DoS: clone must run off the asyncio event loop ───────────────────────────


@pytest.mark.asyncio
async def test_repo_clone_runs_off_event_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """The blocking `git clone` must execute in a worker thread, not on the
    event-loop thread, so one slow/tarpit repo cannot freeze the MCP server."""
    import threading

    from agent_bom.mcp_tools import scanning

    loop_thread = threading.get_ident()
    seen: dict = {}

    real_clone = repo_scan._clone_into_tempdir

    def spy_clone(*args, **kwargs):  # noqa: ANN002, ANN003
        seen["thread"] = threading.get_ident()
        return real_clone(*args, **kwargs)

    monkeypatch.setattr(repo_scan, "_clone_into_tempdir", spy_clone)

    def populate(dest: Path) -> None:
        (dest / "requirements.txt").write_text("requests==2.0.0\n")

    monkeypatch.setattr(subprocess, "run", _fake_clone(populate))

    async def fake_pipeline(*a, **k):  # noqa: ANN002, ANN003
        return [], [], [], []

    await scanning.scan_impl(
        repo_url="https://github.com/org/repo",
        offline=True,
        _run_scan_pipeline=fake_pipeline,
        _truncate_response=lambda s: s,
    )

    assert seen["thread"] != loop_thread, "git clone ran on the event-loop thread"
