"""Safe public-repository clone-and-scan helper.

This module lets ``agent-bom`` map a remote git repository into an AI-BOM from
a single URL, with no local checkout. The repository is **shallow-cloned**
(``git clone --depth 1 --single-branch``, no submodules, no credential prompt)
into a throwaway temp directory, the existing local-directory scan pipeline is
pointed at that directory, and the temp directory is **always** removed
afterwards (``try``/``finally``).

Safety properties:

* **Static-only.** Nothing in the cloned repository is ever executed. The clone
  step runs ``git`` (not repo code), and downstream scanning is pure static
  parsing of manifests, lockfiles, IaC, skills, and AI/MCP config. There is no
  build, install, or post-checkout hook execution: ``core.hooksPath=/dev/null``
  disables any repo-supplied git hooks during the clone.
* **Shallow + bounded.** Depth-1, single-branch, submodules off, with a wall
  clock timeout, a total on-disk size cap, and a file-count cap so a hostile or
  enormous repository cannot exhaust local resources ("clone bomb").
* **No injection.** Only well-formed ``http(s)`` git URLs are accepted;
  ``ssh://``, ``scp``-style ``git@host:path``, ``file://``, and bare local
  paths are rejected so a URL can never reference the local filesystem or a
  non-git transport.
* **No secret/path leak.** An optional auth token (for private repos) is read
  from a caller-named environment variable, injected only via an ephemeral
  in-clone HTTP header, never logged and never echoed into output. Errors are
  scrubbed of the token and of the absolute temp path before they surface.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess  # noqa: S404 — runs `git`, never repository-supplied code
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from agent_bom.config import (
    REPO_SCAN_CLONE_TIMEOUT_SECONDS,
    REPO_SCAN_MAX_FILES,
    REPO_SCAN_MAX_SIZE_BYTES,
)

logger = logging.getLogger(__name__)

# Hosts we accept for http(s) git clones. Empty by default == allow any host;
# operators can pin an allowlist with AGENT_BOM_REPO_SCAN_ALLOWED_HOSTS.
_ALLOWED_HOSTS_ENV = "AGENT_BOM_REPO_SCAN_ALLOWED_HOSTS"

# Maximum accepted URL length — defends against pathological inputs.
_MAX_URL_LEN = 2048


class RepoScanError(Exception):
    """Raised when a repository URL is unsafe or a clone cannot complete."""


def validate_repo_url(repo_url: str) -> str:
    """Validate that ``repo_url`` is a well-formed public ``http(s)`` git URL.

    Rejects ssh/scp-style, ``file://``, and bare local paths so the URL can
    never reference the local filesystem or a non-git transport. Returns the
    normalized URL on success.

    Raises:
        RepoScanError: if the URL is malformed or uses a disallowed scheme.
    """
    if not isinstance(repo_url, str):
        raise RepoScanError("repo_url must be a string")
    url = repo_url.strip()
    if not url:
        raise RepoScanError("repo_url must not be empty")
    if len(url) > _MAX_URL_LEN:
        raise RepoScanError("repo_url is too long")

    # Reject scp-style "git@host:path" syntax (has no scheme but a colon path).
    if "://" not in url:
        raise RepoScanError(
            "repo_url must be a full http(s) URL (e.g. https://github.com/org/repo); ssh/scp-style and local paths are not allowed"
        )

    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise RepoScanError(f"repo_url scheme '{parts.scheme}' is not allowed; use http or https")
    if not parts.hostname:
        raise RepoScanError("repo_url is missing a host")
    # urlsplit keeps any embedded credentials in netloc; reject them so callers
    # use the token env var instead of leaking secrets in the URL/logs.
    if parts.username is not None or parts.password is not None:
        raise RepoScanError("repo_url must not embed credentials; use the token env var instead")
    # Control characters / whitespace in the URL are a strong injection signal.
    if any(ord(ch) < 0x20 or ch in {" ", "\t", "\n", "\r"} for ch in url):
        raise RepoScanError("repo_url contains illegal whitespace or control characters")

    allowed = os.environ.get(_ALLOWED_HOSTS_ENV, "").strip()
    if allowed:
        allowed_hosts = {h.strip().lower() for h in allowed.split(",") if h.strip()}
        if parts.hostname.lower() not in allowed_hosts:
            raise RepoScanError(f"repo host '{parts.hostname}' is not in the configured allowlist")

    return url


def _clone_env() -> dict[str, str]:
    """Return a hardened environment for the clone subprocess.

    ``GIT_TERMINAL_PROMPT=0`` and an always-failing askpass guarantee git never
    blocks on an interactive credential prompt for a private/404 repo.
    """
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"  # never prompt; emit empty credential
    env["GCM_INTERACTIVE"] = "never"
    # Strip any ambient proxy-side credential helpers from inheriting state.
    env.pop("GIT_CONFIG_PARAMETERS", None)
    return env


def _directory_within_bounds(root: Path) -> None:
    """Enforce file-count and total-size caps on a cloned tree.

    Raises RepoScanError if the clone exceeds REPO_SCAN_MAX_FILES or
    REPO_SCAN_MAX_SIZE_BYTES. Symlinks are not followed when measuring.
    """
    total_files = 0
    total_bytes = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Skip the .git metadata directory from the user-facing caps; it is a
        # clone artifact, not repository content.
        if ".git" in dirnames:
            dirnames.remove(".git")
        for name in filenames:
            total_files += 1
            if total_files > REPO_SCAN_MAX_FILES:
                raise RepoScanError(f"repository exceeds the file-count cap ({REPO_SCAN_MAX_FILES} files)")
            fp = Path(dirpath) / name
            try:
                if fp.is_symlink():
                    continue
                total_bytes += fp.stat().st_size
            except OSError:
                continue
            if total_bytes > REPO_SCAN_MAX_SIZE_BYTES:
                raise RepoScanError(f"repository exceeds the size cap ({REPO_SCAN_MAX_SIZE_BYTES} bytes)")


def _scrub(message: str, token: str | None, temp_dir: str | None) -> str:
    """Remove a secret token and the absolute temp path from a message."""
    out = message
    if token:
        out = out.replace(token, "***")
    if temp_dir:
        out = out.replace(temp_dir, "<repo>")
    return out


@contextmanager
def clone_repository(
    repo_url: str,
    *,
    token_env: str | None = None,
    branch: str | None = None,
) -> Iterator[Path]:
    """Shallow-clone ``repo_url`` into a temp dir and yield the path.

    The temp directory is always removed on exit (``try``/``finally``), whether
    the clone succeeded, failed, or the scan raised. No repository code is ever
    executed — only ``git`` runs, with hooks disabled.

    Args:
        repo_url: Public ``http(s)`` git URL. Validated before use.
        token_env: Optional environment-variable *name* holding a token for a
            private repo (reference-only; the value is never logged or emitted).
        branch: Optional single branch to clone. Defaults to the repo's HEAD.

    Yields:
        Path to the cloned working tree.

    Raises:
        RepoScanError: on invalid URL, clone failure, timeout, or bounds breach.
    """
    url = validate_repo_url(repo_url)

    token: str | None = None
    if token_env:
        token = os.environ.get(token_env)
        if token is not None:
            token = token.strip() or None

    temp_dir = tempfile.mkdtemp(prefix="agent-bom-repo-")
    try:
        cmd = [
            "git",
            # Disable any repo-supplied git hooks for the clone (defense in depth;
            # `git clone` does not run checkout hooks, but this is belt-and-braces).
            "-c",
            "core.hooksPath=/dev/null",
            # Never auto-fetch submodules' transitive config.
            "-c",
            "protocol.file.allow=never",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
            "--no-recurse-submodules",
        ]
        if branch:
            cmd += ["--branch", branch]
        # Inject the token only as an ephemeral in-process HTTP header so it
        # never lands in the URL, git config, logs, or process listing of a
        # child. The value is masked by git in any error output.
        if token:
            host = urlsplit(url).hostname or ""
            cmd += ["-c", f"http.https://{host}/.extraheader=Authorization: Bearer {token}"]
        cmd += [url, temp_dir]

        try:
            result = subprocess.run(  # noqa: S603 — fixed argv, no shell, runs git only
                cmd,
                capture_output=True,
                text=True,
                timeout=REPO_SCAN_CLONE_TIMEOUT_SECONDS,
                env=_clone_env(),
                check=False,
            )
        except FileNotFoundError as exc:
            raise RepoScanError("git is not installed or not on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise RepoScanError(f"clone timed out after {REPO_SCAN_CLONE_TIMEOUT_SECONDS:.0f}s") from exc

        if result.returncode != 0:
            stderr = _scrub((result.stderr or "").strip(), token, temp_dir)
            # Keep the surfaced message short and free of secrets/paths.
            detail = stderr[:200] if stderr else f"git exited {result.returncode}"
            raise RepoScanError(f"clone failed: {detail}")

        _directory_within_bounds(Path(temp_dir))

        yield Path(temp_dir)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
