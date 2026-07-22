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
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any
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

# Set by the `mcp server` CLI when it binds an SSE / streamable-http transport
# to a non-loopback host. When the MCP server is internet-reachable we fail
# closed on repo scans unless an explicit host allowlist is configured, so an
# attacker cannot point the clone at internal / cloud-metadata targets.
_REMOTE_BIND_ENV = "AGENT_BOM_MCP_REMOTE_BIND"


def _remote_bind_active() -> bool:
    """True when the MCP server is bound to a remote (non-loopback) transport."""
    return os.environ.get(_REMOTE_BIND_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


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
    elif _remote_bind_active():
        # Fail closed on an internet-reachable MCP transport: refuse to clone
        # arbitrary hosts unless the operator pins an explicit allowlist. Mirrors
        # _enforce_remote_mcp_auth_defaults' posture for remote binds.
        raise RepoScanError(
            f"{_ALLOWED_HOSTS_ENV} must be set to an explicit host allowlist before "
            "scanning repositories on a remotely-bound MCP server"
        )

    # SSRF defense: reject IP-literal private hosts and hostnames that resolve to
    # internal / cloud-metadata targets. Reuses the shared egress guard applied on
    # every other outbound path (loopback / RFC1918 / link-local / ULA / reserved /
    # metadata), which resolves every A/AAAA record and is DNS-rebinding aware.
    from agent_bom.security import SecurityError, validate_url

    try:
        validate_url(url, allowed_schemes=("http", "https"))
    except SecurityError as exc:
        raise RepoScanError(f"repo_url is not allowed: {exc}") from exc

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
    # Strip ambient GIT_CONFIG_* env config so inherited values can neither
    # collide with nor bypass the ephemeral extraheader injected below.
    for key in [k for k in env if k.startswith("GIT_CONFIG_")]:
        env.pop(key, None)
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


def _clone_into_tempdir(
    repo_url: str,
    *,
    token_env: str | None = None,
    branch: str | None = None,
) -> str:
    """Validate, shallow-clone into a fresh temp dir, enforce bounds; return it.

    This is the **blocking** core of a repo clone (it runs ``git`` and walks the
    tree). The caller owns cleanup of the returned directory on success; on any
    failure the temp dir is removed here before the error propagates.

    Returns:
        Absolute path to the cloned working tree (caller must ``rmtree`` it).

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
            # Never follow HTTP redirects: a validated public host must not be
            # able to bounce the clone to an internal / cloud-metadata target.
            "-c",
            "http.followRedirects=false",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
            "--no-recurse-submodules",
        ]
        if branch:
            cmd += ["--branch", branch]
        cmd += [url, temp_dir]

        # Inject the token only as an ephemeral in-process HTTP header. The
        # secret-bearing value is passed via the git config *environment*
        # (GIT_CONFIG_COUNT/KEY/VALUE), never on argv — so it cannot be read
        # from `ps aux` or /proc/<pid>/cmdline of the child. The value is
        # masked by git in any error output.
        env = _clone_env()
        if token:
            host = urlsplit(url).hostname or ""
            env["GIT_CONFIG_COUNT"] = "1"
            env["GIT_CONFIG_KEY_0"] = f"http.https://{host}/.extraheader"
            env["GIT_CONFIG_VALUE_0"] = f"Authorization: Bearer {token}"

        try:
            result = subprocess.run(  # noqa: S603 — fixed argv, no shell, runs git only
                cmd,
                capture_output=True,
                text=True,
                timeout=REPO_SCAN_CLONE_TIMEOUT_SECONDS,
                env=env,
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
        return temp_dir
    except BaseException:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


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
    temp_dir = _clone_into_tempdir(repo_url, token_env=token_env, branch=branch)
    try:
        yield Path(temp_dir)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@asynccontextmanager
async def clone_repository_async(
    repo_url: str,
    *,
    token_env: str | None = None,
    branch: str | None = None,
) -> AsyncIterator[Path]:
    """Async wrapper for :func:`clone_repository`.

    The blocking ``git clone`` (and the temp-dir teardown) run in a worker thread
    via ``asyncio.to_thread`` so a slow or tarpit repository cannot freeze the
    asyncio event loop — the surrounding MCP tool timeout stays effective and the
    server keeps serving other callers while a clone is in flight.
    """
    import asyncio

    temp_dir = await asyncio.to_thread(_clone_into_tempdir, repo_url, token_env=token_env, branch=branch)
    try:
        yield Path(temp_dir)
    finally:
        await asyncio.to_thread(shutil.rmtree, temp_dir, ignore_errors=True)


# ── Optional GitHub trust card (read-only metadata; never required for scan) ─

_GITHUB_API = "https://api.github.com"
_TRUST_DESC_MAX = 280
_TRUST_TIMEOUT_S = 8.0


def parse_github_owner_repo(repo_url: str) -> tuple[str, str] | None:
    """Return ``(owner, repo)`` for a github.com git URL, else ``None``.

    Accepts ``https://github.com/org/repo``, ``…/repo.git``, and deeper paths
    (only the first two path segments are used). Non-GitHub hosts return ``None``.
    """
    try:
        url = validate_repo_url(repo_url)
    except RepoScanError:
        return None
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host not in {"github.com", "www.github.com"}:
        return None
    segments = [s for s in (parts.path or "").split("/") if s]
    if len(segments) < 2:
        return None
    owner, name = segments[0], segments[1]
    if name.endswith(".git"):
        name = name[: -len(".git")]
    if not owner or not name or owner.startswith(".") or name.startswith("."):
        return None
    return owner, name


def _trust_token(token_env: str | None) -> str | None:
    if not token_env:
        return None
    raw = os.environ.get(token_env)
    if raw is None:
        return None
    text = raw.strip()
    return text or None


def _trust_disabled() -> bool:
    from agent_bom.config import REPO_TRUST_ENABLED

    return not REPO_TRUST_ENABLED


def _api_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "agent-bom-repo-trust",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _clip_text(value: object, *, limit: int = _TRUST_DESC_MAX) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _contributor_count(owner: str, repo: str, *, token: str | None) -> int | None:
    """Best-effort contributor count via the contributors list + Link header."""
    from agent_bom.http_client import sync_get
    from agent_bom.security import SecurityError, validate_url

    url = f"{_GITHUB_API}/repos/{owner}/{repo}/contributors"
    try:
        validate_url(url, allowed_schemes=("https",))
    except SecurityError:
        return None
    try:
        resp = sync_get(
            url,
            timeout=_TRUST_TIMEOUT_S,
            headers=_api_headers(token),
            params={"per_page": "1", "anon": "true"},
        )
    except Exception:  # noqa: BLE001 — trust card is best-effort
        return None
    if resp is None or resp.status_code != 200:
        return None
    link = resp.headers.get("Link") or resp.headers.get("link") or ""
    # rel="last" page=N is the total when per_page=1
    import re

    match = re.search(r'[?&]page=(\d+)>;\s*rel="last"', link)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    try:
        payload = resp.json()
    except Exception:  # noqa: BLE001
        return None
    if isinstance(payload, list):
        return len(payload)
    return None


def fetch_repo_trust(
    repo_url: str,
    *,
    token_env: str | None = "AGENT_BOM_REPO_SCAN_TOKEN",
) -> dict[str, Any] | None:
    """Fetch a read-only GitHub trust card for ``repo_url``.

    Uses the same optional token as clone (``AGENT_BOM_REPO_SCAN_TOKEN``) for
    private repos and higher API rate limits. Never raises — returns ``None`` when
    disabled, non-GitHub, offline failure, or the API is unavailable. The scan
    itself must not depend on this metadata.
    """
    if _trust_disabled():
        return None
    parsed = parse_github_owner_repo(repo_url)
    if parsed is None:
        # Still record that we saw a repo URL so UI/CLI can show the source
        # without inventing GitHub fields for GitLab/Bitbucket/etc.
        try:
            url = validate_repo_url(repo_url)
        except RepoScanError:
            return None
        host = (urlsplit(url).hostname or "").lower()
        return {
            "status": "unsupported_host",
            "repo_url": url,
            "host": host,
            "provider": host,
        }

    owner, repo = parsed
    token = _trust_token(token_env)
    api_url = f"{_GITHUB_API}/repos/{owner}/{repo}"

    from agent_bom.http_client import fetch_json
    from agent_bom.security import SecurityError, validate_url

    try:
        validate_url(api_url, allowed_schemes=("https",))
        payload = fetch_json(api_url, timeout=_TRUST_TIMEOUT_S, headers=_api_headers(token))
    except (SecurityError, ConnectionError, OSError, ValueError, TimeoutError) as exc:
        logger.debug("repo trust fetch skipped: %s", type(exc).__name__)
        return {
            "status": "unavailable",
            "repo_url": f"https://github.com/{owner}/{repo}",
            "host": "github.com",
            "provider": "github",
            "owner": owner,
            "name": repo,
            "full_name": f"{owner}/{repo}",
        }
    except Exception:  # noqa: BLE001
        logger.debug("repo trust fetch failed", exc_info=True)
        return {
            "status": "unavailable",
            "repo_url": f"https://github.com/{owner}/{repo}",
            "host": "github.com",
            "provider": "github",
            "owner": owner,
            "name": repo,
            "full_name": f"{owner}/{repo}",
        }

    if not isinstance(payload, dict):
        return None

    license_info = payload.get("license") if isinstance(payload.get("license"), dict) else {}
    license_spdx = ""
    if isinstance(license_info, dict):
        license_spdx = str(license_info.get("spdx_id") or license_info.get("key") or "").strip()

    topics = payload.get("topics")
    topic_list = [str(t) for t in topics if isinstance(t, str)] if isinstance(topics, list) else []

    contributors = _contributor_count(owner, repo, token=token)

    card: dict[str, Any] = {
        "status": "ok",
        "provider": "github",
        "host": "github.com",
        "repo_url": str(payload.get("html_url") or f"https://github.com/{owner}/{repo}"),
        "clone_url": str(payload.get("clone_url") or ""),
        "owner": owner,
        "name": repo,
        "full_name": str(payload.get("full_name") or f"{owner}/{repo}"),
        "description": _clip_text(payload.get("description")),
        "language": str(payload.get("language") or "") or None,
        "license": license_spdx or None,
        "default_branch": str(payload.get("default_branch") or "") or None,
        "stars": int(payload.get("stargazers_count") or 0),
        "forks": int(payload.get("forks_count") or 0),
        "watchers": int(payload.get("subscribers_count") or payload.get("watchers_count") or 0),
        "open_issues": int(payload.get("open_issues_count") or 0),
        "pushed_at": str(payload.get("pushed_at") or "") or None,
        "created_at": str(payload.get("created_at") or "") or None,
        "updated_at": str(payload.get("updated_at") or "") or None,
        "visibility": str(payload.get("visibility") or ("private" if payload.get("private") else "public")),
        "archived": bool(payload.get("archived")),
        "is_fork": bool(payload.get("fork")),
        "topics": topic_list[:20],
        "homepage": _clip_text(payload.get("homepage"), limit=200) or None,
    }
    if contributors is not None:
        card["contributors"] = contributors
    return card
