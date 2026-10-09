"""Shared helpers and constants for the CLI package."""

from __future__ import annotations

import errno
import importlib
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from agent_bom import __version__
from agent_bom.core.severity import SEVERITY_POLICY_ORDER
from agent_bom.inventory import build_agents_from_inventory as _build_agents_from_inventory  # noqa: F401 — compatibility re-export
from agent_bom.inventory import coerce_agent_type_for_inventory as _coerce_agent_type_for_inventory  # noqa: F401
from agent_bom.output.brand_tokens import cli_banner_plain
from agent_bom.security import sanitize_env_vars  # noqa: F401 — re-exported by agent_bom.cli

logger = logging.getLogger(__name__)

# Canonical CLI lockup — product name agent-bom, mark is BOM-with-agent-O.
BANNER = cli_banner_plain(version=__version__)

SEVERITY_ORDER = {label.lower(): rank for label, rank in SEVERITY_POLICY_ORDER.items()}
PORT_RANGE = click.IntRange(1, 65535)
LISTEN_PORT_RANGE = click.IntRange(1024, 65535)
OPTIONAL_PORT_RANGE = click.IntRange(0, 65535)


def read_json_file_for_cli(path: str | Path, *, label: str = "JSON file") -> Any:
    """Read a JSON file and raise concise Click errors for CLI users."""
    file_path = Path(path)
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"{label} JSON error in {file_path}: line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    except OSError as exc:
        raise click.ClickException(f"Could not read {label.lower()} {file_path}: {exc.strerror or exc}") from exc


import contextlib  # noqa: E402 — kept beside the helper that uses it for grep-locality


@contextlib.contextmanager
def rich_log_handler_during_progress(console: Console, *, logger_name: str = "agent_bom.scanners"):
    """Route warnings from ``logger_name`` through Rich for the duration.

    When a Rich ``Progress`` / ``Live`` region is active, a ``logger.warning(...)``
    that goes through a plain stderr handler punches through the live region:
    each warning line pushes the spinner down, the spinner redraws below it,
    and the terminal accumulates a stack of "Scanning N packages" lines
    instead of a single redrawing one.

    Bind a ``RichHandler`` to the same ``Console`` for the duration of the
    progress block so log records render *above* the live region without
    breaking the redraw, then restore the original handlers on exit.
    """
    from rich.logging import RichHandler

    target = logging.getLogger(logger_name)
    saved_handlers = list(target.handlers)
    saved_propagate = target.propagate

    rich_h = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=False,
        rich_tracebacks=False,
        log_time_format="%H:%M:%S",
        omit_repeated_times=False,
    )
    rich_h.setLevel(logging.WARNING)
    target.handlers = [rich_h]
    target.propagate = False
    try:
        yield
    finally:
        target.handlers = saved_handlers
        target.propagate = saved_propagate


def _make_console(quiet: bool = False, output_format: str = "console", no_color: bool = False) -> Console:
    """Create a Console that routes output correctly.

    - quiet mode: suppress all output
    - json/cyclonedx format: route to stderr (keep stdout clean for piping)
    - no_color: disable all ANSI styling (for piping / CI)
    - console format: normal stdout
    """
    if quiet:
        return Console(stderr=True, quiet=True)
    if output_format != "console":
        return Console(stderr=True, no_color=no_color)
    return Console(no_color=no_color)


def _sync_runtime_consoles(console: Console) -> None:
    """Point shared module-level consoles at the active CLI console."""
    for module_name in (
        "agent_bom.scanners",
        "agent_bom.enrichment",
        "agent_bom.resolver",
        "agent_bom.transitive",
        "agent_bom.parsers",
    ):
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Could not sync console for %s: %s", module_name, exc)
            continue
        if hasattr(module, "console"):
            setattr(module, "console", console)


_update_check_result: str | None = None
_update_check_done = threading.Event()

# Upgrade guidance depends on *how* agent-bom was installed. Only a pip install
# can be driven with `pip install --upgrade`; every other method must be
# upgraded through its own tool (running pip against a frozen binary, pipx venv,
# uv tool, or Homebrew Cellar is a no-op at best and corrupts the install at
# worst). The releases page is the upgrade path for standalone frozen binaries.
_RELEASES_URL = "https://github.com/msaad00/agent-bom/releases/latest"
# Published container image; override with AGENT_BOM_DOCKER_IMAGE.
_DEFAULT_DOCKER_IMAGE = "agentbom/agent-bom"


def _detect_install_method() -> tuple[str, str]:
    """Infer how this agent-bom was installed and the matching upgrade command.

    Returns ``(method, upgrade_command)`` where ``method`` is one of
    ``frozen`` / ``docker`` / ``pipx`` / ``uv`` / ``brew`` / ``pip``. Callers
    must only *execute* the command when ``method == "pip"`` — for every other
    method the string is what the operator should run themselves.
    """

    truthy = {"1", "true", "yes", "on"}

    # Frozen / standalone binary (PyInstaller / cx_Freeze .pkg/.msi). There is no
    # pip in this interpreter, so the only upgrade path is a fresh download.
    if getattr(sys, "frozen", False):
        return "frozen", f"re-download the latest release binary from {_RELEASES_URL}"

    # Docker / OCI container.
    if os.path.exists("/.dockerenv") or os.environ.get("AGENT_BOM_IN_CONTAINER", "").strip().lower() in truthy:
        image = os.environ.get("AGENT_BOM_DOCKER_IMAGE") or _DEFAULT_DOCKER_IMAGE
        return "docker", f"docker pull {image}:latest"

    # Path-based detection for isolated-tool installers. sys.prefix (the active
    # environment root) is the most reliable signal; the module path and launcher
    # path are cross-checked for repacked layouts. Normalize to forward slashes so
    # the substring checks are OS-agnostic and easy to exercise in tests.
    parts: list[str] = [str(getattr(sys, "prefix", "") or "")]
    try:
        parts.append(str(Path(__file__).resolve()))
    except OSError:
        pass
    argv = getattr(sys, "argv", None)
    if argv:
        parts.append(str(argv[0] or ""))
    haystack = "/".join(parts).replace("\\", "/").lower()

    if "/pipx/venvs/" in haystack:
        return "pipx", "pipx upgrade agent-bom"
    if "/uv/tools/" in haystack:
        return "uv", "uv tool upgrade agent-bom"
    if "/cellar/" in haystack or "/homebrew/" in haystack or "/linuxbrew/" in haystack:
        return "brew", "brew upgrade agent-bom"
    return "pip", "pip install --upgrade agent-bom"


def _update_check_cache_file() -> Path:
    """Path for the once-a-day update-check stamp.

    Honors ``AGENT_BOM_STATE_DIR`` so the write lands off ``$HOME`` (e.g. on a
    tiny CloudShell home) when the operator redirects state; otherwise uses the
    per-user XDG cache dir.
    """

    state_dir = os.environ.get("AGENT_BOM_STATE_DIR")
    base = Path(state_dir) if state_dir else Path.home() / ".cache" / "agent-bom"
    return base / "update-check.txt"


def _should_skip_update_check() -> bool:

    truthy = {"1", "true", "yes", "on"}
    if os.environ.get("AGENT_BOM_SKIP_UPDATE_CHECK", "").strip().lower() in truthy:
        return True
    if os.environ.get("AGENT_BOM_OFFLINE", "").strip().lower() in truthy:
        return True
    # The update-check thread starts before Click parses subcommand flags, so
    # honor ``--offline`` on argv for air-gap invocations like
    # ``agent-bom agents --demo --offline``.
    if "--offline" in sys.argv:
        return True
    return False


def _check_for_update_bg() -> None:
    """Background thread: compare __version__ against PyPI latest. Non-blocking."""
    global _update_check_result  # noqa: PLW0603

    if _should_skip_update_check():
        _update_check_result = None
        _update_check_done.set()
        return

    try:
        cache_file = _update_check_cache_file()
        cache_file.parent.mkdir(parents=True, exist_ok=True)

        # Only hit PyPI once per 24 hours

        if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 86400:
            _update_check_result = cache_file.read_text().strip() or None
            _update_check_done.set()
            return

        from agent_bom.http_client import fetch_json

        data = fetch_json("https://pypi.org/pypi/agent-bom/json", timeout=5)
        latest = data["info"]["version"]

        def _vt(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.split(".") if x.isdigit())

        if _vt(latest) > _vt(__version__):
            _, upgrade_command = _detect_install_method()
            msg = (
                f"[yellow]Update available:[/yellow] agent-bom {__version__} → [bold]{latest}[/bold]\n  Run: [cyan]{upgrade_command}[/cyan]"
            )
        else:
            msg = ""
        try:
            cache_file.write_text(msg)
        except OSError as exc:
            # A full disk must not lose the update notice or crash the scan —
            # degrade to no-cache (the result is still served this run).
            if exc.errno in (errno.ENOSPC, errno.EDQUOT):
                logger.debug("Disk full writing update-check stamp %s — skipping cache", cache_file)
            else:
                logger.debug("Could not write update-check stamp %s: %s", cache_file, exc)
        _update_check_result = msg or None
    except Exception:  # noqa: BLE001
        _update_check_result = None
    finally:
        _update_check_done.set()


def _print_update_notice(console: Console) -> None:
    """Print update notice if a newer version was found (non-blocking)."""
    _update_check_done.wait(timeout=0.1)  # don't block the user
    if _update_check_result:
        console.print()
        console.print(_update_check_result)


def _check_optional_dep(name: str) -> str:
    """Return 'found (vX.Y.Z)' or 'not installed' for an optional binary dep."""

    path = shutil.which(name)
    if not path:
        return "not installed"
    try:
        result = subprocess.run([path, "version"], capture_output=True, text=True, timeout=3)  # noqa: S603
        ver = (result.stdout or result.stderr).strip().split("\n")[0]
        return f"found ({ver})" if ver else "found"
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not get version for %s: %s", name, exc)
        return "found"
