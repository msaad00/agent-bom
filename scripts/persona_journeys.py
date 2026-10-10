#!/usr/bin/env python3
"""Run agent-bom persona journeys end to end against the installed CLI.

Each journey drives the real ``agent-bom`` entry point the way a user would,
in an isolated HOME and state directory, against a small generated project:

* developer — first run, demo estate, SARIF/CycloneDX artifacts, project scan
* platform  — IaC scan, then boot the self-hosted control plane
* grc       — push scan findings into the control plane, list them, evaluate a framework
* ai-builder — pre-install package check and MCP discovery paths

Every step records pass/fail with the tail of its output so a CI failure names
the broken journey directly. Exits non-zero when any step fails.

Usage::

    uv run python scripts/persona_journeys.py [--report persona-report.json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

Check = Callable[[subprocess.CompletedProcess[str]], str | None]

PROJECT_FILES: dict[str, str] = {
    "requirements.txt": "requests==2.19.1\nlangchain==0.0.150\n",
    ".mcp.json": json.dumps(
        {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                }
            }
        },
        indent=2,
    ),
    "Dockerfile": "FROM python:latest\nUSER root\nRUN pip install requests\n",
    "k8s/pod.yaml": (
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: agent\nspec:\n  containers:\n"
        "    - name: agent\n      image: python:latest\n      securityContext:\n"
        "        privileged: true\n        allowPrivilegeEscalation: true\n"
    ),
}


@dataclass
class StepResult:
    persona: str
    step: str
    ok: bool
    seconds: float
    detail: str = ""


def _tail(text: str, lines: int = 12) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _rows(payload: object) -> list[object]:
    """Return the list of records from a list or a common envelope shape."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("findings", "items", "data", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
    return []


class Journeys:
    def __init__(self, cli: Sequence[str], root: Path, timeout: int) -> None:
        self.cli = list(cli)
        self.root = root
        self.project = root / "project"
        self.out = root / "out"
        self.timeout = timeout
        self.results: list[StepResult] = []
        home = root / "home"
        for path in (self.project, self.out, home):
            path.mkdir(parents=True, exist_ok=True)
        for rel, content in PROJECT_FILES.items():
            target = self.project / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        self.env = {
            **os.environ,
            "HOME": str(home),
            "AGENT_BOM_STATE_DIR": str(home / ".agent-bom"),
            "NO_COLOR": "1",
            "TERM": "dumb",
        }

    def record(self, persona: str, step: str, started: float, detail: str) -> bool:
        result = StepResult(persona, step, not detail, round(time.monotonic() - started, 2), detail)
        self.results.append(result)
        mark = "PASS" if result.ok else "FAIL"
        print(f"[{mark}] {persona:<10} {step} ({result.seconds}s)")
        if detail:
            print("        " + detail.replace("\n", "\n        "))
        return result.ok

    def run(self, persona: str, step: str, args: Sequence[str], ok_codes: Sequence[int] = (0,), check: Check | None = None) -> bool:
        started = time.monotonic()
        try:
            proc = subprocess.run(
                [*self.cli, *args],
                cwd=self.out,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self.record(persona, step, started, f"timed out after {self.timeout}s")
        if proc.returncode not in ok_codes:
            output = proc.stderr.strip() or proc.stdout
            return self.record(persona, step, started, f"exit {proc.returncode}, expected {list(ok_codes)}:\n{_tail(output)}")
        detail = ""
        if check is not None:
            try:
                detail = check(proc) or ""
            except (OSError, ValueError, KeyError, TypeError) as exc:
                detail = f"artifact check raised {type(exc).__name__}: {exc}"
        return self.record(persona, step, started, detail)

    def artifact(self, name: str) -> Path:
        return self.out / name


# ── artifact checks ──────────────────────────────────────────────────────────


def sarif_check(path: Path, min_results: int = 1) -> Check:
    def check(_: subprocess.CompletedProcess[str]) -> str | None:
        doc = _load_json(path)
        if not isinstance(doc, dict) or doc.get("version") != "2.1.0":
            return f"{path.name} is not SARIF 2.1.0"
        results = sum(len(run.get("results") or []) for run in doc.get("runs") or [])
        if results < min_results:
            return f"{path.name} has {results} results, expected >= {min_results}"
        return None

    return check


def demo_json_check(path: Path) -> Check:
    def check(_: subprocess.CompletedProcess[str]) -> str | None:
        doc = _load_json(path)
        if not isinstance(doc, dict):
            return f"{path.name} is not a JSON object"
        if not _rows(doc) and not doc.get("blast_radius"):
            return f"{path.name} has no findings or blast_radius entries (keys: {sorted(doc)[:12]})"
        return None

    return check


def cyclonedx_check(path: Path) -> Check:
    def check(_: subprocess.CompletedProcess[str]) -> str | None:
        doc = _load_json(path)
        if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX":
            return f"{path.name} is not a CycloneDX document"
        if not doc.get("components"):
            return f"{path.name} has no components"
        return None

    return check


def contains_check(path: Path, needles: Sequence[str]) -> Check:
    def check(_: subprocess.CompletedProcess[str]) -> str | None:
        text = path.read_text(encoding="utf-8")
        missing = [needle for needle in needles if needle not in text]
        return f"{path.name} is missing {missing}" if missing else None

    return check


def stdout_rows_check(min_rows: int = 1) -> Check:
    def check(proc: subprocess.CompletedProcess[str]) -> str | None:
        rows = _rows(json.loads(proc.stdout))
        return None if len(rows) >= min_rows else f"expected >= {min_rows} rows, got {len(rows)}: {_tail(proc.stdout, 6)}"

    return check


def stdout_key_check(key: str) -> Check:
    def check(proc: subprocess.CompletedProcess[str]) -> str | None:
        payload = json.loads(proc.stdout)
        return None if isinstance(payload, dict) and key in payload else f"response has no {key!r}: {_tail(proc.stdout, 6)}"

    return check


# ── control plane ────────────────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _http_status(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - loopback only
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, OSError):
        return 0


class ControlPlane:
    def __init__(self, journeys: Journeys) -> None:
        self.journeys = journeys
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.log = journeys.root / "serve.log"
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self, boot_timeout: int) -> bool:
        started = time.monotonic()
        args = ["serve", "--port", str(self.port), "--persist", str(self.journeys.root / "control-plane.db")]
        with self.log.open("wb") as handle:
            self.proc = subprocess.Popen(
                [*self.journeys.cli, *args], cwd=self.journeys.out, env=self.journeys.env, stdout=handle, stderr=subprocess.STDOUT
            )
        while time.monotonic() - started < boot_timeout:
            if self.proc.poll() is not None:
                return self._fail("boot", started, f"serve exited with {self.proc.returncode}")
            if _http_status(f"{self.url}/healthz") == 200:
                return self.journeys.record("platform", "serve boots and /healthz is 200", started, "")
            time.sleep(1)
        return self._fail("boot", started, f"/healthz not 200 within {boot_timeout}s")

    def expect_status(self, path: str, status: int = 200) -> bool:
        started = time.monotonic()
        got = _http_status(f"{self.url}{path}")
        detail = "" if got == status else f"GET {path} returned {got}, expected {status}"
        return self.journeys.record("platform", f"GET {path} is {status}", started, detail)

    def _fail(self, step: str, started: float, reason: str) -> bool:
        log = self.log.read_text(encoding="utf-8", errors="replace") if self.log.exists() else ""
        return self.journeys.record("platform", f"serve {step}", started, f"{reason}\n{_tail(log, 20)}")

    def stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)


# ── journeys ─────────────────────────────────────────────────────────────────


def developer(j: Journeys) -> None:
    j.run("developer", "agent-bom --version", ["--version"])
    j.run("developer", "doctor --offline", ["doctor", "--offline"])
    demo = j.artifact("demo.json")
    # The bundled estate trips the security gate on purpose (documented exit 1).
    j.run(
        "developer",
        "demo scan -> JSON (gate exit 1)",
        ["scan", "--demo", "--offline", "-f", "json", "-o", str(demo)],
        (1,),
        demo_json_check(demo),
    )
    sarif = j.artifact("demo.sarif")
    j.run("developer", "demo scan -> SARIF", ["scan", "--demo", "--offline", "-f", "sarif", "-o", str(sarif)], (0, 1), sarif_check(sarif))
    cdx = j.artifact("demo.cdx.json")
    j.run(
        "developer",
        "demo scan -> CycloneDX",
        ["scan", "--demo", "--offline", "-f", "cyclonedx", "-o", str(cdx)],
        (0, 1),
        cyclonedx_check(cdx),
    )
    project = j.artifact("project.json")
    j.run(
        "developer",
        "project scan inventories packages and MCP server",
        ["scan", str(j.project), "--offline", "-f", "json", "-o", str(project)],
        (0, 1),
        contains_check(project, ["requests", "langchain", "filesystem"]),
    )


def platform(j: Journeys, plane: ControlPlane, boot_timeout: int) -> bool:
    iac = j.artifact("iac.sarif")
    j.run(
        "platform",
        "IaC scan flags Dockerfile + privileged pod",
        ["iac", str(j.project), "-f", "sarif", "-o", str(iac)],
        (0, 1),
        sarif_check(iac, 2),
    )
    if not plane.start(boot_timeout):
        return False
    plane.expect_status("/readyz")
    return True


def grc(j: Journeys, plane: ControlPlane) -> None:
    api = ["--api-url", plane.url]
    demo = j.artifact("demo.json")
    if not demo.exists():
        started = time.monotonic()
        j.record("grc", "push demo findings", started, "demo.json missing; developer journey failed first")
        return
    j.run("grc", "push demo findings to control plane", ["findings", "push", str(demo), "--source", "persona-journey", *api])
    j.run("grc", "findings list shows pushed findings", ["findings", "list", "--format", "json", *api], check=stdout_rows_check())
    j.run(
        "grc",
        "compliance eval owasp-llm reports a status",
        ["compliance", "eval", "--framework", "owasp-llm", "--exit-zero", "--format", "json", *api],
        check=stdout_key_check("status"),
    )


def ai_builder(j: Journeys) -> None:
    j.run("ai-builder", "pre-install check (offline)", ["check", "requests@2.33.0", "--ecosystem", "pypi", "--offline"])
    j.run("ai-builder", "where lists MCP discovery paths", ["where"])


# ── reporting ────────────────────────────────────────────────────────────────


def write_summary(results: list[StepResult], report: Path | None) -> None:
    failed = [r for r in results if not r.ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} persona steps passed")
    if report is not None:
        report.write_text(json.dumps([asdict(r) for r in results], indent=2) + "\n", encoding="utf-8")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines = ["## Persona journeys", "", "| Persona | Step | Result | Seconds |", "|---|---|---|---|"]
    lines += [f"| {r.persona} | {r.step} | {'✅' if r.ok else '❌'} | {r.seconds} |" for r in results]
    for r in failed:
        lines += ["", f"<details><summary>❌ {r.persona}: {r.step}</summary>", "", "```text", r.detail, "```", "</details>"]
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def resolve_cli(explicit: str | None) -> list[str]:
    if explicit:
        return [explicit]
    found = shutil.which("agent-bom")
    return [found] if found else [sys.executable, "-m", "agent_bom"]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cli", help="agent-bom executable (default: agent-bom on PATH, else python -m agent_bom)")
    parser.add_argument("--report", type=Path, help="Write step results as JSON")
    parser.add_argument("--timeout", type=int, default=300, help="Per-command timeout in seconds")
    parser.add_argument("--boot-timeout", type=int, default=120, help="Control-plane boot timeout in seconds")
    parser.add_argument("--keep", action="store_true", help="Keep the working directory for inspection")
    args = parser.parse_args(argv)

    root = Path(tempfile.mkdtemp(prefix="agent-bom-personas-"))
    journeys = Journeys(resolve_cli(args.cli), root, args.timeout)
    plane = ControlPlane(journeys)
    try:
        developer(journeys)
        if platform(journeys, plane, args.boot_timeout):
            grc(journeys, plane)
        ai_builder(journeys)
    finally:
        plane.stop()
        write_summary(journeys.results, args.report)
        if args.keep:
            print(f"working directory kept at {root}")
        else:
            shutil.rmtree(root, ignore_errors=True)
    return 0 if all(r.ok for r in journeys.results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
