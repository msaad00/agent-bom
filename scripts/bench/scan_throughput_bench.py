#!/usr/bin/env python3
"""Offline scan throughput + CLI cold-start bench.

Generates a synthetic npm ``package-lock.json`` from package names that exist
in the local vulnerability DB (so the scan produces real findings), runs an
offline scan with JSON output under ``/usr/bin/time`` and reports wall time,
user/sys CPU, peak RSS and output size. Also measures ``agent-bom --help``
cold start. Records the load average with each run: CPU time is the primary
metric because wall time is noisy on a shared host.

Stdlib-only.

Examples:
  python3 scripts/bench/scan_throughput_bench.py --sizes 200,1000,2000 --runs 3
  python3 scripts/bench/scan_throughput_bench.py --cold-start-runs 5 --sizes ''
  python3 scripts/bench/scan_throughput_bench.py --sizes 200 --runs 1 --keep-output out/
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

DEFAULT_DB = Path.home() / ".agent-bom" / "db" / "vulns.db"


_CMD_OVERRIDE: list[str] = []


def _agent_bom_bin() -> list[str]:
    if _CMD_OVERRIDE:
        return list(_CMD_OVERRIDE)
    exe = shutil.which("agent-bom")
    if exe:
        return [exe]
    return [sys.executable, "-m", "agent_bom"]


def pick_packages(db_path: Path, count: int) -> list[str]:
    """Deterministic list of npm package names, open-ended affected ranges first.

    Packages whose range starts at ``0`` are guaranteed to match ``0.0.1``;
    the remainder (ordered by name) fill larger sizes.
    """
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT package_name FROM affected WHERE ecosystem = 'npm' "
            "GROUP BY package_name "
            "ORDER BY MAX(introduced = '0' AND fixed IS NOT NULL AND fixed != '') DESC, package_name "
            "LIMIT ?",
            (count,),
        ).fetchall()
    finally:
        conn.close()
    names = [row[0] for row in rows]
    if len(names) < count:
        raise SystemExit(f"vuln DB has only {len(names)} matching npm packages (< {count})")
    return names


def write_lockfile(project_dir: Path, names: list[str]) -> None:
    project_dir.mkdir(parents=True, exist_ok=True)
    deps = {name: "0.0.1" for name in names}
    packages: dict[str, Any] = {"": {"name": "bench-app", "version": "1.0.0", "dependencies": deps}}
    for name in names:
        packages[f"node_modules/{name}"] = {"version": "0.0.1"}
    lock = {"name": "bench-app", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": packages}
    (project_dir / "package.json").write_text(json.dumps({"name": "bench-app", "version": "1.0.0", "dependencies": deps}, indent=2))
    (project_dir / "package-lock.json").write_text(json.dumps(lock, indent=2))


def _time_cmd(cmd: list[str], env: dict[str, str], ok_codes: tuple[int, ...] = (0,)) -> dict[str, float]:
    """Run ``cmd`` under /usr/bin/time and return wall/user/sys seconds + peak RSS MB."""
    is_mac = platform.system() == "Darwin"
    time_flag = "-l" if is_mac else "-v"
    started = time.perf_counter()
    proc = subprocess.run(["/usr/bin/time", time_flag, *cmd], env=env, capture_output=True, text=True, check=False)  # noqa: S603
    wall = time.perf_counter() - started
    err = proc.stderr
    if proc.returncode not in ok_codes:
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{err[-2000:]}")
    if is_mac:
        m = re.search(r"([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys", err)
        rss = re.search(r"(\d+)\s+maximum resident set size", err)
        user, sys_s = (float(m.group(2)), float(m.group(3))) if m else (0.0, 0.0)
        rss_mb = int(rss.group(1)) / (1024 * 1024) if rss else 0.0
    else:
        u = re.search(r"User time \(seconds\): ([\d.]+)", err)
        s = re.search(r"System time \(seconds\): ([\d.]+)", err)
        rss = re.search(r"Maximum resident set size \(kbytes\): (\d+)", err)
        user = float(u.group(1)) if u else 0.0
        sys_s = float(s.group(1)) if s else 0.0
        rss_mb = int(rss.group(1)) / 1024 if rss else 0.0
    return {"wall_s": wall, "user_s": user, "sys_s": sys_s, "cpu_s": user + sys_s, "rss_mb": rss_mb}


def _load() -> str:
    try:
        return " ".join(f"{v:.2f}" for v in os.getloadavg())
    except OSError:
        return "n/a"


def run_scan(project_dir: Path, out_path: Path, env: dict[str, str]) -> dict[str, Any]:
    cmd = [
        *_agent_bom_bin(),
        "scan",
        "-p",
        str(project_dir),
        "--no-discover",
        "--offline",
        "-f",
        "json",
        "-o",
        str(out_path),
        "--quiet",
    ]
    load = _load()
    # Exit 1 is the scan verdict (findings at/above the fail threshold), not an error.
    stats: dict[str, Any] = _time_cmd(cmd, env, ok_codes=(0, 1))
    stats["load"] = load
    stats["json_mb"] = out_path.stat().st_size / (1024 * 1024)
    try:
        report = json.loads(out_path.read_text())
        stats["findings"] = len(report.get("findings") or [])
    except (OSError, json.JSONDecodeError):
        stats["findings"] = -1
    return stats


def run_cold_start(env: dict[str, str]) -> dict[str, Any]:
    load = _load()
    stats: dict[str, Any] = _time_cmd([*_agent_bom_bin(), "--help"], env)
    stats["load"] = load
    return stats


def _median(rows: list[dict[str, Any]], key: str) -> float:
    return statistics.median(float(r[key]) for r in rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sizes", default="200,1000,2000", help="Comma-separated package counts ('' to skip scans)")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--cold-start-runs", type=int, default=0)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--keep-output", type=Path, default=None, help="Copy each size's last JSON report here")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable results")
    parser.add_argument(
        "--cmd",
        default="",
        help="Command that invokes the CLI (default: agent-bom on PATH), e.g. to bench another checkout via PYTHONPATH",
    )
    args = parser.parse_args()
    if args.cmd:
        _CMD_OVERRIDE[:] = shlex.split(args.cmd)

    env = dict(os.environ)
    env.setdefault("AGENT_BOM_SKIP_UPDATE_CHECK", "1")
    results: dict[str, Any] = {"host_load_start": _load(), "scans": {}, "cold_start": None}

    if args.cold_start_runs > 0:
        runs = [run_cold_start(env) for _ in range(args.cold_start_runs)]
        results["cold_start"] = {"runs": runs, "median_wall_s": _median(runs, "wall_s"), "median_cpu_s": _median(runs, "cpu_s")}

    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    with tempfile.TemporaryDirectory(prefix="abom-scan-bench-") as tmp:
        for size in sizes:
            project = Path(tmp) / f"npm-{size}"
            write_lockfile(project, pick_packages(args.db, size))
            out = Path(tmp) / f"report-{size}.json"
            runs = [run_scan(project, out, env) for _ in range(args.runs)]
            if args.keep_output:
                args.keep_output.mkdir(parents=True, exist_ok=True)
                shutil.copy(out, args.keep_output / f"report-{size}.json")
            results["scans"][str(size)] = {
                "runs": runs,
                **{f"median_{k}": _median(runs, k) for k in ("cpu_s", "user_s", "wall_s", "rss_mb", "json_mb")},
                "findings": runs[-1]["findings"],
            }

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    print(f"host load at start: {results['host_load_start']}")
    if results["cold_start"]:
        cs = results["cold_start"]
        print(f"--help cold start: median wall {cs['median_wall_s']:.2f}s cpu {cs['median_cpu_s']:.2f}s over {len(cs['runs'])} runs")
    for size, row in results["scans"].items():
        print(
            f"{size:>5} pkgs: cpu {row['median_cpu_s']:.2f}s (user {row['median_user_s']:.2f}s) "
            f"wall {row['median_wall_s']:.2f}s rss {row['median_rss_mb']:.0f}MB json {row['median_json_mb']:.1f}MB "
            f"findings {row['findings']}  loads={[r['load'] for r in row['runs']]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
