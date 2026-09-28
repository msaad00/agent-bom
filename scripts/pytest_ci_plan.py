#!/usr/bin/env python3
"""Build deterministic, exhaustive pytest plans for CI.

The PR suite is split by test-file byte weight.  Every file is assigned to
exactly one shard, while the largest files are greedily spread across runners.
The changed-domain selector is intentionally conservative: it includes tests
changed directly and tests whose basename matches a changed source/script
module.  Cross-surface smoke tests are added by the workflow itself.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable

AUTHORIZATION_SOURCES = frozenset(
    {
        "src/agent_bom/rbac.py",
        "src/agent_bom/api/auth.py",
        "src/agent_bom/api/middleware.py",
        "src/agent_bom/api/route_policy.py",
        "src/agent_bom/api/session_authorization.py",
        "src/agent_bom/api/stream_authorization.py",
        "src/agent_bom/api/sse_authorization.py",
        "src/agent_bom/api/websocket_auth.py",
        "src/agent_bom/api/tenancy.py",
        "src/agent_bom/api/routes/proxy.py",
    }
)
AUTHORIZATION_CONTRACTS = (
    "tests/test_runtime_source_auth_contract.py",
    "tests/test_api_route_policy.py",
    "tests/api/test_operation_scope_coverage.py",
    "tests/api/test_session_authorization_backends.py",
    "tests/api/test_auth_scope_boundaries.py",
    "tests/api/test_auth_contract_matrix.py",
    "tests/api/test_stream_authorization.py",
    "tests/test_websocket_auth_fails_closed.py",
)
MCP_TOOL_CONTRACTS = (
    "tests/test_deployment.py",
    "tests/test_stats_alignment.py",
    "tests/test_fleet_scan.py",
    "tests/test_mcp_tool_output_contract.py",
    "tests/test_mcp_strict_args.py",
)


def discover_test_files(root: Path) -> list[Path]:
    """Return every pytest module below *root* in stable path order."""
    return sorted(path for path in root.rglob("test_*.py") if path.is_file())


def plan_shards(files: Iterable[Path], *, total: int) -> list[list[Path]]:
    """Assign all files once using deterministic largest-first balancing."""
    if total < 1:
        raise ValueError("total shards must be positive")

    shards: list[list[Path]] = [[] for _ in range(total)]
    loads = [0] * total
    weighted = sorted(files, key=lambda path: (-path.stat().st_size, path.as_posix()))
    for path in weighted:
        index = min(range(total), key=lambda candidate: (loads[candidate], candidate))
        shards[index].append(path)
        loads[index] += path.stat().st_size

    return [sorted(shard) for shard in shards]


def select_targeted_tests(*, changed_files: Iterable[Path], root: Path) -> list[Path]:
    """Select directly changed tests and basename matches for source modules."""
    test_root = root / "tests"
    available = discover_test_files(test_root)
    selected: set[Path] = set()

    for changed in changed_files:
        normalized = Path(changed.as_posix().lstrip("./"))
        if (
            normalized.as_posix().startswith("src/agent_bom/mcp_tools/")
            or normalized.as_posix().startswith("src/agent_bom/mcp_server")
            or normalized.as_posix() == "src/agent_bom/mcp_strict_args.py"
        ):
            selected.update(root / path for path in MCP_TOOL_CONTRACTS if root / path in available)
        if normalized.as_posix() in AUTHORIZATION_SOURCES or normalized.as_posix().startswith("src/agent_bom/api/routes/"):
            selected.update(root / path for path in AUTHORIZATION_CONTRACTS if root / path in available)
        if (
            normalized.as_posix().startswith(("src/agent_bom/gateway", "src/agent_bom/runtime/gateway_", "src/agent_bom/api/gateway_"))
            or normalized.as_posix() == "src/agent_bom/runtime/trace_metadata.py"
        ):
            selected.update(candidate for candidate in available if candidate.stem.startswith(("test_gateway", "test_api_gateway")))
        if normalized.as_posix() == "src/agent_bom/runtime/trace_metadata.py":
            selected.update(candidate for candidate in available if candidate.stem.startswith("test_proxy"))
        direct = root / normalized
        if normalized.parts and normalized.parts[0] == "tests" and direct in available:
            selected.add(direct)

        if normalized.suffix != ".py" or normalized.name == "__init__.py":
            continue
        if not normalized.parts or normalized.parts[0] not in {"src", "scripts"}:
            continue

        expected = f"test_{normalized.stem}"
        selected.update(candidate for candidate in available if candidate.stem == expected or candidate.stem.startswith(f"{expected}_"))

    return sorted(selected)


def _display(path: Path, *, base: Path) -> str:
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    shard = subparsers.add_parser("shard", help="print one deterministic test shard")
    shard.add_argument("--index", type=int, required=True, help="zero-based shard index")
    shard.add_argument("--total", type=int, required=True, help="total shard count")
    shard.add_argument("--root", type=Path, default=Path("tests"), help="test root")

    targeted = subparsers.add_parser("targeted", help="print tests related to changed files")
    targeted.add_argument("--root", type=Path, default=Path("."), help="repository root")
    targeted.add_argument("changed_files", nargs="*", type=Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    cwd = Path.cwd().resolve()
    if args.command == "shard":
        if args.index < 0 or args.index >= args.total:
            raise SystemExit(f"shard index {args.index} is outside 0..{args.total - 1}")
        files = discover_test_files(args.root.resolve())
        selected = plan_shards(files, total=args.total)[args.index]
    else:
        selected = select_targeted_tests(changed_files=args.changed_files, root=args.root.resolve())

    for path in selected:
        print(_display(path.resolve(), base=cwd))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
