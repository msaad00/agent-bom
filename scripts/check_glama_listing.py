#!/usr/bin/env python3
"""Verify Glama's public listing is not serving stale release content."""

from __future__ import annotations

import argparse
import ast
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
README = ROOT / "README.md"
DEFAULT_URL = "https://glama.ai/mcp/servers/msaad00/agent-bom"
DEFAULT_API_URL = "https://glama.ai/api/mcp/v1/servers/msaad00/agent-bom"
DEFAULT_SCHEMA_URL = f"{DEFAULT_URL}/schema"
_MAX_TOOL_NAMES_BYTES = 2 * 1024 * 1024


def _env_or(name: str, default: str) -> str:
    """Return env var if non-blank; otherwise ``default``.

    GitHub Actions injects unset ``vars.*`` as empty strings into ``env:``,
    so ``os.environ.get(name, default)`` would keep ``""`` and skip the default.
    """
    value = (os.environ.get(name) or "").strip()
    return value or default


GLAMA_DOCKERFILE = "integrations/glama/Dockerfile"
GLAMA_MANIFESTS = (ROOT / "glama.json", ROOT / "integrations" / "glama" / "server.json")
MCP_SERVER_METADATA = "src/agent_bom/mcp_server_metadata.py"


def _is_current_checkout_ref(git_ref: str) -> bool:
    return git_ref in {"HEAD", ".", ""}


def _read_repo_file(relative_path: str, *, git_ref: str | None = None) -> str:
    if not git_ref:
        return (ROOT / relative_path).read_text(encoding="utf-8")
    try:
        return subprocess.check_output(
            ["git", "show", f"{git_ref}:{relative_path}"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        if _is_current_checkout_ref(git_ref):
            checkout_path = ROOT / relative_path
            if checkout_path.exists():
                return checkout_path.read_text(encoding="utf-8")
        detail = (exc.stderr or "").strip()
        raise FileNotFoundError(f"{relative_path} at {git_ref}: {detail}") from exc


def _load_version() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("pyproject.toml version not found")
    return match.group(1)


def _load_readme_tool_count() -> str:
    text = README.read_text(encoding="utf-8")
    # Prefer the current README phrasing ("exposes"); keep "advertises" as a
    # fallback so older release tags still parse during surface-freshness probes.
    match = re.search(r"MCP server mode (?:exposes|advertises)\s+(\d+)\s+MCP tools", text)
    if not match:
        raise SystemExit("README.md MCP tool count sentence not found")
    return match.group(1)


def _load_expected_tool_names(path: Path) -> list[str]:
    if path.stat().st_size > _MAX_TOOL_NAMES_BYTES:
        raise ValueError("expected tool-name contract exceeds the bounded input size")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not payload:
        raise ValueError("expected tool-name contract must be a non-empty JSON list")
    if any(not isinstance(name, str) or not name or name != name.strip() for name in payload):
        raise ValueError("expected tool-name contract contains an invalid name")
    normalized = sorted(payload)
    if len(set(normalized)) != len(normalized):
        raise ValueError("expected tool-name contract contains duplicate names")
    return normalized


def _load_expected_tool_contract(path: Path) -> list[dict[str, object]]:
    if path.stat().st_size > _MAX_TOOL_NAMES_BYTES:
        raise ValueError("expected tool contract exceeds the bounded input size")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list) or not payload:
        raise ValueError("expected tool contract must be a non-empty JSON list")
    normalized: list[dict[str, object]] = []
    for tool in payload:
        if not isinstance(tool, dict):
            raise ValueError("expected tool contract contains a non-object tool")
        name = tool.get("name")
        input_schema = tool.get("inputSchema")
        if not isinstance(name, str) or not name or name != name.strip() or not isinstance(input_schema, dict):
            raise ValueError("expected tool contract contains an invalid name or input schema")
        normalized.append({"name": name, "inputSchema": input_schema})
    normalized.sort(key=lambda tool: str(tool["name"]))
    names = [str(tool["name"]) for tool in normalized]
    if len(set(names)) != len(names):
        raise ValueError("expected tool contract contains duplicate names")
    return normalized


def _tool_set_failures(actual: list[str], expected: list[str]) -> list[str]:
    actual_set = set(actual)
    expected_set = set(expected)
    failures: list[str] = []
    missing = sorted(expected_set - actual_set)
    unexpected = sorted(actual_set - expected_set)
    if missing:
        failures.append(f"missing expected tools: {', '.join(missing[:10])}")
    if unexpected:
        failures.append(f"unexpected tools: {', '.join(unexpected[:10])}")
    return failures


def _api_inventory_result(
    tools: object,
    *,
    tool_count: int,
    expected_tool_names: list[str] | None,
    expected_tool_contract: list[dict[str, object]] | None,
) -> tuple[int, list[str], bool | None, bool | None]:
    if not isinstance(tools, list):
        raise ValueError("Glama public API tools field is not a list")
    failures: list[str] = []
    actual_tool_count = len(tools)
    raw_tool_names = [tool.get("name") for tool in tools if isinstance(tool, dict)]
    valid_tool_names = len(raw_tool_names) == actual_tool_count and all(
        isinstance(name, str) and bool(name) and name == name.strip() for name in raw_tool_names
    )
    exact_tool_set: bool | None = None
    exact_input_schemas: bool | None = None
    tool_names: list[str] = []
    if not valid_tool_names:
        failures.append("Glama public API inventory contains a tool without a name")
        exact_tool_set = False
    else:
        tool_names = [name for name in raw_tool_names if isinstance(name, str)]
        if len(set(tool_names)) != actual_tool_count:
            failures.append("Glama public API inventory contains duplicate tool names")
            exact_tool_set = False
    if actual_tool_count != tool_count:
        failures.append(f"Glama public API exposes {actual_tool_count} tools; expected {tool_count}")
    if expected_tool_names is not None and valid_tool_names and len(set(tool_names)) == actual_tool_count:
        tool_set_failures = _tool_set_failures(tool_names, expected_tool_names)
        failures.extend(tool_set_failures)
        exact_tool_set = not tool_set_failures
    if expected_tool_contract is not None:
        actual_by_name = {str(tool["name"]): tool for tool in tools if isinstance(tool, dict) and isinstance(tool.get("name"), str)}
        schema_failures: list[str] = []
        for expected_tool in expected_tool_contract:
            name = str(expected_tool["name"])
            actual_tool = actual_by_name.get(name)
            if actual_tool is None or actual_tool.get("inputSchema") != expected_tool["inputSchema"]:
                schema_failures.append(f"input schema differs for tool: {name}")
        failures.extend(schema_failures)
        exact_input_schemas = not schema_failures and len(actual_by_name) == len(expected_tool_contract)
    return actual_tool_count, failures, exact_tool_set, exact_input_schemas


def _release_tool_names(git_ref: str | None) -> list[str]:
    """Parse the release's static server-card tool list without executing it."""

    tree = ast.parse(_read_repo_file(MCP_SERVER_METADATA, git_ref=git_ref), filename=MCP_SERVER_METADATA)
    raw_tools: object | None = None
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == "_SERVER_CARD_TOOLS" for target in targets):
            raw_tools = ast.literal_eval(node.value)
            break
    if not isinstance(raw_tools, list) or not raw_tools:
        raise ValueError("release metadata does not contain a non-empty static MCP tool list")
    names = [tool.get("name") for tool in raw_tools if isinstance(tool, dict)]
    if len(names) != len(raw_tools) or any(not isinstance(name, str) or not name or name != name.strip() for name in names):
        raise ValueError("release metadata contains an invalid MCP tool name")
    normalized = sorted(names)
    if len(set(normalized)) != len(normalized):
        raise ValueError("release metadata contains duplicate MCP tool names")
    return normalized


def verify_build_manifest(git_ref: str | None = None) -> list[str]:
    """Ensure Glama manifests point at the curated Dockerfile before rebuild."""

    failures: list[str] = []
    try:
        dockerfile_text = _read_repo_file(GLAMA_DOCKERFILE, git_ref=git_ref)
    except FileNotFoundError:
        location = f" at {git_ref}" if git_ref else ""
        failures.append(f"missing Glama Dockerfile at {GLAMA_DOCKERFILE}{location}")
    else:
        if "RUN uv sync --locked --no-dev --no-editable --extra mcp-server" not in dockerfile_text:
            failures.append(f"{GLAMA_DOCKERFILE} must install the mcp-server extra from the reviewed uv.lock")
        if "COPY --from=builder /app/.venv /app/.venv" not in dockerfile_text:
            failures.append(f"{GLAMA_DOCKERFILE} must copy the locked virtual environment into the runtime image")
        if "ENV VIRTUAL_ENV=/app/.venv" not in dockerfile_text:
            failures.append(f"{GLAMA_DOCKERFILE} must expose the locked virtual environment")
        if 'ENV PATH="/app/.venv/bin:${PATH}"' not in dockerfile_text:
            failures.append(f"{GLAMA_DOCKERFILE} must put the locked virtual environment on mcp-proxy PATH")
        if 'ENTRYPOINT ["agent-bom", "mcp", "server"]' not in dockerfile_text:
            failures.append(f"{GLAMA_DOCKERFILE} must ENTRYPOINT agent-bom mcp server")

    for manifest in GLAMA_MANIFESTS:
        manifest_path = str(manifest.relative_to(ROOT))
        try:
            manifest_text = _read_repo_file(manifest_path, git_ref=git_ref)
        except FileNotFoundError:
            location = f" at {git_ref}" if git_ref else ""
            failures.append(f"missing Glama manifest: {manifest_path}{location}")
            continue
        data = json.loads(manifest_text)
        if data.get("dockerfile") != GLAMA_DOCKERFILE:
            failures.append(f"{manifest_path} dockerfile must be {GLAMA_DOCKERFILE!r}, found {data.get('dockerfile')!r}")
    return failures


def _fetch(url: str, timeout: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "agent-bom-release-check/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _fetch_json(url: str, timeout: int) -> dict[str, object]:
    payload = json.loads(_fetch(url, timeout))
    if not isinstance(payload, dict):
        raise ValueError("Glama public API returned a non-object payload")
    return payload


def _visible_text(page: str) -> str:
    """Return user-visible page text, excluding metadata and serialized state."""

    visible = re.sub(
        r"<(head|script|style|template)\b[^>]*>.*?</\1\s*>",
        " ",
        page,
        flags=re.IGNORECASE | re.DOTALL,
    )
    visible = re.sub(r"<[^>]+>", " ", visible)
    return re.sub(r"\s+", " ", html.unescape(visible)).strip()


def _extract_schema_tool_names(schema_page: str, listing_url: str) -> list[str]:
    """Extract the unique tools Glama renders on the public Schema page."""

    listing_path = urllib.parse.urlsplit(listing_url).path.rstrip("/")
    tool_prefix = f"{listing_path}/tools/"
    names: set[str] = set()
    for href in re.findall(r"\bhref\s*=\s*['\"]([^'\"]+)['\"]", schema_page, flags=re.IGNORECASE):
        path = urllib.parse.urlsplit(html.unescape(href)).path
        if not path.startswith(tool_prefix):
            continue
        name = urllib.parse.unquote(path.removeprefix(tool_prefix)).strip("/")
        if name and "/" not in name:
            names.add(name)
    return sorted(names)


def _check(page: str, version: str, tool_count: int) -> list[str]:
    page = _visible_text(page)
    expected_tokens = [
        f"v{version}",
        # Accept either phrasing while Glama's rendered README catches up.
        # Presence of the tool-count sentence is what matters for freshness.
    ]
    failures = [f"missing current Glama listing token: {token!r}" for token in expected_tokens if token not in page]
    tool_count_ok = bool(
        re.search(rf"MCP server mode (?:exposes|advertises)\s+{re.escape(str(tool_count))}\s+MCP tools", page)
        or f"MCP server mode exposes {tool_count} MCP tools" in page
        or f"MCP server mode advertises {tool_count} MCP tools" in page
    )
    if not tool_count_ok:
        failures.append(f"missing current Glama listing token: 'MCP server mode exposes|advertises {tool_count} MCP tools'")

    stale_patterns = [
        r"uses:\s*msaad00/agent-bom@v0\.88\.4",
        r"MCP server mode (?:exposes|advertises)\s+55\s+MCP tools",
        r"18 tools for CVE scanning",
        r"98c3e543",  # pre-0.92.0 pinned Glama build ref from audit #3472
        r"git checkout 98c3e543",
    ]
    failures.extend(f"stale Glama listing pattern still present: {pattern}" for pattern in stale_patterns if re.search(pattern, page))
    return failures


def _extract_listing_version(page: str) -> str:
    """Best-effort version extraction from Glama's rendered listing."""

    page = _visible_text(page)
    patterns = [
        r"uses:\s*msaad00/agent-bom@v([0-9]+\.[0-9]+\.[0-9]+)",
        r"\bv([0-9]+\.[0-9]+\.[0-9]+)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, page)
        if match:
            return match.group(1)
    return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=_env_or("GLAMA_LISTING_URL", DEFAULT_URL))
    parser.add_argument("--schema-url", default=_env_or("GLAMA_SCHEMA_URL", DEFAULT_SCHEMA_URL))
    parser.add_argument("--api-url", default=_env_or("GLAMA_API_URL", DEFAULT_API_URL))
    parser.add_argument("--expected", default=None, help="Expected version; defaults to pyproject.toml.")
    parser.add_argument(
        "--expected-tool-count",
        type=int,
        default=None,
        help="Expected public API tool count; defaults to the current README contract.",
    )
    parser.add_argument(
        "--expected-tool-names-file",
        type=Path,
        default=None,
        help="JSON list of exact released tool names required from the public inventory.",
    )
    parser.add_argument(
        "--expected-tool-contract-file",
        type=Path,
        default=None,
        help="JSON list of name/inputSchema objects required from a reachable public machine inventory.",
    )
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable freshness result.")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--delay-seconds", type=int, default=30)
    parser.add_argument(
        "--verify-manifest",
        action="store_true",
        help="Validate glama.json/server.json and integrations/glama/Dockerfile, then exit.",
    )
    parser.add_argument(
        "--git-ref",
        default=None,
        help="Read manifest files from this git ref/SHA while running trusted checker code.",
    )
    parser.add_argument(
        "--write-tool-names",
        type=Path,
        default=None,
        help="Write the exact static MCP tool-name list parsed from --git-ref, then exit.",
    )
    args = parser.parse_args(argv)

    if args.write_tool_names:
        names = _release_tool_names(args.git_ref)
        args.write_tool_names.write_text(json.dumps(names, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {len(names)} release-bound MCP tool names")
        return 0

    if args.verify_manifest:
        failures = verify_build_manifest(args.git_ref)
        if failures:
            print("ERROR: Glama build manifest check failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
        suffix = f" at {args.git_ref}" if args.git_ref else ""
        print(f"Glama build manifest is valid ({GLAMA_DOCKERFILE}{suffix})")
        return 0

    version = (args.expected or _load_version()).lstrip("v").strip()
    expected_tool_names = _load_expected_tool_names(args.expected_tool_names_file) if args.expected_tool_names_file else None
    expected_tool_contract = _load_expected_tool_contract(args.expected_tool_contract_file) if args.expected_tool_contract_file else None
    if expected_tool_contract is not None:
        contract_names = [str(tool["name"]) for tool in expected_tool_contract]
        if expected_tool_names is not None and contract_names != expected_tool_names:
            raise SystemExit("expected Glama tool-name and input-schema contracts do not match")
        expected_tool_names = contract_names
    tool_count = args.expected_tool_count if args.expected_tool_count is not None else int(_load_readme_tool_count())
    if tool_count < 1:
        raise SystemExit("expected Glama tool count must be positive")
    if expected_tool_names is not None and len(expected_tool_names) != tool_count:
        raise SystemExit("expected Glama tool-name contract and tool count do not match")
    last_error = ""
    listing_version = "unknown"
    actual_tool_count: int | None = None
    inventory_source: str | None = None
    exact_tool_set: bool | None = None
    exact_input_schemas: bool | None = None
    degraded_reason: str | None = None
    last_probe_unreachable = False
    for attempt in range(1, max(1, args.retries) + 1):
        actual_tool_count = None
        inventory_source = None
        exact_tool_set = None
        exact_input_schemas = None
        degraded_reason = None
        last_probe_unreachable = False
        try:
            page = _fetch(args.url, args.timeout)
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = f"failed to fetch Glama listing: {exc}"
            last_probe_unreachable = True
        else:
            listing_version = _extract_listing_version(page)
            failures = _check(page, version, tool_count)
            schema_tools: list[str] = []
            try:
                schema_tools = _extract_schema_tool_names(_fetch(args.schema_url, args.timeout), args.url)
            except (urllib.error.URLError, TimeoutError):
                # The directory API remains a valid fallback when the rendered
                # Schema page cannot be fetched or has not populated yet.
                pass

            api_result: tuple[int, list[str], bool | None, bool | None] | None = None
            api_error: Exception | None = None
            try:
                api_payload = _fetch_json(args.api_url, args.timeout)
                api_result = _api_inventory_result(
                    api_payload.get("tools"),
                    tool_count=tool_count,
                    expected_tool_names=expected_tool_names,
                    expected_tool_contract=expected_tool_contract,
                )
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
                api_error = exc

            if schema_tools:
                inventory_source = "schema+api" if api_result is not None else "schema"
                actual_tool_count = len(schema_tools)
                if actual_tool_count != tool_count:
                    failures.append(f"Glama public Schema exposes {actual_tool_count} tools; expected {tool_count}")
                if expected_tool_names is not None:
                    tool_set_failures = _tool_set_failures(schema_tools, expected_tool_names)
                    failures.extend(tool_set_failures)
                    exact_tool_set = not tool_set_failures
                if api_result is None:
                    degraded_reason = "Glama public API inventory was unreachable"
                else:
                    api_count, api_failures, api_exact_set, api_exact_schemas = api_result
                    actual_tool_count = api_count
                    failures.extend(api_failures)
                    if api_exact_set is not None:
                        exact_tool_set = bool(exact_tool_set is not False and api_exact_set)
                    exact_input_schemas = api_exact_schemas
            elif api_result is not None:
                inventory_source = "api"
                actual_tool_count, api_failures, exact_tool_set, exact_input_schemas = api_result
                failures.extend(api_failures)
            else:
                inventory_source = "api"
                failures.append(f"failed to verify Glama public API tool inventory: {api_error}")
                last_probe_unreachable = True
            if not failures:
                status = "fresh_degraded" if degraded_reason else "fresh"
                if args.json:
                    print(
                        json.dumps(
                            {
                                "surface": "Glama",
                                "status": status,
                                "expected": version,
                                "listing_version": listing_version,
                                "tool_count": actual_tool_count,
                                "expected_tool_count": tool_count,
                                "inventory_source": inventory_source,
                                "exact_tool_set": exact_tool_set,
                                "exact_input_schemas": exact_input_schemas,
                                "degraded_reason": degraded_reason,
                            },
                            separators=(",", ":"),
                        )
                    )
                    return 0
                suffix = f" ({degraded_reason})" if degraded_reason else ""
                print(f"Glama listing is {status} for agent-bom v{version} with {actual_tool_count} MCP tools{suffix}")
                return 0
            last_error = "\n".join(failures)

        if attempt < args.retries:
            print(f"Glama listing freshness check failed on attempt {attempt}/{args.retries}: {last_error}")
            time.sleep(args.delay_seconds)

    if args.json:
        print(
            json.dumps(
                {
                    "surface": "Glama",
                    "status": "unreachable" if last_probe_unreachable else "stale",
                    "expected": version,
                    "listing_version": listing_version,
                    "tool_count": actual_tool_count,
                    "expected_tool_count": tool_count,
                    "inventory_source": inventory_source,
                    "exact_tool_set": exact_tool_set,
                    "exact_input_schemas": exact_input_schemas,
                    "degraded_reason": degraded_reason,
                    "error": last_error,
                },
                separators=(",", ":"),
            )
        )
    print(f"ERROR: Glama listing is stale or unreachable:\n{last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
