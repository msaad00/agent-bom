#!/usr/bin/env python3
"""Validate README/docs storefront and release-surface consistency."""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
PYPI_README = ROOT / "PYPI_README.md"
CHANGELOG = ROOT / "CHANGELOG.md"
DEMO_TAPE = ROOT / "docs" / "demo.tape"
DEMO_LATEST = ROOT / "docs" / "images" / "demo-latest.gif"
GLAMA_SERVER = ROOT / "integrations" / "glama" / "server.json"
DOCKER_README = ROOT / "DOCKER_HUB_README.md"
TOP_DOCKERFILE = ROOT / "Dockerfile"
PYPROJECT = ROOT / "pyproject.toml"
MANAGED_IMAGE_REFS: list[tuple[Path, re.Pattern[str]]] = [
    (ROOT / "deploy" / "docker-compose.pilot.yml", re.compile(r"agentbom/agent-bom(?:-ui)?:([0-9]+\.[0-9]+\.[0-9]+)")),
    (ROOT / "deploy" / "docker-compose.runtime.yml", re.compile(r"agentbom/agent-bom(?:-ui)?:([0-9]+\.[0-9]+\.[0-9]+)")),
    (ROOT / "deploy" / "docker-compose.fullstack.yml", re.compile(r"agentbom/agent-bom(?:-ui)?:([0-9]+\.[0-9]+\.[0-9]+)")),
    (ROOT / "deploy" / "docker-compose.platform.yml", re.compile(r"agentbom/agent-bom(?:-ui)?:([0-9]+\.[0-9]+\.[0-9]+)")),
    (ROOT / "deploy" / "k8s" / "daemonset.yaml", re.compile(r"agentbom/agent-bom:([0-9]+\.[0-9]+\.[0-9]+)")),
    (ROOT / "site-docs" / "deployment" / "docker.md", re.compile(r"agentbom/agent-bom:([0-9]+\.[0-9]+\.[0-9]+)")),
    (ROOT / "docs" / "RUNTIME_MONITORING.md", re.compile(r"agentbom/agent-bom:([0-9]+\.[0-9]+\.[0-9]+)")),
]
MANAGED_VERSION_REFS: list[tuple[Path, re.Pattern[str], str]] = [
    (
        ROOT / "src" / "agent_bom" / "__init__.py",
        re.compile(r'__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"'),
        "__version__",
    ),
    (ROOT / "uv.lock", re.compile(r'name = "agent-bom"\nversion = "([0-9]+\.[0-9]+\.[0-9]+)"'), "uv.lock package version"),
    (ROOT / "ui" / "package.json", re.compile(r'"version":\s*"([0-9]+\.[0-9]+\.[0-9]+)"'), "UI package version"),
    (
        ROOT / "deploy" / "helm" / "agent-bom" / "values.yaml",
        re.compile(r'tag:\s*"([0-9]+\.[0-9]+\.[0-9]+)"'),
        "Helm values image tag",
    ),
    (
        ROOT / "deploy" / "docker" / "Dockerfile.runtime",
        re.compile(r"^ARG VERSION=([0-9]+\.[0-9]+\.[0-9]+)$", re.M),
        "runtime Dockerfile ARG",
    ),
    (
        ROOT / "deploy" / "docker" / "Dockerfile.sse",
        re.compile(r"^ARG VERSION=([0-9]+\.[0-9]+\.[0-9]+)$", re.M),
        "SSE Dockerfile ARG",
    ),
    (
        ROOT / "deploy" / "docker" / "Dockerfile.mcp",
        re.compile(r"^ARG VERSION=([0-9]+\.[0-9]+\.[0-9]+)$", re.M),
        "MCP Dockerfile ARG",
    ),
    (
        ROOT / "deploy" / "docker" / "Dockerfile.snowpark",
        re.compile(r"^ARG VERSION=([0-9]+\.[0-9]+\.[0-9]+)$", re.M),
        "Snowpark Dockerfile ARG",
    ),
    (
        ROOT / "deploy" / "k8s" / "sidecar-example.yaml",
        re.compile(r"agentbom/agent-bom:([0-9]+\.[0-9]+\.[0-9]+)"),
        "K8s sidecar image",
    ),
    (
        ROOT / "deploy" / "k8s" / "proxy-sidecar-pilot.yaml",
        re.compile(r"agentbom/agent-bom:([0-9]+\.[0-9]+\.[0-9]+)"),
        "K8s proxy sidecar image",
    ),
    (
        ROOT / "integrations" / "mcp-registry" / "server.json",
        re.compile(r'"version":\s*"([0-9]+\.[0-9]+\.[0-9]+)"'),
        "MCP Registry manifest version",
    ),
    (ROOT / "integrations" / "glama" / "server.json", re.compile(r'"version":\s*"([0-9]+\.[0-9]+\.[0-9]+)"'), "Glama manifest version"),
    (ROOT / "docs" / "RELEASE_VERIFICATION.md", re.compile(r"^TAG=v([0-9]+\.[0-9]+\.[0-9]+)$", re.M), "release verification tag"),
    (
        ROOT / "docs" / "PUBLISHING.md",
        re.compile(r"(?:--version \"|git tag v|git push origin v)([0-9]+\.[0-9]+\.[0-9]+)"),
        "publishing example version",
    ),
    (
        ROOT / "DOCKER_HUB_README.md",
        re.compile(r"\| `([0-9]+\.[0-9]+\.[0-9]+)` \| Current stable version \(pinned\) \|"),
        "Docker Hub stable tag",
    ),
    (
        ROOT / "site-docs" / "deployment" / "airgapped-image-bundle.md",
        re.compile(
            r"(?:--version |agent-bom-airgap-|VERSION=|tag:\s*\"|agent-bom-ui:\")"
            r"([0-9]+\.[0-9]+\.[0-9]+)"
        ),
        "air-gapped bundle release example",
    ),
    (
        ROOT / "site-docs" / "deployment" / "aws-company-rollout.md",
        re.compile(r"(?:--version |refs/tags/v)([0-9]+\.[0-9]+\.[0-9]+)"),
        "AWS company rollout release example",
    ),
    (
        ROOT / "site-docs" / "reference" / "remediate-output.md",
        re.compile(r'"version":\s*"([0-9]+\.[0-9]+\.[0-9]+)"'),
        "remediate output example version",
    ),
]
MANAGED_ACTION_REFS: list[Path] = [
    ROOT / "README.md",
    ROOT / "docs" / "AI_INFRASTRUCTURE_SCANNING.md",
    ROOT / "docs" / "ENTERPRISE_DEPLOYMENT.md",
    ROOT / "docs" / "MCP_SECURITY_MODEL.md",
    ROOT / "site-docs" / "features" / "policy.md",
]
MCP_COUNT_DOCS: list[Path] = [
    ROOT / "README.md",
    ROOT / "docs" / "MCP_SERVER.md",
    ROOT / "site-docs" / "getting-started" / "mcp-server.md",
]
DOCKER_MCP_TOOLS = ROOT / "integrations" / "docker-mcp-registry" / "tools.json"


def _load_version() -> str:
    text = PYPROJECT.read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("pyproject.toml version not found")
    return match.group(1)


def _load_description() -> str:
    text = PYPROJECT.read_text()
    match = re.search(r'^description\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("pyproject.toml description not found")
    return match.group(1)


def _fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def _server_card_list(variable_name: str) -> list[dict[str, object]]:
    metadata = ROOT / "src" / "agent_bom" / "mcp_server_metadata.py"
    module = ast.parse(metadata.read_text())
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == variable_name for target in node.targets):
            continue
        value = ast.literal_eval(node.value)
        if isinstance(value, list):
            return value
    _fail(f"{metadata.relative_to(ROOT)} is missing {variable_name}")


def _server_card_catalog() -> tuple[list[str], list[str], list[str]]:
    tools = [str(tool["name"]) for tool in _server_card_list("_SERVER_CARD_TOOLS")]
    resources = [str(resource["uri"]) for resource in _server_card_list("_SERVER_CARD_RESOURCES")]
    prompts = [str(prompt["name"]) for prompt in _server_card_list("_SERVER_CARD_PROMPTS")]
    return tools, resources, prompts


def _assert_versions(path: Path, pattern: re.Pattern[str], expected: str, label: str) -> None:
    if not path.exists():
        _fail(f"{path.relative_to(ROOT)} is missing from release surface")
    text = path.read_text()
    versions = {match.group(1) for match in pattern.finditer(text)}
    if not versions:
        _fail(f"{path.relative_to(ROOT)} has no managed {label}")
    if versions != {expected}:
        _fail(f"{path.relative_to(ROOT)} has stale {label}: {sorted(versions)} != {expected}")


def main() -> int:
    version = _load_version()
    description = _load_description()
    readme = README.read_text()
    pypi_readme = PYPI_README.read_text()
    changelog = CHANGELOG.read_text()
    demo_tape = DEMO_TAPE.read_text()

    required_github_markers = [
        "img.shields.io/github/actions/workflow/status",
        "img.shields.io/pypi/v/agent-bom",
        "img.shields.io/docker/pulls/agentbom/agent-bom",
        "img.shields.io/ossf-scorecard",
        "docs/images/demo-latest.gif",
    ]
    for marker in required_github_markers:
        if marker not in readme:
            _fail(f"README is missing required storefront marker: {marker}")

    required_pypi_markers = [
        "mcp-name: io.github.msaad00/agent-bom",
        "docs/images/demo-latest.gif",
        "docs/images/scan-pipeline-light.svg",
        "docs/images/blast-radius-light.svg",
    ]
    for marker in required_pypi_markers:
        if marker not in pypi_readme:
            _fail(f"PYPI_README.md is missing required storefront marker: {marker}")

    forbidden_pypi_markers = [
        "img.shields.io/github/actions/workflow/status",
        "img.shields.io/ossf-scorecard",
        "api.securityscorecards.dev",
        "```mermaid",
        "flowchart ",
        "demo-v0.",
        "@mcp/server-filesystem /tmp",
    ]
    for marker in forbidden_pypi_markers:
        if marker in pypi_readme:
            _fail(f"PYPI_README.md contains forbidden storefront marker: {marker}")

    if "demo-latest.gif" not in readme:
        _fail("README must reference docs/images/demo-latest.gif")
    if "demo-latest.gif" not in pypi_readme:
        _fail("PYPI_README.md must reference docs/images/demo-latest.gif")
    if re.search(r"demo-v\d+\.\d+\.\d+\.gif", readme):
        _fail("README must not reference versioned demo GIF filenames")
    if re.search(r"demo-v\d+\.\d+\.\d+\.gif", pypi_readme):
        _fail("PYPI_README.md must not reference versioned demo GIF filenames")
    if "Output docs/images/demo-latest.gif" not in demo_tape:
        _fail("docs/demo.tape must render to docs/images/demo-latest.gif")
    if not DEMO_LATEST.exists():
        _fail("docs/images/demo-latest.gif is missing")
    stale_path_markers = [
        "npx @mcp/server-filesystem /tmp",
        "npx -y @modelcontextprotocol/server-filesystem /tmp",
        "npx @modelcontextprotocol/server-filesystem /tmp",
        "@modelcontextprotocol/server-fs /tmp",
    ]
    release_path_roots = [
        ROOT / "README.md",
        ROOT / "PYPI_README.md",
        ROOT / "docs",
        ROOT / "site-docs",
        ROOT / "integrations",
        ROOT / "ui" / "app" / "proxy" / "page.tsx",
    ]
    for root in release_path_roots:
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
        for file in files:
            if file.suffix.lower() in {".gif", ".png", ".jpg", ".jpeg", ".svg", ".ico"}:
                continue
            text = file.read_text(errors="ignore")
            for marker in stale_path_markers:
                if marker in text:
                    _fail(f"{file.relative_to(ROOT)} contains stale toy runtime path: {marker}")

    if len(description) > 120:
        _fail("pyproject.toml description must stay concise for PyPI storefront rendering")
    stale_description_markers = [
        "Security scanner for AI infrastructure and supply chain.",
        "19 output formats",
        "20-page Next.js dashboard",
        "14-framework compliance",
    ]
    for marker in stale_description_markers:
        if marker in description:
            _fail(f"pyproject.toml description contains stale storefront phrase: {marker}")

    if f"## [{version}]" not in changelog:
        _fail(f"CHANGELOG.md must include a {version} release entry before tagging")
    if f"[Unreleased]: https://github.com/msaad00/agent-bom/compare/v{version}...HEAD" not in changelog:
        _fail(f"CHANGELOG.md Unreleased compare link must start at v{version}")

    leaked_patterns = [
        r"/Users/[^/\s]+",
        r"[A-Za-z]:\\Users\\[^\\\s]+",
    ]
    scan_roots = [ROOT / "README.md", ROOT / "PYPI_README.md", ROOT / "docs"]
    for path in scan_roots:
        files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
        for file in files:
            if file.suffix.lower() in {".gif", ".png", ".jpg", ".jpeg", ".svg", ".ico"}:
                continue
            text = file.read_text(errors="ignore")
            for pattern in leaked_patterns:
                if re.search(pattern, text):
                    _fail(f"personal/local path leak found in {file.relative_to(ROOT)}")

    if f"agent-bom v{version}" not in demo_tape:
        _fail(f"docs/demo.tape header must include v{version}")

    glama_text = GLAMA_SERVER.read_text()
    if f'"version": "{version}"' not in glama_text:
        _fail(f"integrations/glama/server.json must be aligned to {version}")
    if f"`{version}` | Current stable version (pinned)" not in DOCKER_README.read_text():
        _fail(f"DOCKER_HUB_README.md must mark {version} as the current stable version")
    if f"ARG VERSION={version}" not in TOP_DOCKERFILE.read_text():
        _fail(f"Dockerfile ARG VERSION must be {version}")
    for path, pattern in MANAGED_IMAGE_REFS:
        text = path.read_text()
        versions = {match.group(1) for match in pattern.finditer(text)}
        if versions and versions != {version}:
            _fail(f"{path.relative_to(ROOT)} contains stale managed image version(s): {sorted(versions)} != {version}")
    for path, pattern, label in MANAGED_VERSION_REFS:
        _assert_versions(path, pattern, version, label)
    ui_lock = json.loads((ROOT / "ui" / "package-lock.json").read_text())
    ui_lock_versions = {ui_lock.get("version"), ui_lock.get("packages", {}).get("", {}).get("version")}
    if ui_lock_versions != {version}:
        _fail(f"ui/package-lock.json has stale root package version(s): {sorted(ui_lock_versions)} != {version}")
    for skill in sorted((ROOT / "integrations" / "openclaw").rglob("SKILL.md")):
        _assert_versions(skill, re.compile(r"^version:\s*([0-9]+\.[0-9]+\.[0-9]+)$", re.M), version, "OpenClaw skill frontmatter version")
        text = skill.read_text()
        docker_versions = set(re.findall(r"ghcr\.io/msaad00/agent-bom:([0-9]+\.[0-9]+\.[0-9]+)", text))
        verify_versions = set(re.findall(r"agent-bom verify agent-bom@([0-9]+\.[0-9]+\.[0-9]+)", text))
        if docker_versions and docker_versions != {version}:
            _fail(f"{skill.relative_to(ROOT)} has stale OpenClaw Docker pin(s): {sorted(docker_versions)} != {version}")
        if verify_versions and verify_versions != {version}:
            _fail(f"{skill.relative_to(ROOT)} has stale OpenClaw verify pin(s): {sorted(verify_versions)} != {version}")
    for path in MANAGED_ACTION_REFS:
        text = path.read_text()
        action_versions = set(re.findall(r"msaad00/agent-bom@v([0-9]+\.[0-9]+\.[0-9]+)", text))
        if action_versions and action_versions != {version}:
            _fail(f"{path.relative_to(ROOT)} has stale GitHub Action ref(s): {sorted(action_versions)} != {version}")

    tool_names, resource_uris, prompt_names = _server_card_catalog()
    tools = len(tool_names)
    resources = len(resource_uris)
    prompts = len(prompt_names)
    if (tools, resources, prompts) != (36, 6, 6):
        _fail(f"MCP server card count changed unexpectedly: tools={tools}, resources={resources}, prompts={prompts}")
    docker_mcp_tool_names = [str(tool["name"]) for tool in json.loads(DOCKER_MCP_TOOLS.read_text())]
    if docker_mcp_tool_names != tool_names:
        missing = sorted(set(tool_names) - set(docker_mcp_tool_names))
        extra = sorted(set(docker_mcp_tool_names) - set(tool_names))
        _fail(f"integrations/docker-mcp-registry/tools.json is out of sync with MCP server-card tools: missing={missing}, extra={extra}")
    for path in MCP_COUNT_DOCS:
        text = path.read_text()
        readme_count_phrase = f"{tools} read-only security tools, {resources} resources, and {prompts} workflow prompts"
        if path.name == "README.md" and readme_count_phrase not in text:
            _fail("README.md must advertise current MCP tool/resource/prompt counts")
        if path.name == "MCP_SERVER.md" and f"Tool Categories ({tools} tools)" not in text:
            _fail("docs/MCP_SERVER.md must advertise current MCP tool count")
        if path.name == "mcp-server.md" and f"{resources} resources and {prompts} workflow prompts" not in text:
            _fail("site-docs/getting-started/mcp-server.md must advertise current MCP resource/prompt counts")

    helm_chart = ROOT / "deploy" / "helm" / "agent-bom" / "Chart.yaml"
    helm_text = helm_chart.read_text()
    chart_version = re.search(r"^version:\s*(\S+)\s*$", helm_text, re.M)
    chart_app_version = re.search(r'^appVersion:\s*"([^"]+)"\s*$', helm_text, re.M)
    if chart_version is None or chart_app_version is None:
        _fail('deploy/helm/agent-bom/Chart.yaml must declare both `version:` and `appVersion: "..."`')
    elif chart_version.group(1) != version or chart_app_version.group(1) != version:
        _fail(
            "deploy/helm/agent-bom/Chart.yaml is out of sync with pyproject.toml: "
            f"chart.version={chart_version.group(1)}, chart.appVersion={chart_app_version.group(1)}, expected {version}. "
            "Run scripts/bump-version.py to refresh both fields together."
        )

    print("README/PyPI/docs release consistency checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
