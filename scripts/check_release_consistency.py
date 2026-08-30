#!/usr/bin/env python3
"""Validate README/docs storefront and release-surface consistency."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
PYPI_README = ROOT / "PYPI_README.md"
CHANGELOG = ROOT / "CHANGELOG.md"
DEMO_TAPE = ROOT / "docs" / "demo.tape"
DEMO_LATEST = ROOT / "docs" / "images" / "demo-latest.gif"
PRODUCT_SCREENSHOTS = ROOT / "docs" / "images" / "product-screenshots.json"
REFERENCE_LAB_DIGEST = ROOT / "examples" / "reference-evidence-lab" / "generated" / "correlation-proof.sha256"
GLAMA_SERVER = ROOT / "integrations" / "glama" / "server.json"
DOCKER_README = ROOT / "DOCKER_HUB_README.md"
SITE_INDEX = ROOT / "site-docs" / "index.md"
TOP_DOCKERFILE = ROOT / "Dockerfile"
PYPROJECT = ROOT / "pyproject.toml"
MCP_REGISTRY = ROOT / "src" / "agent_bom" / "mcp_registry.json"
CANONICAL_TAGLINE = "Open security scanner and self-hosted control plane for AI, MCP, and cloud infrastructure."
CANONICAL_TAGLINE_SURFACES: list[Path] = [
    README,
    PYPI_README,
    DOCKER_README,
    SITE_INDEX,
    ROOT / "docs" / "PRODUCT_BRIEF.md",
]
MANAGED_IMAGE_REFS: list[tuple[Path, re.Pattern[str]]] = [
    (ROOT / "deploy" / "docker-compose.pilot.yml", re.compile(r"agentbom/agent-bom(?:-ui)?:([0-9]+\.[0-9]+\.[0-9]+)")),
    (ROOT / "deploy" / "docker-compose.runtime-example.yml", re.compile(r"agentbom/agent-bom(?:-ui)?:([0-9]+\.[0-9]+\.[0-9]+)")),
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
        ROOT / "deploy" / "docker" / "Dockerfile.collector",
        re.compile(r"^ARG VERSION=([0-9]+\.[0-9]+\.[0-9]+)$", re.M),
        "collector Dockerfile ARG",
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

# ---------------------------------------------------------------------------
# Derived version sweep
#
# Everything above this line is a hand-maintained list, and so is
# ``scripts/bump-version.py``. A version-bearing artifact that is in neither
# list is written by nobody and checked by nobody — which is exactly how
# ``sdks/python/pyproject.toml`` sat at 0.92.0 while the platform shipped
# 0.100.0. It had been bumped by hand once, then forgotten.
#
# The sweep below finds those artifacts by SHAPE instead of by name: any file
# matching a structural glob is read, any self-referential version it carries is
# extracted, and a mismatch fails. A newly added SDK, compose profile, or
# deploy manifest is therefore covered the moment it exists.
#
# A genuinely independent version must be declared here, with a reason. Silence
# is not an option: the sweep fails closed.
# ---------------------------------------------------------------------------
VERSION_SWEEP: list[tuple[str, re.Pattern[str], str]] = [
    ("sdks/*/pyproject.toml", re.compile(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', re.M), "SDK package version"),
    # `\A\{` plus a brace-free run keeps this on the TOP-LEVEL "version" — once a
    # nested object opens, `[^{}]` can no longer advance, so a dependency's
    # version is never picked up. The run must NOT be written `(?:[^{}]|\n)*?`:
    # a negated class already matches newline in Python, so the alternation gives
    # the engine two ways to consume the same character and backtracking becomes
    # exponential (CodeQL ReDoS, HIGH). We ship a scanner that flags this shape.
    ("sdks/*/package.json", re.compile(r'\A\{[^{}]*?"version":\s*"([0-9]+\.[0-9]+\.[0-9]+)"'), "SDK package version"),
    ("deploy/docker-compose*.yml", re.compile(r"agentbom/agent-bom(?:-ui)?:([0-9]+\.[0-9]+\.[0-9]+)"), "compose image tag"),
    ("deploy/k8s/*.yaml", re.compile(r"agentbom/agent-bom(?:-ui)?:([0-9]+\.[0-9]+\.[0-9]+)"), "k8s image tag"),
    ("deploy/docker/Dockerfile*", re.compile(r"^ARG VERSION=([0-9]+\.[0-9]+\.[0-9]+)$", re.M), "Dockerfile ARG VERSION"),
    ("integrations/*/server.json", re.compile(r'"version":\s*"([0-9]+\.[0-9]+\.[0-9]+)"'), "integration manifest version"),
]

# Artifacts that legitimately carry their own version line, each with the reason
# it does not track the platform release.
INDEPENDENTLY_VERSIONED: dict[str, str] = {
    "sdks/typescript/package.json": "@agent-bom/runtime is published to npm on its own 0.x line, independent of the platform tag",
    "sdks/typescript-client/package.json": "@agent-bom/client is published to npm on its own 0.x line, independent of the platform tag",
}


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


def _fail(message: str) -> NoReturn:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def _assert_mcp_registry_serialization_stable() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from agent_bom.mcp_registry_text import dumps_registry_json

    current = MCP_REGISTRY.read_text(encoding="utf-8")
    normalized = dumps_registry_json(json.loads(current))
    if normalized != current:
        _fail("src/agent_bom/mcp_registry.json is not in canonical registry serialization. Run the registry formatter before tagging.")


def _assert_data_model_atlas_current() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/regenerate_data_model_atlas.py", "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        _fail(detail or "docs/DATA_MODEL.md generated atlas is stale")


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


def _assert_canonical_tagline(description: str) -> None:
    if description != CANONICAL_TAGLINE:
        _fail(f"pyproject.toml description must match the canonical tagline: {CANONICAL_TAGLINE!r}")
    for path in CANONICAL_TAGLINE_SURFACES:
        if CANONICAL_TAGLINE not in path.read_text():
            _fail(f"{path.relative_to(ROOT)} is missing the canonical tagline: {CANONICAL_TAGLINE!r}")


def _requires_published_storefront(_version: str, environment: dict[str, str] | None = None) -> bool:
    """Return whether this run explicitly validates a finalized storefront file."""

    env = os.environ if environment is None else environment
    return env.get("AGENT_BOM_RELEASE_FINALIZE", "").strip().lower() in {"1", "true", "yes"}


def _is_matching_release_tag(version: str, environment: dict[str, str] | None = None) -> bool:
    env = os.environ if environment is None else environment
    return env.get("GITHUB_REF_TYPE") == "tag" and env.get("GITHUB_REF_NAME") == f"v{version}"


def _assert_docker_storefront_state(version: str) -> None:
    docker_readme = Path(os.environ.get("AGENT_BOM_DOCKER_README_PATH", str(DOCKER_README)))
    text = docker_readme.read_text()
    stable = f"| `{version}` | Current stable version (pinned) |"
    neutral = f"| `{version}` | Version used by the examples below; verify registry availability before pinning |"
    if _requires_published_storefront(version):
        if stable not in text:
            _fail(f"Docker storefront README must mark {version} as current stable in finalize context")
        return
    if neutral not in text:
        _fail(f"DOCKER_HUB_README.md must describe {version} with lifecycle-neutral availability wording")


def _assert_product_screenshots_current(expected_version: str) -> None:
    if not PRODUCT_SCREENSHOTS.exists():
        _fail("docs/images/product-screenshots.json is missing from release surface")
    try:
        manifest = json.loads(PRODUCT_SCREENSHOTS.read_text())
    except json.JSONDecodeError as exc:
        _fail(f"docs/images/product-screenshots.json is invalid JSON: {exc}")

    if manifest.get("release_version") != expected_version:
        _fail(f"docs/images/product-screenshots.json has stale release_version: {manifest.get('release_version')!r} != {expected_version}")

    required = {
        "dashboard-live.png",
        "dashboard-paths-live.png",
        "mesh-live.png",
        "security-graph-live.png",
        "correlation-receipts-live.png",
        "correlation-path-live.png",
        "lineage-graph-live.png",
        "dependency-map-live.png",
        "remediation-live.png",
    }
    screenshots = manifest.get("screenshots")
    if not isinstance(screenshots, list):
        _fail("docs/images/product-screenshots.json must contain a screenshots list")
    paths = {entry.get("path") for entry in screenshots if isinstance(entry, dict)}
    missing = sorted(required - paths)
    if missing:
        _fail(f"docs/images/product-screenshots.json is missing screenshot entries: {missing}")

    lab_digest = REFERENCE_LAB_DIGEST.read_text(encoding="utf-8").strip()
    by_path = {entry.get("path"): entry for entry in screenshots if isinstance(entry, dict)}
    for rel_path in ("correlation-receipts-live.png", "correlation-path-live.png"):
        entry = by_path[rel_path]
        if entry.get("evidence_sha256") != lab_digest:
            _fail(f"docs/images/{rel_path} is not bound to the current reference lab artifact")
        manifest_hash = entry.get("correlation_manifest_sha256")
        if not isinstance(manifest_hash, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", manifest_hash) is None:
            _fail(f"docs/images/{rel_path} is missing the correlation manifest hash")

    expected_parts = tuple(int(part) for part in expected_version.split("."))
    for entry in screenshots:
        if not isinstance(entry, dict):
            _fail("docs/images/product-screenshots.json screenshots entries must be objects")
        rel_path = entry.get("path")
        if not isinstance(rel_path, str):
            _fail("docs/images/product-screenshots.json screenshot entry is missing path")
        page = entry.get("page")
        if not isinstance(page, str) or not page:
            _fail(f"docs/images/{rel_path} manifest entry is missing page")
        scope = entry.get("scope")
        if not isinstance(scope, str) or not scope:
            _fail(f"docs/images/{rel_path} manifest entry is missing scope")
        image = ROOT / "docs" / "images" / rel_path
        if not image.exists():
            _fail(f"docs/images/product-screenshots.json references missing image: docs/images/{rel_path}")
        visible_version = entry.get("visible_version")
        if not isinstance(visible_version, str) or re.fullmatch(r"\d+\.\d+\.\d+", visible_version) is None:
            _fail(f"docs/images/{rel_path} manifest visible_version is not semantic version text: {visible_version!r}")
        # A screenshot is immutable evidence bound by its recorded SHA-256. Its
        # visible version describes what is actually in those bytes and must not
        # be rewritten during a later release bump. It may therefore trail the
        # release that still embeds it, but it can never claim a future version.
        visible_parts = tuple(int(part) for part in visible_version.split("."))
        if visible_parts > expected_parts:
            _fail(f"docs/images/{rel_path} manifest visible_version is newer than the release: {visible_version!r} > {expected_version}")


def sweep_version_drift(expected: str) -> list[str]:
    """Return every self-referential version that disagrees with the release.

    Discovery is structural, so an artifact nobody remembered to register still
    gets checked. Declared-independent files are skipped by exact relative path
    — a glob there would re-open the hole this closes.
    """
    problems: list[str] = []
    for glob, pattern, label in VERSION_SWEEP:
        for path in sorted(ROOT.glob(glob)):
            if not path.is_file():
                continue
            relative = path.relative_to(ROOT).as_posix()
            if relative in INDEPENDENTLY_VERSIONED:
                continue
            found = {match.group(1) for match in pattern.finditer(path.read_text(encoding="utf-8"))}
            stale = sorted(found - {expected})
            if stale:
                problems.append(f"{relative} has stale {label}: {stale} != {expected}")
    return problems


def _assert_no_unmanaged_version_drift(version: str) -> None:
    problems = sweep_version_drift(version)
    if problems:
        detail = "\n  - ".join(problems)
        _fail(
            "version sweep found artifacts that do not track the release:\n  - "
            f"{detail}\n"
            "Add the file to scripts/bump-version.py so it is bumped automatically, "
            "or declare it in INDEPENDENTLY_VERSIONED with the reason it differs."
        )


def main() -> int:
    version = _load_version()
    description = _load_description()
    readme = README.read_text()
    pypi_readme = PYPI_README.read_text()
    changelog = CHANGELOG.read_text()
    demo_tape = DEMO_TAPE.read_text()

    _assert_canonical_tagline(description)

    required_github_markers = [
        "img.shields.io/github/actions/workflow/status",
        "img.shields.io/pypi/v/agent-bom",
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
    _assert_product_screenshots_current(version)
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
    stale_public_markers = [
        "agent-bom cis-benchmark --provider aws",
        "uses: msaad00/agent-bom@v0.88.4",
        "MCP server mode advertises 55 MCP tools",
        "18 tools for CVE scanning",
    ]
    public_surface_roots = [
        ROOT / "README.md",
        ROOT / "PYPI_README.md",
        ROOT / "site-docs",
        ROOT / "docs" / "PRODUCT_BRIEF.md",
        ROOT / "docs" / "MCP_SECURITY_MODEL.md",
    ]
    for root in public_surface_roots:
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
        for file in files:
            if file.suffix.lower() in {".gif", ".png", ".jpg", ".jpeg", ".svg", ".ico"}:
                continue
            text = file.read_text(errors="ignore")
            for marker in stale_public_markers:
                if marker in text:
                    _fail(f"{file.relative_to(ROOT)} contains stale public registry marker: {marker}")

    if len(description) > 100:
        _fail("pyproject.toml description must be <=100 chars for Docker Hub short-description publishing")
    stale_description_markers = [
        "Security scanner for AI infrastructure and supply chain.",
        "19 output formats",
        "20-page Next.js dashboard",
        "14-framework compliance",
    ]
    for marker in stale_description_markers:
        if marker in description:
            _fail(f"pyproject.toml description contains stale storefront phrase: {marker}")

    _assert_mcp_registry_serialization_stable()
    _assert_data_model_atlas_current()

    if f"## [{version}]" not in changelog:
        _fail(f"CHANGELOG.md must include a {version} release entry before tagging")
    if f"[Unreleased]: https://github.com/msaad00/agent-bom/compare/v{version}...HEAD" not in changelog:
        _fail(f"CHANGELOG.md Unreleased compare link must start at v{version}")

    leaked_patterns = [
        r"/Users/[A-Za-z0-9._-]+",
        r"[A-Za-z]:\\Users\\[^\\\s]+",
    ]
    scan_roots = [ROOT / "README.md", ROOT / "PYPI_README.md", ROOT / "docs"]
    for path in scan_roots:
        files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
        for file in files:
            if file.suffix.lower() in {".gif", ".png", ".jpg", ".jpeg", ".svg", ".ico"}:
                continue
            text = file.read_text(errors="ignore")
            for leaked_pattern in leaked_patterns:
                if re.search(leaked_pattern, text):
                    _fail(f"personal/local path leak found in {file.relative_to(ROOT)}")

    if f"agent-bom v{version}" not in demo_tape:
        _fail(f"docs/demo.tape header must include v{version}")

    glama_text = GLAMA_SERVER.read_text()
    if f'"version": "{version}"' not in glama_text:
        _fail(f"integrations/glama/server.json must be aligned to {version}")
    if '"dockerfile": "integrations/glama/Dockerfile"' not in glama_text:
        _fail("integrations/glama/server.json must point at integrations/glama/Dockerfile")
    glama_root = (ROOT / "glama.json").read_text()
    if '"dockerfile": "integrations/glama/Dockerfile"' not in glama_root:
        _fail("glama.json must point at integrations/glama/Dockerfile")
    _assert_docker_storefront_state(version)
    if f"ARG VERSION={version}" not in TOP_DOCKERFILE.read_text():
        _fail(f"Dockerfile ARG VERSION must be {version}")
    for path, image_pattern in MANAGED_IMAGE_REFS:
        text = path.read_text()
        versions = {match.group(1) for match in image_pattern.finditer(text)}
        if versions and versions != {version}:
            _fail(f"{path.relative_to(ROOT)} contains stale managed image version(s): {sorted(versions)} != {version}")
    for path, version_pattern, label in MANAGED_VERSION_REFS:
        _assert_versions(path, version_pattern, version, label)
    _assert_no_unmanaged_version_drift(version)
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
    if (tools, resources, prompts) != (86, 6, 8):
        _fail(f"MCP server card count changed unexpectedly: tools={tools}, resources={resources}, prompts={prompts}")
    docker_mcp_tool_names = [str(tool["name"]) for tool in json.loads(DOCKER_MCP_TOOLS.read_text())]
    if docker_mcp_tool_names != tool_names:
        missing = sorted(set(tool_names) - set(docker_mcp_tool_names))
        extra = sorted(set(docker_mcp_tool_names) - set(tool_names))
        _fail(f"integrations/docker-mcp-registry/tools.json is out of sync with MCP server-card tools: missing={missing}, extra={extra}")
    for path in MCP_COUNT_DOCS:
        text = path.read_text()
        readme_count_phrase = f"{tools} MCP tools, {resources} resources, and {prompts} workflow prompts"
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
