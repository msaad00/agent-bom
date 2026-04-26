#!/usr/bin/env python3
"""Bump agent-bom version across all files in one command.

Usage:
    python scripts/bump-version.py 0.29.0
    python scripts/bump-version.py 0.29.0 --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Every file + regex pattern that contains the version string.
# Each entry: (relative_path, compiled_regex, replacement_template)
# The replacement_template uses \g<1> for the prefix capture group.
VERSION_LOCATIONS: list[tuple[str, re.Pattern, str]] = [
    # Core
    ("pyproject.toml", re.compile(r'^(version\s*=\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    ("src/agent_bom/__init__.py", re.compile(r'(__version__\s*=\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    # Dockerfiles
    ("deploy/docker/Dockerfile.runtime", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    ("deploy/docker/Dockerfile.sse", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    ("deploy/docker/Dockerfile.mcp", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    # MCP Registry server.json (version field + pypi identifier version)
    ("integrations/mcp-registry/server.json", re.compile(r'("version":\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    ("integrations/glama/server.json", re.compile(r'("version":\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    # Snowpark Dockerfile
    ("deploy/docker/Dockerfile.snowpark", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    ("Dockerfile", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    # Compose + packaged manifests
    ("deploy/docker-compose.pilot.yml", re.compile(r"(agentbom/agent-bom(?:-ui)?:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("deploy/docker-compose.runtime.yml", re.compile(r"(agentbom/agent-bom(?:-ui)?:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("deploy/docker-compose.fullstack.yml", re.compile(r"(agentbom/agent-bom(?:-ui)?:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("deploy/docker-compose.platform.yml", re.compile(r"(agentbom/agent-bom(?:-ui)?:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("deploy/k8s/daemonset.yaml", re.compile(r"(agentbom/agent-bom:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    # Helm chart — both chart `version:` and `appVersion:` track the platform release
    ("deploy/helm/agent-bom/Chart.yaml", re.compile(r"^(version:\s*)\S+", re.M), r"\g<1>{v}"),
    ("deploy/helm/agent-bom/Chart.yaml", re.compile(r'^(appVersion:\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    ("deploy/helm/agent-bom/values.yaml", re.compile(r'^(\s*tag:\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    # Frontend package — UI version tracks the platform release so the docker image and
    # the Next.js build manifest agree on what version is shipping
    ("ui/package.json", re.compile(r'^(\s*"version":\s*")[^"]+(",?)', re.M), r"\g<1>{v}\g<2>"),
]

OPENCLAW_SKILL_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("integrations/openclaw/**/SKILL.md", re.compile(r"^(version:\s*)\S+", re.M), r"\g<1>{v}"),
    ("integrations/openclaw/**/SKILL.md", re.compile(r"(ghcr\.io/msaad00/agent-bom:)\S+"), r"\g<1>{v}"),
    ("integrations/openclaw/**/SKILL.md", re.compile(r"(agent-bom verify agent-bom@)[^`\s]+(`)"), r"\g<1>{v}\g<2>"),
]

# Patterns that reference the version in docs/tests (updated separately)
DOC_TEST_LOCATIONS: list[tuple[str, re.Pattern, str]] = [
    # README.md + docs — GitHub Action version references
    ("README.md", re.compile(r"(msaad00/agent-bom@v)\d+(?:\.\d+){0,2}"), r"\g<1>{v}"),
    ("docs/AI_INFRASTRUCTURE_SCANNING.md", re.compile(r"(msaad00/agent-bom@v)\d+(?:\.\d+){0,2}"), r"\g<1>{v}"),
    ("docs/ENTERPRISE_DEPLOYMENT.md", re.compile(r"(msaad00/agent-bom@v)\d+(?:\.\d+){0,2}"), r"\g<1>{v}"),
    ("docs/archive/WINDOWS_CONTAINERS.md", re.compile(r"(msaad00/agent-bom@v)\d+(?:\.\d+){0,2}"), r"\g<1>{v}"),
    ("docs/MCP_SECURITY_MODEL.md", re.compile(r"(msaad00/agent-bom@v)\d+(?:\.\d+){0,2}"), r"\g<1>{v}"),
    ("site-docs/index.md", re.compile(r"(msaad00/agent-bom@v)\d+(?:\.\d+){0,2}"), r"\g<1>{v}"),
    ("site-docs/features/policy.md", re.compile(r"(msaad00/agent-bom@v)\d+(?:\.\d+){0,2}"), r"\g<1>{v}"),
    ("site-docs/deployment/overview.md", re.compile(r"(msaad00/agent-bom@v)\d+(?:\.\d+){0,2}"), r"\g<1>{v}"),
    ("docs/ENTERPRISE_DEPLOYMENT.md", re.compile(r"(agentbom/agent-bom:)(?:v)?\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("README.md", re.compile(r"(--version\s+)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("site-docs/deployment/control-plane-helm.md", re.compile(r"(--version\s+)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("deploy/k8s/sidecar-example.yaml", re.compile(r"(agentbom/agent-bom:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("deploy/k8s/proxy-sidecar-pilot.yaml", re.compile(r"(agentbom/agent-bom:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("docs/PRODUCT_METRICS.md", re.compile(r"(- Version: `)\d+\.\d+\.\d+(`)"), r"\g<1>{v}\g<2>"),
    ("docs/PRODUCT_METRICS.json", re.compile(r'("version":\s*")\d+\.\d+\.\d+(")'), r"\g<1>{v}\g<2>"),
    ("docs/RELEASE_VERIFICATION.md", re.compile(r"^(TAG=v)\d+\.\d+\.\d+$", re.M), r"\g<1>{v}"),
    ("DOCKER_HUB_README.md", re.compile(r"(\| `)\d+\.\d+\.\d+(` \| Current stable version \(pinned\) \|)"), r"\g<1>{v}\g<2>"),
    # PUBLISHING.md — version examples
    ("docs/PUBLISHING.md", re.compile(r'(--version\s+")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    ("docs/PUBLISHING.md", re.compile(r"(git tag v)\S+", re.M), r"\g<1>{v}"),
    ("docs/PUBLISHING.md", re.compile(r"(git push origin v)\S+", re.M), r"\g<1>{v}"),
    ("ui/tests/nav.test.tsx", re.compile(r"(version:\s*')\d+\.\d+\.\d+(')"), r"\g<1>{v}\g<2>"),
    ("site-docs/deployment/docker.md", re.compile(r"(agentbom/agent-bom:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    ("docs/RUNTIME_MONITORING.md", re.compile(r"(agentbom/agent-bom:)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    # cve-freshness.yml — SARIF fallback template version
    (".github/workflows/cve-freshness.yml", re.compile(r'("version":")\d+\.\d+\.\d+(")'), r"\g<1>{v}\g<2>"),
    # mcp-change-scan.yml — pinned agent-bom install version
    (".github/workflows/mcp-change-scan.yml", re.compile(r"(agent-bom==)\d+\.\d+\.\d+"), r"\g<1>{v}"),
    # docs/demo.tape — version header
    ("docs/demo.tape", re.compile(r"^(# agent-bom v)\d+\.\d+\.\d+(\s+.*demo.*)$", re.M), r"\g<1>{v}\g<2>"),
]


def bump(new_version: str, *, dry_run: bool = False, check: bool = False) -> int:
    """Replace version strings across all tracked files."""
    if not re.match(r"^\d+\.\d+\.\d+$", new_version):
        print(f"ERROR: Invalid semver: {new_version}", file=sys.stderr)
        return 1

    all_locations = VERSION_LOCATIONS + DOC_TEST_LOCATIONS
    for glob_pattern, pattern, template in OPENCLAW_SKILL_PATTERNS:
        for path in sorted(ROOT.glob(glob_pattern)):
            text = path.read_text()
            if pattern.search(text):
                all_locations.append((str(path.relative_to(ROOT)), pattern, template))
    changed = 0

    for rel_path, pattern, template in all_locations:
        path = ROOT / rel_path
        if not path.exists():
            print(f"  SKIP (not found): {rel_path}")
            continue

        text = path.read_text()
        replacement = template.format(v=new_version)
        new_text, count = pattern.subn(replacement, text)

        if count == 0:
            print(f"  WARN (no match):  {rel_path}  pattern={pattern.pattern!r}")
        elif new_text == text:
            print(f"  OK (already {new_version}): {rel_path}")
        else:
            changed += count
            if dry_run or check:
                print(f"  DRY-RUN ({count} hit): {rel_path}")
            else:
                path.write_text(new_text)
                print(f"  UPDATED ({count} hit): {rel_path}")

    print(f"\n{'Would update' if dry_run else 'Updated'} {changed} occurrence(s)")

    if check:
        if changed > 0:
            print(
                f"\nERROR: release-managed files drift from {new_version}. Run: python scripts/bump-version.py {new_version}",
                file=sys.stderr,
            )
            return 1
        return 0

    if not dry_run and changed > 0:
        print("\nNext steps:")
        print(f"  git add -A && git commit -m 'chore: bump version to {new_version}'")
        print(f"  git tag v{new_version}")
        print(f"  git push origin main v{new_version}")

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Bump agent-bom version everywhere")
    parser.add_argument("version", help="New version (e.g. 0.29.0)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    parser.add_argument("--check", action="store_true", help="Fail if managed files are not already aligned")
    args = parser.parse_args()
    sys.exit(bump(args.version, dry_run=args.dry_run, check=args.check))


if __name__ == "__main__":
    main()
